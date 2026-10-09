import Darwin
import Foundation
import RemozioMach
import RemozioProtocol

/// Owns one native child and the original command resources. Only the serialized journal calls this owner.
final class CommandExecution {
    enum Progress { case preparing, prepared, running, terminal(CommandTerminalOutcome) }
    let resources: RetainedCommandExecutionResources
    let approval: CommandExecutionApproval
    let clock: () throws -> AuthorityMoment
    let receiptTime: () -> UInt64?
    private struct Validation {
        let callerExpression: String
        let callerUserID: uid_t
        let callerSessionID: au_asid_t?
        let launcher: () throws -> Void
        let elevation: (CommandCapture) throws -> Void
    }
    private let validation: Validation?
    private var process: OpaquePointer?
    private var pump: CommandPTYStreamPump?
    private var nativeOwned = false
    private var pendingSignals: [UInt32] = []
    var committedOutcome: CommandTerminalOutcome?
    private var released = false
    private var releaseSucceeded = false
    private var cancelledBeforeRelease = false
    private var observationUncertain = false
    private var disposed = false
    var dispatchRevision: UInt64 = 0
    var terminalCommitFailed = false

    private init(resources: RetainedCommandExecutionResources, approval: CommandExecutionApproval,
                 clock: @escaping () throws -> AuthorityMoment, receiptTime: @escaping () -> UInt64?, validation: Validation?) {
        self.resources = resources; self.approval = approval; self.clock = clock; self.receiptTime = receiptTime
        self.validation = validation
    }
    convenience init(resources: RetainedCommandExecutionResources, approval: CommandExecutionApproval,
                     clock: @escaping () throws -> AuthorityMoment, receiptTime: @escaping () -> UInt64?,
                     callerExpression: String, callerUserID: uid_t, callerSessionID: au_asid_t?,
                     validateLauncher: @escaping () throws -> Void, validateElevation: @escaping (CommandCapture) throws -> Void) {
        self.init(resources: resources, approval: approval, clock: clock, receiptTime: receiptTime,
            validation: Validation(callerExpression: callerExpression, callerUserID: callerUserID,
                callerSessionID: callerSessionID, launcher: validateLauncher, elevation: validateElevation))
    }
    /// Retains only a failed pre-spawn outcome. This owner has no runtime validation and cannot spawn.
    convenience init(resources: RetainedCommandExecutionResources, approval: CommandExecutionApproval,
                     clock: @escaping () throws -> AuthorityMoment, receiptTime: @escaping () -> UInt64?) {
        self.init(resources: resources, approval: approval, clock: clock, receiptTime: receiptTime, validation: nil)
    }
    func validateLauncher() throws {
        guard let validation else { throw CommandExecutionError.unavailable }
        try validation.launcher()
    }
    func validateElevation(_ capture: CommandCapture) throws {
        guard let validation else { throw CommandExecutionError.unavailable }
        try validation.elevation(capture)
    }

    /// A failed spawn can still return a live child. Retain and retire that child through ordinary polling.
    func prepare(path: String, preparationMilliseconds: UInt32, fileCreationMask: UInt32) throws {
        guard validation != nil, !disposed, !released, !cancelledBeforeRelease, process == nil,
              (resources.capture.ioMode == .pipes && !resources.requiresStreamPump ||
               resources.capture.ioMode == .pty && resources.requiresStreamPump) else { throw CommandExecutionError.unavailable }
        let frame = try CommandChildLaunchSpecification(capture: resources.capture,
            preparationMilliseconds: preparationMilliseconds, fileCreationMask: fileCreationMask).canonicalBytes
        try validateLauncher(); try validateElevation(resources.capture)
        try recheck()
        let status = try resources.withBorrowedDescriptors { input, output, error, directory in
            let pty: RetainedCommandPTY?
            if resources.requiresStreamPump {
                var attributes = termios(), size = winsize()
                let hasTerminal = isatty(input) == 1
                if hasTerminal {
                    guard tcgetattr(input, &attributes) == 0, ioctl(input, TIOCGWINSZ, &size) == 0 else {
                        throw RetainedCommandPTYError.native(errno)
                    }
                }
                let privatePTY = try RetainedCommandPTY(attributes: hasTerminal ? attributes : nil, size: hasTerminal ? size : nil)
                pty = privatePTY
                pump = try CommandPTYStreamPump(pty: privatePTY, channel: resources.makeStreamAuthority())
            } else { pty = nil }
            defer { pty?.sealSlave() }
            func spawn(_ input: Int32, _ output: Int32, _ error: Int32) -> Int32 {
                frame.withUnsafeBytes { bytes in
                    path.withCString { path in
                        remozio_command_process_spawn(path, bytes.baseAddress, bytes.count, input, output, error, directory, &process)
                    }
                }
            }
            if let pty { return try pty.withBorrowedSlave { spawn($0, $0, $0) } }
            return spawn(input, output, error)
        }
        nativeOwned = process != nil
        if status != 0 { cancelBeforeRelease(); throw CommandExecutionError.native(status) }
    }

    func recheck() throws {
        guard let validation else { throw CommandExecutionError.unavailable }
        try resources.recheck(expression: validation.callerExpression, userID: validation.callerUserID,
            auditSessionID: validation.callerSessionID)
    }

    /// Call only after the dispatch transition commits and all final checks pass.
    func release() throws {
        guard !disposed, !released, !cancelledBeforeRelease, let process else { throw CommandExecutionError.unavailable }
        released = true
        let status = remozio_command_process_release(process)
        if status != 0 { pendingSignals.removeAll(); observationUncertain = true; cancelOwned(); throw CommandExecutionError.native(status) }
        releaseSucceeded = true
    }
    func cancelBeforeRelease() {
        guard !released else { return }
        cancelledBeforeRelease = true; pendingSignals.removeAll()
        cancelOwned()
    }
    private func cancelOwned() {
        guard nativeOwned, let process else { return }
        try? pump?.signalForeground(SIGKILL)
        _ = remozio_command_process_cancel(process)
    }
    private func applyControl(_ body: CommandStreamFrame.Body) throws {
        guard nativeOwned, let process else { return }
        switch body {
        case .cancel: if released { cancelOwned() } else { cancelBeforeRelease() }
        case .signal(let number):
            if !released {
                guard !cancelledBeforeRelease else { return }
                guard pendingSignals.count < CommandPTYStreamPump.maximumControlsPerTurn else { throw CommandStreamError.capacity }
                pendingSignals.append(number)
                return
            }
            guard releaseSucceeded else { return }
            do { try pump?.signalForeground(Int32(number)) }
            catch RetainedCommandPTYError.native(let error) where error == EPIPE || error == EIO {
                let status = remozio_command_process_signal(process, Int32(number))
                if status != 0 && status != ESRCH { throw CommandExecutionError.native(status) }
            }
        case .resize(let rows, let columns, let width, let height):
            do { try pump?.resize(winsize(ws_row: rows, ws_col: columns, ws_xpixel: width, ws_ypixel: height)) }
            catch RetainedCommandPTYError.native(let error) where error == EPIPE || error == EIO { }
        default: throw CommandStreamError.malformed
        }
    }
    /// Delivery waits for the original frontend to drain output. Durable native outcomes remain independent.
    func deliverTerminal(_ outcome: CommandTerminalOutcome) {
        guard pump?.readyForTerminal ?? true else { return }
        try? resources.sendTerminalOutcome(outcome, outputInterrupted: pump?.outputInterrupted ?? false)
        pump?.finishDelivery()
    }
    func poll(checkStreamPolicy: () throws -> Void = { throw CommandExecutionError.unavailable }) -> Progress {
        guard !disposed else { return .terminal(.unknown) }
        guard let process else {
            return .terminal(resources.requesterExitObserved ? .requesterExitedBeforeStart : .failedBeforeStart)
        }
        var observation = remozio_command_process_observation_t()
        let status = remozio_command_process_poll(process, &observation)
        if status != 0 {
            observationUncertain = true
            if !released { cancelBeforeRelease() }
        }
        nativeOwned = !observation.reaped && !observation.ownership_lost
        if let pump, let validation {
            if observation.ownership_lost { pump.detach() }
            else {
                do {
                    if releaseSucceeded, !pendingSignals.isEmpty {
                        let signals = pendingSignals; pendingSignals.removeAll()
                        if nativeOwned {
                            try resources.recheckCaller(expression: validation.callerExpression, userID: validation.callerUserID,
                                auditSessionID: validation.callerSessionID)
                            try checkStreamPolicy()
                            for number in signals { try applyControl(.signal(number)) }
                        }
                    }
                    if !released, !cancelledBeforeRelease, observation.prepared, !observation.reaped {
                        _ = try pump.open()
                    }
                    try pump.poll(expression: validation.callerExpression, userID: validation.callerUserID,
                        auditSessionID: validation.callerSessionID, allowInput: releaseSucceeded,
                        checkCaller: { try self.resources.recheckCaller(expression: validation.callerExpression,
                            userID: validation.callerUserID, auditSessionID: validation.callerSessionID) },
                        checkControlPolicy: checkStreamPolicy, applyControl: { try self.applyControl($0) })
                } catch {
                    pump.detach()
                    if !released || resources.capture.disconnectBehavior == .terminate { cancelOwned() }
                }
            }
        }
        if observation.ownership_lost { return .terminal(.unknown) }
        if observation.reaped {
            if observationUncertain && released { return .terminal(.unknown) }
            guard observation.exec_observed else { return .terminal(.failedBeforeStart) }
            let signal = observation.wait_status & 0x7f
            if signal == 0 { return .terminal(.exited(UInt8((observation.wait_status >> 8) & 0xff))) }
            if signal > 0 && signal < NSIG { return .terminal(.signalled(UInt32(signal))) }
            return .terminal(.unknown)
        }
        if released {
            if resources.capture.disconnectBehavior == .terminate, let validation {
                do { try resources.recheckCaller(expression: validation.callerExpression, userID: validation.callerUserID,
                    auditSessionID: validation.callerSessionID) }
                catch { cancelOwned() }
            }
            return .running
        }
        if cancelledBeforeRelease || observation.preparation_failed { cancelBeforeRelease(); return .preparing }
        return observation.prepared && (pump == nil || pump?.opened == true && pump?.connected == true) ? .prepared : .preparing
    }
    /// Poll until this succeeds. Disposal never waits for a live child.
    func dispose() -> Bool {
        guard !disposed else { return true }
        guard pump?.readyForTerminal ?? true else { return false }
        if let process, remozio_command_process_dispose(process) != 0 { return false }
        process = nil; nativeOwned = false; disposed = true; pump?.close(); resources.close(); return true
    }
}

enum CommandExecutionError: Error, Equatable { case invalidConfiguration, unavailable, policyChanged, native(Int32) }

/// Original consumption bindings retained in memory. These values cannot recreate a command or grant a release.
struct CommandApprovalEnrollment: Sendable { let epoch: Data; let key: EnrolledApprovalKey }
struct CommandExecutionApproval: Sendable {
    let retained: RetainedApprovalRequest
    let receipt: ConsumptionReceipt
    let enrollment: CommandApprovalEnrollment
    func requireCurrent(_ current: RequestDeliveryTrust) throws {
        let payload = retained.payload, decision = receipt.decision
        guard current.approval.macID == payload.macID, current.approval.accountID == payload.accountID,
              current.approval.allowedContracts.contains(payload.contract),
              let localFeatures = current.approval.authorityCapabilities.contracts[payload.contract],
              payload.requiredFeatures.isSubset(of: localFeatures),
              current.approval.enrollments.contains(where: { $0.phoneID == decision.phoneID && $0.active }),
              let phone = current.enrollments.first(where: {
                  $0.approval.phoneID == decision.phoneID && $0.epoch == enrollment.epoch && $0.approval.active
              }),
              let peerFeatures = phone.approval.capabilities.contracts[payload.contract],
              payload.requiredFeatures.isSubset(of: peerFeatures),
              let key = phone.approval.keys.first(where: { $0.id == decision.keyID }),
              key.keyClass == .biometric, key.publicKey == enrollment.key.publicKey,
              enrollment.key.keyClass == .biometric else { throw CommandExecutionError.policyChanged }
    }
}
