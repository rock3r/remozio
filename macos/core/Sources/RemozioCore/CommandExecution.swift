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
    private var released = false
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
              resources.capture.ioMode == .pipes, !resources.requiresStreamPump else { throw CommandExecutionError.unavailable }
        let frame = try CommandChildLaunchSpecification(capture: resources.capture,
            preparationMilliseconds: preparationMilliseconds, fileCreationMask: fileCreationMask).canonicalBytes
        try validateLauncher(); try validateElevation(resources.capture)
        try recheck()
        let status = try resources.withBorrowedDescriptors { input, output, error, directory in
            frame.withUnsafeBytes { bytes in
                path.withCString { path in
                    remozio_command_process_spawn(path, bytes.baseAddress, bytes.count, input, output, error, directory, &process)
                }
            }
        }
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
        if status != 0 { observationUncertain = true; _ = remozio_command_process_cancel(process); throw CommandExecutionError.native(status) }
    }
    func cancelBeforeRelease() {
        guard !released else { return }
        cancelledBeforeRelease = true
        if let process { _ = remozio_command_process_cancel(process) }
    }
    func poll() -> Progress {
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
                catch { _ = remozio_command_process_cancel(process) }
            }
            return .running
        }
        if cancelledBeforeRelease || observation.preparation_failed { cancelBeforeRelease(); return .preparing }
        return observation.prepared ? .prepared : .preparing
    }
    /// Poll until this succeeds. Disposal never waits for a live child.
    func dispose() -> Bool {
        guard !disposed else { return true }
        if let process, remozio_command_process_dispose(process) != 0 { return false }
        process = nil; disposed = true; resources.close(); return true
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
