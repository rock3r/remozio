import Darwin
import Foundation
import RemozioProtocol

public enum CommandCallerReadinessError: Error, Equatable {
    case invalidConfiguration, clockMovedBackwards
    case deadlineExceeded(lastBusyReason: CommandAdmissionRejectionReason?)
}

/// Endpoint lookup can report this before exposing a command. It grants no retry authority for a submitted command.
public enum CommandAuthorityEndpointError: Error { case unavailable }

/// These durations are caller settings. The readiness deadline does not change an admitted request's approval lifetime.
public struct CommandCallerReadinessConfiguration: Sendable {
    public let timeoutMilliseconds: UInt64
    public let initialBackoffMilliseconds: UInt32
    public let maximumBackoffMilliseconds: UInt32
    public let controlTimeoutMilliseconds: UInt32

    public init(timeoutMilliseconds: UInt64, initialBackoffMilliseconds: UInt32 = 250,
                maximumBackoffMilliseconds: UInt32 = 2000, controlTimeoutMilliseconds: UInt32 = 5000) throws {
        guard timeoutMilliseconds > 0, (1...60_000).contains(initialBackoffMilliseconds),
              (initialBackoffMilliseconds...60_000).contains(maximumBackoffMilliseconds),
              (1...60_000).contains(controlTimeoutMilliseconds) else { throw CommandCallerReadinessError.invalidConfiguration }
        self.timeoutMilliseconds = timeoutMilliseconds; self.initialBackoffMilliseconds = initialBackoffMilliseconds
        self.maximumBackoffMilliseconds = maximumBackoffMilliseconds; self.controlTimeoutMilliseconds = controlTimeoutMilliseconds
    }
}

public enum CommandCallerReadinessStatus: Equatable, Sendable {
    case connecting
    case waiting(CommandAdmissionRejectionReason)
}

public enum CommandCallerReadiness {
    /// The template's identifiers are discarded. Every permitted submission gets fresh randomness and a new authenticated handshake.
    /// The endpoint provider borrows a current registered send right. This method never reads or closes the original input descriptor.
    /// Only a verified busy refusal permits another submission. Lost replies, cancellation and uncertain results never resubmit.
    public static func submit(_ template: CommandSubmission, inputDescriptor: Int32, authorityPort: () throws -> mach_port_t,
                              authorityPolicy: XPCPeerPolicy, macID: Data, accountID: Data, submissionLimits: CBORLimits,
                              configuration: CommandCallerReadinessConfiguration, checkCancellation: () throws -> Void = {},
                              onStatus: (CommandCallerReadinessStatus) -> Void = { _ in }) throws -> VerifiedCommandAdmissionResult {
        guard authorityPolicy.expectedUserID == 0 else { throw MachCommandHandshakeError.invalidConfiguration }
        return try submit(template, inputDescriptor: inputDescriptor, authorityPort: authorityPort,
            expression: authorityPolicy.requirement, userID: 0, auditSessionID: authorityPolicy.expectedAuditSessionID,
            macID: macID, accountID: accountID, submissionLimits: submissionLimits, configuration: configuration,
            checkCancellation: checkCancellation, onStatus: onStatus)
    }

    /// Fixture identity and clock seams. The transport and result verification still use actual Mach messages.
    static func submit(_ template: CommandSubmission, inputDescriptor: Int32, authorityPort: () throws -> mach_port_t,
                       expression: String, userID: uid_t, auditSessionID: au_asid_t?, macID: Data, accountID: Data,
                       submissionLimits: CBORLimits, configuration: CommandCallerReadinessConfiguration,
                       checkCancellation: () throws -> Void = {}, onStatus: (CommandCallerReadinessStatus) -> Void = { _ in },
                       clock: (() throws -> UInt64)? = nil, wait: ((UInt32, () throws -> Void) throws -> Void)? = nil) throws -> VerifiedCommandAdmissionResult {
        guard macID.count == 16, accountID.count == 16, submissionLimits.maxBytes > 0,
              submissionLimits.maxBytes <= Int(UInt32.max) - 1024 else { throw CommandCallerReadinessError.invalidConfiguration }
        let continuous = try AuthorityClock(), now = clock ?? { try continuous.now().milliseconds }
        let started = try now()
        var previous = started, lastBusy: CommandAdmissionRejectionReason?, lastStatus: CommandCallerReadinessStatus?
        var backoff = configuration.initialBackoffMilliseconds, submissionInFlight = false
        func remaining() throws -> UInt64 {
            let current = try now()
            guard current >= previous else { throw CommandCallerReadinessError.clockMovedBackwards }
            previous = current
            guard current - started < configuration.timeoutMilliseconds else {
                if submissionInFlight { throw MachCommandCallerError.timeout }
                throw CommandCallerReadinessError.deadlineExceeded(lastBusyReason: lastBusy)
            }
            return configuration.timeoutMilliseconds - (current - started)
        }
        func checkpoint() throws { try checkCancellation(); _ = try remaining() }
        func budget() throws -> UInt32 { UInt32(min(try remaining(), UInt64(configuration.controlTimeoutMilliseconds))) }
        func status(_ value: CommandCallerReadinessStatus) throws {
            if value != lastStatus { lastStatus = value; onStatus(value) }
            try checkpoint()
        }
        func pause() throws {
            let duration = UInt32(min(try remaining(), UInt64(backoff)))
            if let wait { try wait(duration, checkpoint) }
            else {
                var left = duration
                while left > 0 {
                    try checkpoint()
                    let slice = min(left, 50)
                    Thread.sleep(forTimeInterval: Double(slice) / 1000)
                    left -= slice
                }
            }
            try checkpoint()
            backoff = min(configuration.maximumBackoffMilliseconds, backoff * 2)
        }
        while true {
            try checkpoint()
            let handshake: VerifiedCommandHandshake
            var negotiationCallbackError: Error?
            do {
                let port = try authorityPort()
                try checkpoint()
                handshake = try MachCommandHandshakeClient.negotiate(authorityPort: port, expression: expression,
                    userID: userID, auditSessionID: auditSessionID, macID: macID, accountID: accountID,
                    capabilities: .admissionResults, timeoutMilliseconds: budget(), checkCancellation: {
                        do { try checkpoint() } catch { negotiationCallbackError = error; throw error }
                    })
            } catch {
                if let negotiationCallbackError { throw negotiationCallbackError }
                // This catch covers metadata only. There is no invocation or input fileport in flight.
                guard isUnavailableBeforeExposure(error) else { throw error }
                try status(lastBusy.map(CommandCallerReadinessStatus.waiting) ?? .connecting)
                try pause(); continue
            }
            let result: VerifiedCommandAdmissionResult
            do {
                defer { handshake.close() }
                try checkpoint()
                let binding = CapturedSubmission(id: try MachCommandWire.random(16), nonce: try MachCommandWire.random(32),
                    callerBinding: handshake.profile.callerBinding)
                let submission = try CommandSubmission(schemaVersion: handshake.profile.submissionSchemaVersion,
                    executablePath: template.executablePath, arguments: template.arguments, directoryPath: template.directoryPath,
                    requestedTargetUID: template.requestedTargetUID, environmentAdditions: template.environmentAdditions,
                    ioMode: template.ioMode, disconnectBehavior: template.disconnectBehavior,
                    unverifiedRationale: template.unverifiedRationale, binding: binding, limits: submissionLimits)
                try checkpoint()
                // Nothing below this point catches transport errors to make another submission.
                let controlBudget = try budget()
                submissionInFlight = true
                let reply = try MachCommandAdmissionClient.submit(submission, inputDescriptor: inputDescriptor, handshake: handshake,
                    expression: expression, userID: userID, auditSessionID: auditSessionID,
                    maximumPayloadBytes: submissionLimits.maxBytes, timeoutMilliseconds: controlBudget,
                    checkCancellation: checkpoint, typedResult: true)
                guard let verified = reply.verifiedResult else { throw CommandAdmissionResultError.incompatible }
                result = verified
                try checkpoint()
                submissionInFlight = false
            }
            guard case .notAdmitted(let reason, let retry) = result.outcome, retry != .never else { return result }
            lastBusy = reason
            try status(.waiting(reason))
            try pause()
        }
    }

    private static func isUnavailableBeforeExposure(_ error: Error) -> Bool {
        if error is CommandAuthorityEndpointError { return true }
        guard let error = error as? MachCommandCallerError else { return false }
        if error == .timeout { return true }
        if case .mach(let result) = error {
            let code = result & ~MACH_MSG_MASK
            return code == MACH_SEND_INVALID_DEST || code == MACH_SEND_TIMED_OUT
        }
        return false
    }
}

