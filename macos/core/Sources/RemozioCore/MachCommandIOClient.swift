import Darwin
import Foundation
import RemozioProtocol

/// Admission returns either an owned live result channel or a verified admission result. Neither permits execution by the frontend.
public enum CommandIOAdmission {
    case admitted(RetainedCommandExecutionSession)
    case result(VerifiedCommandAdmissionResult)
}

/// Owns the original Root handshake and private terminal endpoint after admission. The caller serializes all operations.
public final class RetainedCommandExecutionSession {
    public let admission: VerifiedCommandAdmissionResult
    private let original: CommandSubmission
    private let handshake: VerifiedCommandHandshake
    private let endpoint: MachCommandPrivateReplyPort
    private let receiver: MachCommandCallerReceiver
    private let expression: String
    private let userID: uid_t
    private let auditSessionID: au_asid_t?
    private var terminal: VerifiedCommandTerminalResult?
    private var closed = false
    fileprivate init(admission: VerifiedCommandAdmissionResult, original: CommandSubmission, handshake: VerifiedCommandHandshake,
                     endpoint: MachCommandPrivateReplyPort, expression: String, userID: uid_t, auditSessionID: au_asid_t?) throws {
        self.admission = admission; self.original = original; self.handshake = handshake; self.endpoint = endpoint
        self.expression = expression; self.userID = userID; self.auditSessionID = auditSessionID
        receiver = try MachCommandCallerReceiver(receivePort: endpoint.port, expression: expression, userID: userID,
            auditSessionID: auditSessionID, maxPayloadBytes: 4096)
    }
    /// A poll timeout with no observed message returns nil. It does not expire an approval or impose a command runtime limit.
    /// Malformed, late or unauthenticated results retire this channel. They never authorize resubmission.
    public func pollTerminalResult(timeoutMilliseconds: UInt32 = 250,
                                   checkCancellation: () throws -> Void = {}) throws -> VerifiedCommandTerminalResult? {
        try pollTerminalResult(timeoutMilliseconds: timeoutMilliseconds, checkCancellation: checkCancellation, clock: nil)
    }
    func pollTerminalResult(timeoutMilliseconds: UInt32, checkCancellation: () throws -> Void = {},
                            clock: (() throws -> UInt64)?) throws -> VerifiedCommandTerminalResult? {
        if let terminal { return terminal }
        guard !closed else { throw MachCommandHandshakeError.retired }
        guard (1...60_000).contains(timeoutMilliseconds) else { throw MachCommandHandshakeError.invalidConfiguration }
        let continuous = try AuthorityClock(), now = clock ?? { try continuous.now().milliseconds }
        let started = try now()
        func remaining() throws -> UInt32 {
            let current = try now()
            guard current >= started, current - started < UInt64(timeoutMilliseconds) else {
                throw CommandTerminalResultError.deadlineExceeded
            }
            return UInt32(UInt64(timeoutMilliseconds) - (current - started))
        }
        do {
            try checkCancellation()
            try handshake.authenticateReplyAuthority(expression: expression, userID: userID, auditSessionID: auditSessionID)
            _ = try remaining()
            let reply: ReceivedMachCommandSubmission
            do { reply = try receiver.receiveTerminalReply(timeoutMilliseconds: remaining()) }
            catch MachCommandCallerError.timeout { try checkCancellation(); return nil }
            defer { reply.caller.close() }
            try checkCancellation(); _ = try remaining()
            try handshake.authenticateReply(reply.caller, expression: expression, userID: userID, auditSessionID: auditSessionID)
            let result = try CommandTerminalResultPayload.decode(reply.payload, profile: handshake.profile,
                original: original, admission: admission)
            try checkCancellation(); _ = try remaining()
            terminal = result; close()
            return result
        } catch { close(); throw error }
    }
    public func close() { if !closed { closed = true; endpoint.close(); handshake.close() } }
    deinit { close() }
}

public enum MachCommandIOClient {
    /// Consumes the authenticated handshake. Borrows original stdio without reading, writing or changing shared flags.
    public static func submit(_ submission: CommandSubmission, inputDescriptor: Int32, outputDescriptor: Int32, errorDescriptor: Int32,
                              handshake: sending VerifiedCommandHandshake, authorityPolicy: XPCPeerPolicy, maximumPayloadBytes: Int,
                              timeoutMilliseconds: UInt32 = 5000, checkCancellation: () throws -> Void = {}) throws -> sending CommandIOAdmission {
        guard authorityPolicy.expectedUserID == 0 else { handshake.close(); throw MachCommandHandshakeError.invalidConfiguration }
        return try submit(submission, inputDescriptor: inputDescriptor, outputDescriptor: outputDescriptor, errorDescriptor: errorDescriptor,
            handshake: handshake, expression: authorityPolicy.requirement, userID: 0, auditSessionID: authorityPolicy.expectedAuditSessionID,
            maximumPayloadBytes: maximumPayloadBytes, timeoutMilliseconds: timeoutMilliseconds, checkCancellation: checkCancellation)
    }
    static func submit(_ submission: CommandSubmission, inputDescriptor: Int32, outputDescriptor: Int32, errorDescriptor: Int32,
                       handshake: sending VerifiedCommandHandshake, expression: String, userID: uid_t, auditSessionID: au_asid_t?,
                       maximumPayloadBytes: Int, timeoutMilliseconds: UInt32 = 5000,
                       checkCancellation: () throws -> Void = {}) throws -> sending CommandIOAdmission {
        do {
            let admissionEndpoint = try MachCommandPrivateReplyPort()
            defer { admissionEndpoint.close() }
            let terminalEndpoint = try MachCommandPrivateReplyPort()
            guard handshake.profile.supportsExecutionChannels, submission.schemaVersion == handshake.profile.submissionSchemaVersion,
                  submission.binding.callerBinding == handshake.profile.callerBinding, (1...60_000).contains(timeoutMilliseconds) else {
                throw MachCommandHandshakeError.incompatible
            }
            let clock = try AuthorityClock(), started = try clock.now().milliseconds
            func remaining() throws -> UInt32 {
                let current = try clock.now().milliseconds
                guard current >= started, current - started < UInt64(timeoutMilliseconds) else { throw MachCommandCallerError.timeout }
                return UInt32(UInt64(timeoutMilliseconds) - (current - started))
            }
            try checkCancellation()
            try handshake.authenticateReplyAuthority(expression: expression, userID: userID, auditSessionID: auditSessionID)
            let receiver = try MachCommandCallerReceiver(receivePort: admissionEndpoint.port, expression: expression,
                userID: userID, auditSessionID: auditSessionID, maxPayloadBytes: 4096)
            try MachCommandIOWire.send(submission.canonicalBytes, inputDescriptor: inputDescriptor, outputDescriptor: outputDescriptor,
                errorDescriptor: errorDescriptor, destination: handshake.borrowedAuthorityPort(), admissionReply: admissionEndpoint.port,
                terminalReply: terminalEndpoint.port, maximumPayloadBytes: maximumPayloadBytes, timeoutMilliseconds: remaining())
            func receive() throws -> sending ReceivedMachCommandSubmission {
                while true {
                    try checkCancellation()
                    let budget = try remaining()
                    do { return try receiver.receiveAdmissionReply(timeoutMilliseconds: budget, previewTimeoutMilliseconds: min(budget, 250)) }
                    catch MachCommandCallerError.timeout { _ = try remaining() }
                }
            }
            let reply = try receive(); defer { reply.caller.close() }
            try checkCancellation(); _ = try remaining()
            try handshake.authenticateReply(reply.caller, expression: expression, userID: userID, auditSessionID: auditSessionID)
            let verified = try CommandAdmissionResultPayload.decode(reply.payload, profile: handshake.profile, original: submission)
            try checkCancellation(); _ = try remaining()
            guard case .admitted = verified.outcome else {
                terminalEndpoint.close(); handshake.close()
                return .result(verified)
            }
            let session = try RetainedCommandExecutionSession(admission: verified, original: submission, handshake: handshake,
                endpoint: terminalEndpoint, expression: expression, userID: userID, auditSessionID: auditSessionID)
            return .admitted(session)
        } catch { handshake.close(); throw error }
    }
}
