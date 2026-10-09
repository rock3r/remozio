import Darwin
import Foundation
import RemozioProtocol

/// Admission returns either an owned live result channel or a verified admission result. Neither permits execution by the frontend.
public enum CommandIOAdmission {
    case admitted(RetainedCommandExecutionSession)
    case result(VerifiedCommandAdmissionResult)
}

/// Ordered stream observations grant no execution or retry permission.
public enum CommandExecutionStreamEvent {
    case opened, output(Data), outputEnded, inputCapacity(Int)
    case terminal(VerifiedCommandTerminalResult)
}

/// Owns the original Root handshake and private terminal endpoint after admission. The caller serializes all operations.
public final class RetainedCommandExecutionSession {
    public static let maximumInputChunk = CommandStreamFrame.maximumChunk
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
    private var incoming = CommandStreamReceiveSequence(direction: .toFrontend)
    private var outgoing = CommandStreamReceiveSequence(direction: .toAuthority)
    private var control: MachCommandAuthorityPort?
    private var inputCapacity = 0
    private var outputAcknowledged = false
    private var streamBinding: CommandStreamBinding {
        get throws {
            guard case .admitted(let request) = admission.outcome else { throw CommandStreamError.binding }
            return CommandStreamBinding(profile: handshake.profile, submission: original.binding,
                submissionDigest: admission.submissionDigest, request: request)
        }
    }
    fileprivate init(admission: VerifiedCommandAdmissionResult, original: CommandSubmission, handshake: VerifiedCommandHandshake,
                     endpoint: MachCommandPrivateReplyPort, expression: String, userID: uid_t, auditSessionID: au_asid_t?) throws {
        self.admission = admission; self.original = original; self.handshake = handshake; self.endpoint = endpoint
        self.expression = expression; self.userID = userID; self.auditSessionID = auditSessionID
        receiver = try MachCommandCallerReceiver(receivePort: endpoint.port, expression: expression, userID: userID,
            auditSessionID: auditSessionID, maxPayloadBytes: handshake.profile.supportsStreamingExecution ? CommandStreamFrame.maximumBytes : 4096)
    }
    /// A poll timeout with no observed message returns nil. It does not expire an approval or impose a command runtime limit.
    /// Malformed, late or unauthenticated results retire this channel. They never authorize resubmission.
    public func pollTerminalResult(timeoutMilliseconds: UInt32 = 250,
                                   checkCancellation: () throws -> Void = {}) throws -> VerifiedCommandTerminalResult? {
        try pollTerminalResult(timeoutMilliseconds: timeoutMilliseconds, checkCancellation: checkCancellation, clock: nil)
    }
    func pollTerminalResult(timeoutMilliseconds: UInt32, checkCancellation: () throws -> Void = {},
                            clock: (() throws -> UInt64)?) throws -> VerifiedCommandTerminalResult? {
        guard !handshake.profile.supportsStreamingExecution else { throw MachCommandHandshakeError.incompatible }
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
    /// Each poll has a finite wait. It imposes no command lifetime limit and never repeats a submission.
    public func pollStreamEvent(timeoutMilliseconds: UInt32 = 250) throws -> CommandExecutionStreamEvent? {
        guard handshake.profile.supportsStreamingExecution, (1...60_000).contains(timeoutMilliseconds) else {
            throw MachCommandHandshakeError.incompatible
        }
        if let terminal { return .terminal(terminal) }
        guard !closed else { throw MachCommandHandshakeError.retired }
        let clock = try AuthorityClock(), started = try clock.now().milliseconds
        func remaining() throws -> UInt32 {
            let current = try clock.now().milliseconds
            guard current >= started, current - started < UInt64(timeoutMilliseconds) else { throw CommandTerminalResultError.deadlineExceeded }
            return UInt32(UInt64(timeoutMilliseconds) - (current - started))
        }
        do {
            try handshake.authenticateReplyAuthority(expression: expression, userID: userID, auditSessionID: auditSessionID)
            let event: ReceivedMachCommandExecutionEvent
            do { event = try receiver.receiveExecutionEvent(timeoutMilliseconds: remaining()) }
            catch MachCommandCallerError.timeout { return nil }
            switch event {
            case .stream(let reply, let right):
                defer { reply.caller.close(); right?.close() }
                try handshake.authenticateReply(reply.caller, expression: expression, userID: userID, auditSessionID: auditSessionID)
                let frame = try CommandStreamFrame.decode(reply.payload, binding: streamBinding, direction: .toFrontend)
                _ = try remaining()
                try incoming.check(frame)
                guard (frame.body == .opened) == (right != nil) else { throw CommandStreamError.malformed }
                let observation: CommandExecutionStreamEvent
                switch frame.body {
                case .opened:
                    guard let right else { throw CommandStreamError.malformed }
                    control = try right.takeControlRight()
                    inputCapacity = CommandStreamFrame.inputWindow; observation = .opened
                case .output(let bytes): observation = .output(bytes)
                case .outputEnd: observation = .outputEnded
                case .inputCredit(let count):
                    guard Int(count) <= CommandStreamFrame.inputWindow - inputCapacity else { throw CommandStreamError.capacity }
                    inputCapacity += Int(count); observation = .inputCapacity(inputCapacity)
                default: throw CommandStreamError.malformed
                }
                try incoming.accept(frame)
                return observation
            case .terminal(let reply):
                defer { reply.caller.close() }
                try handshake.authenticateReply(reply.caller, expression: expression, userID: userID, auditSessionID: auditSessionID)
                let result = try CommandTerminalResultPayload.decode(reply.payload, profile: handshake.profile,
                    original: original, admission: admission)
                _ = try remaining()
                if incoming.next == 0 {
                    guard !result.outputInterrupted else { throw CommandStreamError.closed }
                    switch result.outcome {
                    case .exited, .signalled: throw CommandStreamError.closed
                    default: break
                    }
                } else if !result.outputInterrupted && (!incoming.ended || !outputAcknowledged) { throw CommandStreamError.closed }
                terminal = result; close()
                return .terminal(result)
            }
        } catch { close(); throw error }
    }
    /// Returns the accepted count. Keep the entire unsent input when this returns zero.
    /// The caller bounds its own buffer and must not read input before admission and the opened event.
    public func forwardInput(_ bytes: Data) throws -> Int {
        guard !closed, control != nil, !outgoing.ended else { throw CommandStreamError.closed }
        guard (1...CommandStreamFrame.maximumChunk).contains(bytes.count) else { throw CommandStreamError.capacity }
        guard bytes.count <= inputCapacity else { return 0 }
        if try sendControl(.input(bytes)) { inputCapacity -= bytes.count; return bytes.count }
        return 0
    }
    public func finishInput() throws -> Bool { try sendControl(.inputEnd) }
    public func forwardSignal(_ signal: UInt32) throws -> Bool { try sendControl(.signal(signal)) }
    public func resizeTerminal(rows: UInt16, columns: UInt16, pixelWidth: UInt16 = 0, pixelHeight: UInt16 = 0) throws -> Bool {
        try sendControl(.resize(rows, columns, pixelWidth, pixelHeight))
    }
    public func cancelCommand() throws -> Bool { try sendControl(.cancel) }
    /// Call after all output bytes are consumed. A full control queue preserves this acknowledgment for the caller to retry.
    public func acknowledgeOutput() throws -> Bool {
        guard !closed, incoming.ended else { throw CommandStreamError.closed }
        if outputAcknowledged { return true }
        outputAcknowledged = try sendControl(.outputDrained)
        return outputAcknowledged
    }
    private func sendControl(_ body: CommandStreamFrame.Body) throws -> Bool {
        guard !closed, handshake.profile.supportsStreamingExecution, let control else { throw CommandStreamError.closed }
        let frame = CommandStreamFrame(sequence: outgoing.next, body: body)
        try outgoing.check(frame)
        let bytes = try frame.encode(binding: streamBinding)
        do {
            try handshake.authenticateReplyAuthority(expression: expression, userID: userID, auditSessionID: auditSessionID)
            let queued = try MachCommandWire.sendStream(bytes, destination: control.borrowed(), toAuthority: true)
            if queued { try outgoing.accept(frame) }
            return queued
        } catch { close(); throw error }
    }
    public func close() { if !closed { closed = true; control?.close(); control = nil; endpoint.close(); handshake.close() } }
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
            let terminalEndpoint = try MachCommandPrivateReplyPort(queueLimit: handshake.profile.supportsStreamingExecution ? 4 : nil)
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
