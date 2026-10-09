import Darwin
import Foundation

/// Retains only private IO rights. This class cannot prepare, release, signal, or repeat a command.
/// The serialized execution owner keeps the original caller alive and supplies its current protected policy for each receive.
final class MachCommandStreamAuthority {
    private let binding: CommandStreamBinding
    private let original: RetainedCommandCaller
    private let endpoint: MachCommandPrivateReplyPort
    private let output: MachCommandAuthorityPort
    private var incoming = CommandStreamReceiveSequence(direction: .toAuthority)
    private var outgoing = CommandStreamReceiveSequence(direction: .toFrontend)
    private var closed = false
    private var observedJob: CommandJobStatePayload?
    private var pendingJob: CommandJobStatePayload?
    private(set) var outputDrained = false

    init(binding: CommandStreamBinding, original: RetainedCommandCaller, terminal: MachCommandReplyRight) throws {
        try binding.validate()
        guard original.retainedAuditBinding != nil else { throw MachCommandHandshakeError.retired }
        self.binding = binding; self.original = original
        output = try terminal.copyStreamRight()
        endpoint = try MachCommandPrivateReplyPort(queueLimit: 4)
    }
    deinit { close() }

    /// Zero progress means kernel backpressure. Retain the original body and retry it on a later bounded pump turn.
    func send(_ body: CommandStreamFrame.Body) throws -> Bool {
        guard !closed else { throw CommandStreamError.closed }
        let frame = CommandStreamFrame(sequence: outgoing.next, body: body)
        try outgoing.check(frame)
        let bytes = try frame.encode(binding: binding)
        let queued = try MachCommandWire.sendStream(bytes, destination: output.borrowed(),
            openedControl: body == .opened ? endpoint.port : nil)
        if queued {
            try outgoing.accept(frame)
            if body == .opened { try endpoint.releaseLocalSendRight() }
        }
        return queued
    }
    /// Coalesce only unsent observations. Native revisions can skip; emitted channel sequences cannot.
    func observeJobState(_ value: CommandJobStatePayload?) throws {
        guard binding.profile.supportsJobState, !closed else { return }
        guard let value else { pendingJob = nil; return }
        _ = try value.fields
        if let observedJob, value.revision <= observedJob.revision {
            guard value == observedJob else { throw CommandStreamError.sequence }
            return
        }
        observedJob = value; pendingJob = value
    }
    func flushJobState() throws {
        guard !closed, outgoing.next > 0, let pendingJob else { return }
        if try send(.jobState(pendingJob)) { self.pendingJob = nil }
    }
    func receiveControl(currentPolicy: XPCPeerPolicy) throws -> CommandStreamFrame.Body? {
        try receiveControl(expression: currentPolicy.requirement, userID: currentPolicy.expectedUserID,
            auditSessionID: currentPolicy.expectedAuditSessionID)
    }
    /// Internal fixture seam. Product callers supply the protected current code role through the method above.
    func receiveControl(expression: String, userID: uid_t, auditSessionID: au_asid_t?) throws -> CommandStreamFrame.Body? {
        guard !closed, outgoing.next > 0 else { throw CommandStreamError.closed }
        try original.recheck(expression: expression, userID: userID, auditSessionID: auditSessionID)
        let receiver = try MachCommandCallerReceiver(receivePort: endpoint.port, expression: expression,
            userID: userID, auditSessionID: auditSessionID, maxPayloadBytes: CommandStreamFrame.maximumBytes)
        let reply: ReceivedMachCommandSubmission
        do { reply = try receiver.receiveStreamControl() }
        catch MachCommandCallerError.timeout {
            guard try endpoint.hasSenders() else { throw CommandStreamError.closed }
            return nil
        }
        defer { reply.caller.close() }
        try original.recheck(expression: expression, userID: userID, auditSessionID: auditSessionID)
        guard original.hasSameAuditBinding(as: reply.caller) else { throw MachCommandHandshakeError.wrongBinding }
        let frame = try CommandStreamFrame.decode(reply.payload, binding: binding, direction: .toAuthority)
        if frame.body == .outputDrained {
            guard outgoing.ended, !outputDrained else { throw CommandStreamError.closed }
        }
        try incoming.accept(frame)
        if frame.body == .outputDrained { outputDrained = true }
        return frame.body
    }
    func close() {
        guard !closed else { return }
        closed = true; pendingJob = nil; endpoint.close(); output.close()
    }
}
