import Darwin

/// Owns only private controls. Separate stdin, stdout and stderr remain with the native process owner.
final class CommandPipeControlChannel {
    private let channel: MachCommandStreamAuthority
    private(set) var opened = false
    private(set) var connected = true

    init(channel: MachCommandStreamAuthority) { self.channel = channel }
    func open() throws -> Bool {
        guard connected else { throw CommandStreamError.closed }
        if opened { return true }
        opened = try channel.send(.opened)
        return opened
    }
    func observeJobState(_ value: CommandJobStatePayload?) throws {
        if connected { try channel.observeJobState(value) }
    }
    func poll(expression: String, userID: uid_t, auditSessionID: au_asid_t?, checkCaller: () throws -> Void,
              checkControlPolicy: () throws -> Void, applyControl: (CommandStreamFrame.Body) throws -> Void,
              currentJob: () throws -> CommandCurrentJobState = { .unknown }) throws {
        guard opened, connected else { return }
        do {
            try checkCaller()
            for _ in 0..<CommandPTYStreamPump.maximumControlsPerTurn {
                guard let body = try channel.receiveControl(expression: expression, userID: userID, auditSessionID: auditSessionID) else { break }
                try checkControlPolicy()
                switch body {
                case .signal, .cancel: try applyControl(body)
                case .queryCurrentJob: break
                default: throw CommandStreamError.malformed
                }
            }
            try channel.flushCurrentJob(expression: expression, userID: userID, auditSessionID: auditSessionID,
                checkPolicy: checkControlPolicy, currentState: currentJob)
            try channel.flushJobState(checkPolicy: checkControlPolicy)
        } catch { detach(); throw error }
    }
    func detach() { connected = false; channel.close() }
    func close() { detach() }
}
