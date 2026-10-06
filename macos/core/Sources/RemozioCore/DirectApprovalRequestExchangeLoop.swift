import Foundation
import RemozioProtocol

/// One consumer owns root operations and all writes. The reader applies backpressure without dropping decisions.
struct DirectApprovalRequestExchangeLoop: Sendable {
    let service: DirectApprovalTransportService
    let session: DirectApprovalSession
    let channel: NegotiatedNetworkChannel
    let remoteRequests: [ChannelRequestCapability]
    let timeoutMilliseconds: UInt64
    let refreshMilliseconds: UInt64

    func run() async throws {
        let events = RequestExchangeEvents()
        await events.refresh()
        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask {
                do {
                    while let bytes = try await channel.receive(maximumBytes: min(session.peer.maximumPayloadBytes, AuthorityRequestExchange.maximumFrameBytes)) {
                        guard await events.push(bytes) else { return }
                    }
                    await events.finish()
                } catch { await events.finish(error) }
            }
            group.addTask {
                do {
                    while true {
                        try await Task.sleep(for: .milliseconds(Int64(refreshMilliseconds)))
                        await events.refresh()
                    }
                } catch { }
            }
            do { try await consume(events) }
            catch {
                group.cancelAll(); channel.close(); await events.finish()
                throw error
            }
            group.cancelAll(); channel.close(); await events.finish()
        }
    }

    private func consume(_ events: RequestExchangeEvents) async throws {
        var watching = Set<Data>()
        var work: [Data] = [], position = 0
        while true {
            try Task.checkCancellation()
            let event = await events.next(wait: position == work.count)
            switch event {
            case .ended(let error):
                if let error { throw error }
                return
            case .refresh:
                let ids = try await service.pendingRequestIDs(for: session)
                let remaining = Set(work.dropFirst(position)).union(ids).union(watching)
                guard remaining.count <= AuthorityPendingRequests.maximumRequests else { throw ApprovalChannelError.invalidInput }
                work = remaining.sorted { $0.lexicographicallyPrecedes($1) }; position = 0
            case .incoming(let bytes):
                let requestID: Data, decision: Data?
                if let query = try? RequestStatusQuery.decode(bytes) {
                    requestID = query.requestID; decision = nil
                } else {
                    guard session.peer.maximumPayloadBytes > ApprovalMessage.overheadBytes else { throw ApprovalChannelError.invalidInput }
                    let message = try ApprovalMessage.decode(bytes, maximumBodyBytes: min(session.peer.maximumPayloadBytes,
                        AuthorityRequestExchange.maximumFrameBytes) - ApprovalMessage.overheadBytes)
                    guard message.type == .decision else { throw ApprovalChannelError.invalidInput }
                    let limits = try CBORLimits(maxBytes: AuthorityRequestExchange.maximumFrameBytes, maxDepth: 4, maxItems: 64)
                    let claim = try DecisionPayload.decode(message.body, limits: limits)
                    guard claim.macID == session.peer.scope.macID, claim.accountID == session.peer.scope.accountID,
                          claim.phoneID == session.peer.scope.phoneID else { throw ApprovalChannelError.invalidInput }
                    requestID = claim.requestID; decision = bytes
                }
                // These are routing claims. The root verifies every decision and retains the first valid winner.
                try await sendStatus(for: requestID, decision: decision, watching: &watching)
            case .work:
                let id = work[position]; position += 1
                if let frame = try await service.requestFrame(for: session, requestID: id),
                   try DirectApprovalTransportService.supports(frame, maximumBytes: session.peer.maximumPayloadBytes,
                       local: session.peer.requests, remote: remoteRequests) {
                    try await send(frame)
                    try await sendStatus(for: id, watching: &watching)
                } else if watching.contains(id) {
                    // Presence can suppress discovery and captures. It cannot hide the outcome of a retained request.
                    try await sendStatus(for: id, watching: &watching)
                }
            }
        }
    }

    private func sendStatus(for id: Data, decision: Data? = nil, watching: inout Set<Data>) async throws {
        guard let frame = try await service.exchangeRequest(for: session, requestID: id, decisionFrame: decision) else {
            watching.remove(id)
            return
        }
        let message = try ApprovalMessage.decode(frame, maximumBodyBytes: AuthorityRequestExchange.maximumFrameBytes - ApprovalMessage.overheadBytes)
        let status = try RequestStatusPayload.decode(message.body,
            limits: CBORLimits(maxBytes: AuthorityRequestExchange.maximumFrameBytes, maxDepth: 4, maxItems: 64))
        try await send(frame)
        if status.phase.isTerminal { watching.remove(id) }
        else {
            guard watching.contains(id) || watching.count < AuthorityPendingRequests.maximumRequests else {
                throw ApprovalChannelError.invalidInput
            }
            watching.insert(id)
        }
    }

    private func send(_ frame: Data) async throws {
        guard frame.count <= session.peer.maximumPayloadBytes else { throw ApprovalChannelError.invalidInput }
        try await service.validate(session)
        try await DirectApprovalTransportService.send(frame, over: channel,
            deadline: ContinuousClock.now.advanced(by: .milliseconds(Int64(timeoutMilliseconds))))
    }
}

/// At most eight queued frames and one blocked reader. Timer events occupy one bit.
private actor RequestExchangeEvents {
    enum Event: Sendable { case incoming(Data), refresh, work, ended((any Error)?) }
    private var frames: [Data] = []
    private var refreshing = false
    private var ended = false
    private var failure: (any Error)?
    private var reader: CheckedContinuation<Event, Never>?
    private var sender: (Data, CheckedContinuation<Bool, Never>)?

    func push(_ frame: Data) async -> Bool {
        guard !ended else { return false }
        if let reader {
            self.reader = nil; reader.resume(returning: .incoming(frame)); return true
        }
        if frames.count < 8 { frames.append(frame); return true }
        return await withCheckedContinuation { sender = (frame, $0) }
    }
    func refresh() {
        guard !ended else { return }
        if let reader { self.reader = nil; reader.resume(returning: .refresh) }
        else { refreshing = true }
    }
    func next(wait: Bool) async -> Event {
        if ended { return .ended(failure) }
        if !frames.isEmpty {
            let frame = frames.removeFirst()
            if let sender {
                self.sender = nil; frames.append(sender.0); sender.1.resume(returning: true)
            }
            return .incoming(frame)
        }
        if !wait { return .work }
        if refreshing { refreshing = false; return .refresh }
        return await withCheckedContinuation { reader = $0 }
    }
    func finish(_ error: (any Error)? = nil) {
        guard !ended else { return }
        ended = true; failure = error; frames.removeAll(); refreshing = false
        reader?.resume(returning: .ended(error)); reader = nil
        sender?.1.resume(returning: false); sender = nil
    }
}
