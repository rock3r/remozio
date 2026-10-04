import Foundation

/// Invalidation is synchronous, including while actor callbacks are waiting to run.
final class AuthorityTrustLease: @unchecked Sendable {
    private let lock = NSLock()
    private var active = true
    var isActive: Bool { lock.withLock { active } }
    func invalidate() { lock.withLock { active = false } }
}

/// One authenticated authority incarnation, owned by the dedicated transport service.
/// Keep the host alive separately. Reconnection uses a new feed and a fresh handshake.
public actor AuthorityTrustFeed {
    typealias Factory = @Sendable (@escaping @Sendable () -> Void) throws -> AuthorityXPCChannel
    private let macID: Data
    private let accountID: Data
    private let factory: Factory
    private let refreshMilliseconds: UInt64
    private let maximumWaiting: Int
    private let lease = AuthorityTrustLease()
    private weak var host: DirectApprovalTransportHost?
    private var channel: AuthorityXPCChannel?
    private var timer: Task<Void, Never>?
    private var lastSnapshot: Data?
    private var started = false
    private var ready = false
    private var closed = false
    private var busy = false
    private var waiters: [(UUID, CheckedContinuation<Void, Error>)] = []

    public init(serviceName: String, peerPolicy: XPCPeerPolicy, macID: Data, accountID: Data,
                timeoutMilliseconds: UInt64 = 5000, refreshMilliseconds: UInt64 = 5000,
                maximumWaiting: Int = 8) throws {
        guard macID.count == 16, accountID.count == 16, (500...60_000).contains(refreshMilliseconds),
              (0...64).contains(maximumWaiting) else { throw AuthorityXPCError.invalidConfiguration }
        self.macID = macID; self.accountID = accountID
        self.refreshMilliseconds = refreshMilliseconds; self.maximumWaiting = maximumWaiting
        factory = { onClose in try AuthorityXPCChannel(serviceName: serviceName, peerPolicy: peerPolicy,
            timeoutMilliseconds: timeoutMilliseconds, onClose: onClose) }
    }
    init(macID: Data, accountID: Data, refreshMilliseconds: UInt64 = 60_000, maximumWaiting: Int = 8,
         factory: @escaping Factory) {
        self.macID = macID; self.accountID = accountID; self.refreshMilliseconds = refreshMilliseconds
        self.maximumWaiting = maximumWaiting; self.factory = factory
    }
    deinit {
        lease.invalidate(); timer?.cancel(); channel?.abort()
        let host = host, lease = lease
        Task { await host?.authorityDisconnected(lease) }
    }

    public func start(host: DirectApprovalTransportHost) async throws {
        guard !started, !closed else { throw AuthorityXPCError.invalidState }
        started = true; busy = true; self.host = host
        defer { release() }
        do {
            try await host.beginAuthority(lease)
            try requireActive()
            let value = try factory { [weak self, lease] in
                lease.invalidate()
                Task { await self?.close() }
            }
            channel = value
            try await value.start()
            try await update(value)
            try requireActive(); ready = true
            timer = Task { [weak self, refreshMilliseconds] in
                while !Task.isCancelled {
                    do { try await Task.sleep(for: .milliseconds(Int64(refreshMilliseconds))) } catch { return }
                    guard let self else { return }
                    do { try await self.refreshWhenIdle() } catch { return }
                }
            }
        } catch { await close(); throw error }
    }
    private func refreshWhenIdle() async throws {
        guard !busy else { return }
        try await refresh()
    }
    public func refresh() async throws {
        try await acquire()
        defer { release() }
        do { try await update(try activeChannel()) }
        catch { await close(); throw error }
    }
    /// Every call reaches the authority. A previous allow result is never cached.
    public func validatePeer(_ peer: DirectApprovalPeer, revision: UUID) async throws {
        try await acquire()
        defer { release() }
        let allowed: Bool
        do {
            allowed = try await activeChannel().validatePeer(AuthorityPeerBinding(peer: peer, revision: revision))
            try requireActive()
        } catch { await close(); throw error }
        guard allowed else { throw DirectHostError.staleSession }
    }
    public func close() async {
        if !closed {
            closed = true; ready = false; lease.invalidate(); timer?.cancel(); timer = nil
            channel?.abort(); channel = nil; lastSnapshot = nil
            let pending = waiters; waiters.removeAll()
            for (_, waiter) in pending { waiter.resume(throwing: AuthorityXPCError.closed) }
        }
        await host?.authorityDisconnected(lease)
    }
    private func update(_ channel: AuthorityXPCChannel) async throws {
        let trust = try await channel.fetchTrust(expectedMacID: macID, expectedAccountID: accountID)
        try requireActive()
        let bytes = try AuthorityTrustCodec.encodeSnapshot(trust)
        guard bytes != lastSnapshot else { return }
        guard let host else { throw AuthorityXPCError.closed }
        try await host.replaceTrust(trust, authority: lease)
        try requireActive(); lastSnapshot = bytes
    }
    private func requireActive() throws {
        try Task.checkCancellation()
        guard !closed, lease.isActive else { throw AuthorityXPCError.closed }
    }
    private func activeChannel() throws -> AuthorityXPCChannel {
        try requireActive()
        guard let channel else { throw AuthorityXPCError.closed }; return channel
    }
    private func acquire() async throws {
        try requireActive()
        guard ready else { throw AuthorityXPCError.invalidState }
        if !busy { busy = true; return }
        guard waiters.count < maximumWaiting else { throw AuthorityXPCError.concurrentOperation }
        let id = UUID()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { waiters.append((id, $0)) }
        } onCancel: { Task { await self.cancel(id) } }
        do { try requireActive() } catch { release(); throw error }
    }
    private func cancel(_ id: UUID) {
        guard let index = waiters.firstIndex(where: { $0.0 == id }) else { return }
        waiters.remove(at: index).1.resume(throwing: CancellationError())
    }
    private func release() {
        if waiters.isEmpty { busy = false }
        else { waiters.removeFirst().1.resume() }
    }
}
