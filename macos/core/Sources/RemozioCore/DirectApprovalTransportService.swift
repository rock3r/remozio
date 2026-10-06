import Foundation
import Security

/// Owns one transport incarnation. Authority reconnection requires a new service instance.
public actor DirectApprovalTransportService {
    private let feed: AuthorityTrustFeed
    private let host: DirectApprovalTransportHost
    private var started = false
    private var closed = false

    public init(macID: Data, accountID: Data, identity: sending SecIdentity,
                authorityServiceName: String, authorityPolicy: XPCPeerPolicy,
                binding: DirectApprovalListener.Binding = .localNetwork,
                maximumConnections: Int = 8, timeoutMilliseconds: UInt64 = 15_000,
                authorityTimeoutMilliseconds: UInt64 = 5000, refreshMilliseconds: UInt64 = 5000,
                maximumWaiting: Int = 8,
                handler: @escaping @Sendable (DirectApprovalSession, NegotiatedNetworkChannel) async throws -> Void) throws {
        let feed = try AuthorityTrustFeed(serviceName: authorityServiceName, peerPolicy: authorityPolicy,
            macID: macID, accountID: accountID, timeoutMilliseconds: authorityTimeoutMilliseconds,
            refreshMilliseconds: refreshMilliseconds, maximumWaiting: maximumWaiting)
        self.feed = feed
        host = try DirectApprovalTransportHost(macID: macID, accountID: accountID, identity: identity,
            binding: binding, maximumConnections: maximumConnections, timeoutMilliseconds: timeoutMilliseconds,
            validatePeer: { try await feed.validatePeer($0, revision: $1) }, handler: handler)
    }

    init(feed: AuthorityTrustFeed, host: DirectApprovalTransportHost) {
        self.feed = feed; self.host = host
    }

    deinit {
        let feed = feed, host = host
        Task { await host.close(); await feed.close() }
    }

    public var state: DirectHostState { get async { await host.state } }

    public func start() async throws {
        guard !started, !closed else { throw DirectHostError.stopped }
        started = true
        do {
            try Task.checkCancellation()
            try await feed.start(host: host)
            guard !closed else { throw DirectHostError.stopped }
            try Task.checkCancellation()
            try await host.start()
            guard !closed else { throw DirectHostError.stopped }
            try Task.checkCancellation()
        } catch { await close(); throw error }
    }

    /// Retrieves a frame for this live phone session. It neither acknowledges delivery nor grants an action.
    public func requestFrame(for session: DirectApprovalSession, requestID: Data) async throws -> Data? {
        guard started, !closed else { throw DirectHostError.stopped }
        try await host.validate(session)
        let frame = try await feed.requestFrame(session.peer, revision: session.revision, requestID: requestID)
        try Task.checkCancellation()
        guard !closed else { throw DirectHostError.stopped }
        try await host.validate(session)
        try Task.checkCancellation()
        guard !closed else { throw DirectHostError.stopped }
        return frame
    }

    public func close() async {
        closed = true
        await host.close()
        await feed.close()
    }
}
