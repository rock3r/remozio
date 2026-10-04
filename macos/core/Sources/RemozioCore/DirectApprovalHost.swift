import Foundation
import Security

public enum DirectHostError: Error { case stopped, staleSession }
public enum DirectHostState: Sendable, Equatable {
    case stopped, noEligiblePhones, starting, ready(port: UInt16), failed
}

public struct DirectHostPolicy: Sendable, Equatable {
    public let maximumPayloadBytes: Int
    public let minimumEnvelopeVersion: UInt64
    public let auditVersions: Set<UInt64>
    public init(maximumPayloadBytes: Int, minimumEnvelopeVersion: UInt64 = 1,
                auditVersions: Set<UInt64> = []) throws {
        guard (1...16_777_216).contains(maximumPayloadBytes), minimumEnvelopeVersion > 0,
              auditVersions.count <= 16, !auditVersions.contains(0) else {
            throw DirectListenerError.invalidConfiguration
        }
        self.maximumPayloadBytes = maximumPayloadBytes
        self.minimumEnvelopeVersion = minimumEnvelopeVersion
        self.auditVersions = auditVersions
    }
}

/// Identifies one authenticated channel incarnation. It grants no approval or execution authority.
public struct DirectApprovalSession: Sendable {
    public let peer: DirectApprovalPeer
    fileprivate let generation: UUID
    fileprivate let revision: UUID
}

protocol OwnedDirectListener: Sendable {
    func start() throws
    func close()
}
extension DirectApprovalListener: OwnedDirectListener { }

/// Owns the journal and listener. All journal operations run without suspension on this actor.
/// Transport handlers must use a session transaction for each operation, then apply the existing decision verifiers.
public actor DirectApprovalHost {
    typealias Factory = (UUID, [DirectApprovalPeer], @escaping @Sendable (DirectListenerEvent) -> Void,
        @escaping @Sendable (DirectApprovalPeer, NegotiatedNetworkChannel) async throws -> Void) throws -> any OwnedDirectListener
    private let database: JournalDatabase
    private let factory: Factory
    private let handler: @Sendable (DirectApprovalSession, NegotiatedNetworkChannel) async throws -> Void
    private var policy: DirectHostPolicy
    private var listener: (generation: UUID, revision: UUID, value: any OwnedDirectListener)?
    private var enabled = false
    private var closed = false
    public private(set) var state: DirectHostState = .stopped

    /// Transfer exclusive journal ownership. The identity must come from the protected service's key owner.
    public init(database: sending JournalDatabase, identity: sending SecIdentity, policy: DirectHostPolicy,
                binding: DirectApprovalListener.Binding = .localNetwork, maximumConnections: Int = 8,
                timeoutMilliseconds: UInt64 = 15_000,
                handler: @escaping @Sendable (DirectApprovalSession, NegotiatedNetworkChannel) async throws -> Void) {
        self.database = database; self.policy = policy; self.handler = handler
        factory = { _, peers, event, handler in
            try DirectApprovalListener(identity: identity, peers: peers, binding: binding,
                maximumConnections: maximumConnections, timeoutMilliseconds: timeoutMilliseconds,
                event: event, handler: handler)
        }
    }

    init(database: sending JournalDatabase, policy: DirectHostPolicy, factory: sending @escaping Factory,
         handler: @escaping @Sendable (DirectApprovalSession, NegotiatedNetworkChannel) async throws -> Void = { _, _ in }) {
        self.database = database; self.policy = policy; self.factory = factory; self.handler = handler
    }

    public func start() throws {
        guard !closed else { throw DirectHostError.stopped }
        enabled = true
        try refresh()
    }
    public func stop() {
        enabled = false; invalidate(); state = .stopped
    }
    public func close() throws {
        stop(); closed = true
        try database.close()
    }
    public func updatePolicy(_ value: DirectHostPolicy) throws {
        guard !closed else { throw DirectHostError.stopped }
        guard policy != value else { return }
        invalidate(); policy = value
        if enabled { try refresh() }
    }

    /// Trusted local service operation. Callers cannot retain a usable transaction after this callback returns.
    public func read<T: Sendable>(_ body: @Sendable (JournalTransaction) throws -> T) throws -> T {
        guard !closed else { throw DirectHostError.stopped }
        do { return try database.read(body) }
        catch { reconcile(); throw error }
    }

    /// A listener failure after commit does not turn a committed write into an apparent rollback. Inspect state separately.
    public func write<T: Sendable>(_ body: @Sendable (JournalTransaction) throws -> T) throws -> T {
        guard !closed else { throw DirectHostError.stopped }
        defer { reconcile() }
        return try database.write(body)
    }

    /// Rechecks the listener incarnation and protected enrollment in the same transaction as the supplied operation.
    /// The callback must not perform asynchronous work or treat channel authentication as authorization to act.
    public func transaction<T: Sendable>(session: DirectApprovalSession, write: Bool = false,
                                        _ body: @Sendable (JournalTransaction) throws -> T) throws -> T {
        guard enabled, !closed, listener?.generation == session.generation else { throw DirectHostError.staleSession }
        defer { reconcile() }
        let checked: (JournalTransaction) throws -> T = { tx in
            try tx.requireDirectApprovalPeer(session.peer, expectedTrustRevision: session.revision)
            return try body(tx)
        }
        return try write ? database.write(checked) : database.read(checked)
    }

    func admit(_ peer: DirectApprovalPeer, generation: UUID) throws -> DirectApprovalSession {
        guard enabled, !closed, let active = listener, active.generation == generation else { throw DirectHostError.staleSession }
        do {
            try database.read { try $0.requireDirectApprovalPeer(peer, expectedTrustRevision: active.revision) }
            return DirectApprovalSession(peer: peer, generation: generation, revision: active.revision)
        } catch { reconcile(); throw error }
    }

    private func reconcile() {
        guard enabled else { return }
        do { try refresh() } catch { }
    }
    private func refresh() throws {
        do {
            let trust = try database.read { try $0.directApprovalTrust(maximumPayloadBytes: policy.maximumPayloadBytes,
                minimumEnvelopeVersion: policy.minimumEnvelopeVersion, auditVersions: policy.auditVersions) }
            if listener?.revision == trust.revision { return }
            invalidate()
            guard !trust.peers.isEmpty else { state = .noEligiblePhones; return }
            let generation = UUID()
            let handler = handler
            let value = try factory(generation, trust.peers, { [weak self] event in
                Task { await self?.changed(event, generation: generation) }
            }, { [weak self] peer, channel in
                guard let self else { throw DirectHostError.stopped }
                let session = try await self.admit(peer, generation: generation)
                try await handler(session, channel)
            })
            listener = (generation, trust.revision, value)
            state = .starting
            try value.start()
        } catch {
            invalidate(); state = .failed
            throw error
        }
    }
    private func changed(_ event: DirectListenerEvent, generation: UUID) {
        guard enabled, listener?.generation == generation else { return }
        switch event {
        case .ready(let port): state = .ready(port: port)
        case .failed, .stopped: invalidate(); state = .failed
        }
    }
    private func invalidate() {
        let previous = listener; listener = nil
        previous?.value.close()
    }
}
