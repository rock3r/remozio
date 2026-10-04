import Foundation

public enum AuthorityXPCEndpointError: Error { case invalidConfiguration, unavailable }

/// Share one budget across all authority transport endpoints. Admission never queues waiting work.
public final class AuthorityXPCWorkBudget: @unchecked Sendable {
    private let lock = NSLock()
    private let maximum: Int
    private var active = 0
    public init(maximum: Int = 8) throws {
        guard (1...64).contains(maximum) else { throw AuthorityXPCEndpointError.invalidConfiguration }
        self.maximum = maximum
    }
    func acquire() -> Bool { lock.withLock { guard active < maximum else { return false }; active += 1; return true } }
    func release() { lock.withLock { active -= 1 } }
}

/// One exported transport connection. Handlers execute synchronously and must use the root owner's serialized journal access.
/// This endpoint exports no mutation, arbitrary signing, credential release, or execution operation.
public final class AuthorityXPCEndpoint: NSObject, TransportAuthorityXPCProtocol, @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private let verify: () throws -> Void
    private let invalidate: () -> Void
    private let snapshot: @Sendable () throws -> DirectApprovalTrust
    private let validate: @Sendable (AuthorityPeerBinding) throws -> Bool
    private let budget: AuthorityXPCWorkBudget
    private let macID: Data
    private let accountID: Data
    private var ready = false
    private var closed = false
    private var busy = false

    /// The listener must enforce the same peer policy and own the accepted connection. Activate it only after this initializer succeeds.
    public convenience init(connection: NSXPCConnection, peerPolicy: XPCPeerPolicy, macID: Data, accountID: Data,
                            budget: AuthorityXPCWorkBudget,
                            snapshot: @escaping @Sendable () throws -> DirectApprovalTrust,
                            validate: @escaping @Sendable (AuthorityPeerBinding) throws -> Bool) throws {
        guard peerPolicy.expectedUserID != 0, macID.count == 16, accountID.count == 16 else { throw AuthorityXPCEndpointError.invalidConfiguration }
        _ = try peerPolicy.verifyCredentials(connection)
        let invocation = XPCInvocationGuard(connection: connection, policy: peerPolicy)
        self.init(macID: macID, accountID: accountID, budget: budget,
            verify: { _ = try invocation.verifyInvocation() }, invalidate: { [weak connection] in connection?.invalidate() },
            snapshot: snapshot, validate: validate)
        peerPolicy.configure(connection)
        connection.exportedInterface = NSXPCInterface(with: TransportAuthorityXPCProtocol.self)
        connection.exportedObject = self
        connection.interruptionHandler = { [weak self] in self?.close() }
        connection.invalidationHandler = { [weak self] in self?.close() }
    }
    init(macID: Data, accountID: Data, budget: AuthorityXPCWorkBudget,
         verify: @escaping () throws -> Void, invalidate: @escaping () -> Void,
         snapshot: @escaping @Sendable () throws -> DirectApprovalTrust,
         validate: @escaping @Sendable (AuthorityPeerBinding) throws -> Bool) {
        self.macID = macID; self.accountID = accountID; self.budget = budget
        self.verify = verify; self.invalidate = invalidate; self.snapshot = snapshot; self.validate = validate
    }
    public func close() {
        let notify = lock.withLock { if closed { return false }; closed = true; ready = false; return true }
        if notify { invalidate() }
    }
    public func hello(reply: @escaping @Sendable (UInt64) -> Void) {
        do {
            try verify()
            let accepted = lock.withLock { guard !closed, !ready, !busy else { return false }; ready = true; return true }
            guard accepted else { throw AuthorityXPCEndpointError.unavailable }
            send { reply(1) }
        } catch { close(); reply(0) }
    }
    public func trustSnapshot(reply: @escaping @Sendable (Data?) -> Void) {
        do {
            try begin(); defer { end() }
            let trust = try snapshot()
            guard trust.macID == macID, trust.accountID == accountID else { throw AuthorityXPCEndpointError.unavailable }
            let bytes = try AuthorityTrustCodec.encodeSnapshot(trust)
            send { reply(bytes) }
        } catch { close(); reply(nil) }
    }
    public func validatePeer(_ binding: Data, reply: @escaping @Sendable (Bool) -> Void) {
        do {
            try begin(); defer { end() }
            let decoded = try AuthorityTrustCodec.decodeBinding(binding, expectedMacID: macID, expectedAccountID: accountID)
            let allowed = try validate(decoded)
            send { reply(allowed) }
        } catch { close(); reply(false) }
    }
    private func begin() throws {
        try verify()
        try lock.withLock {
            guard !closed, ready, !busy, budget.acquire() else { throw AuthorityXPCEndpointError.unavailable }
            busy = true
        }
    }
    private func end() { lock.withLock { busy = false }; budget.release() }
    private func send(_ reply: () -> Void) { lock.withLock { if !closed { reply() } } }
}
