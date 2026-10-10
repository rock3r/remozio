import CryptoKit
import Foundation

/// A separate interface for transport possession proofs. It exposes no Root control or provider settings.
@objc public protocol GatewayWakeXPCProtocol {
    func hello(reply: @escaping @Sendable (UInt64) -> Void)
    func challenge(reply: @escaping @Sendable (Data?) -> Void)
    func wake(_ payload: Data, signature: Data, reply: @escaping @Sendable (Bool) -> Void)
}

struct GatewayWakeChallenge: Sendable { let bytes: Data; let issuedAt: UInt64; let deadline: UInt64 }

/// Challenges belong to one verified connection. Each submission consumes its challenge before asynchronous work starts.
final class GatewayWakeXPCEndpoint: NSObject, GatewayWakeXPCProtocol, @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private let verify: () throws -> Void
    private let invalidate: () -> Void
    private let onHandshake: @Sendable () -> Void
    private let budget: AuthorityXPCWorkBudget
    private let sample: @Sendable () throws -> UInt64
    private let lifetime: UInt64
    private let execute: @Sendable (GatewayWakeSubmission, Data, GatewayWakeChallenge) async throws -> Void
    private var ready = false
    private var closed = false
    private var outstanding: GatewayWakeChallenge?
    private var lastTime: UInt64 = 0
    private var task: Task<Void, Never>?
    private var operationID: UUID?

    convenience init(connection: NSXPCConnection, policy: XPCPeerPolicy, budget: AuthorityXPCWorkBudget,
                     clock: AuthorityClock, challengeLifetimeMillis: UInt64,
                     onHandshake: @escaping @Sendable () -> Void, onClose: @escaping @Sendable () -> Void,
                     execute: @escaping @Sendable (GatewayWakeSubmission, Data, GatewayWakeChallenge) async throws -> Void) throws {
        guard policy.expectedUserID > 0 else { throw GatewayServiceError.invalidConfiguration }
        _ = try policy.verifyCredentials(connection)
        let invocation = XPCInvocationGuard(connection: connection, policy: policy)
        try self.init(verify: { _ = try invocation.verifyInvocation() }, budget: budget,
            sample: { try clock.now().milliseconds }, challengeLifetimeMillis: challengeLifetimeMillis,
            onHandshake: onHandshake, invalidate: { [weak connection] in onClose(); connection?.invalidate() }, execute: execute)
        policy.configure(connection)
        connection.exportedInterface = NSXPCInterface(with: GatewayWakeXPCProtocol.self)
        connection.exportedObject = self
        connection.interruptionHandler = { [weak self] in self?.close() }
        connection.invalidationHandler = { [weak self] in self?.close() }
    }
    init(verify: @escaping () throws -> Void, budget: AuthorityXPCWorkBudget,
         sample: @escaping @Sendable () throws -> UInt64, challengeLifetimeMillis: UInt64,
         onHandshake: @escaping @Sendable () -> Void = {}, invalidate: @escaping () -> Void,
         execute: @escaping @Sendable (GatewayWakeSubmission, Data, GatewayWakeChallenge) async throws -> Void) throws {
        guard (1...60_000).contains(challengeLifetimeMillis) else { throw GatewayServiceError.invalidConfiguration }
        self.verify = verify; self.budget = budget; self.sample = sample; lifetime = challengeLifetimeMillis
        self.onHandshake = onHandshake; self.invalidate = invalidate; self.execute = execute
    }
    func close() {
        let removed = lock.withLock { () -> (Bool, Task<Void, Never>?) in
            guard !closed else { return (false, nil) }
            closed = true; ready = false; outstanding = nil; return (true, task)
        }
        if removed.0 { invalidate(); removed.1?.cancel() }
    }
    func hello(reply: @escaping @Sendable (UInt64) -> Void) {
        do {
            try verify()
            try lock.withLock {
                guard !closed, !ready, operationID == nil else { throw GatewayServiceError.unavailable }
                ready = true; onHandshake(); reply(1)
            }
        } catch { close(); reply(0) }
    }
    func challenge(reply: @escaping @Sendable (Data?) -> Void) {
        do {
            try verify()
            try lock.withLock {
                guard ready, !closed, operationID == nil else { throw GatewayServiceError.unavailable }
                let now = try current(), (deadline, overflow) = now.addingReportingOverflow(lifetime)
                guard !overflow else { throw GatewayServiceError.unavailable }
                let bytes = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
                outstanding = GatewayWakeChallenge(bytes: bytes, issuedAt: now, deadline: deadline)
                reply(bytes)
            }
        } catch { close(); reply(nil) }
    }
    func wake(_ payload: Data, signature: Data, reply: @escaping @Sendable (Bool) -> Void) {
        do {
            // Keep this check on the exported invocation stack. Message fields never supply peer identity.
            try verify()
            try lock.withLock {
                guard ready, !closed, operationID == nil, let challenge = outstanding else { throw GatewayServiceError.unavailable }
                outstanding = nil
                let now = try current()
                guard now >= challenge.issuedAt, now < challenge.deadline, signature.count == 64 else { throw GatewayServiceError.invalidMessage }
                let submission = try GatewayWakeSubmission.decode(payload)
                guard submission.challenge == challenge.bytes else { throw GatewayServiceError.invalidMessage }
                guard budget.acquire() else { throw GatewayServiceError.capacityExceeded }
                let id = UUID(); operationID = id
                task = Task { [self] in
                    defer { finish(id) }
                    do {
                        try Task.checkCancellation()
                        // Admission may wait for the coordinator actor. Recheck the same original challenge deadline there.
                        try await execute(submission, signature, challenge)
                        try Task.checkCancellation()
                        lock.withLock { finish(id); if !closed { reply(true) } }
                    } catch { lock.withLock { finish(id); if !closed { reply(false) } } }
                }
            }
        } catch { close(); reply(false) }
    }
    private func current() throws -> UInt64 {
        let now = try sample()
        guard now >= lastTime else { throw GatewayServiceError.unavailable }
        lastTime = now
        return now
    }
    private func finish(_ id: UUID) {
        lock.withLock {
            guard operationID == id else { return }
            operationID = nil; task = nil; budget.release()
        }
    }
}
