import Foundation

@objc public protocol GatewayRootXPCProtocol {
    func hello(reply: @escaping @Sendable (UInt64) -> Void)
    func synchronize(_ snapshot: Data, reply: @escaping @Sendable (Bool) -> Void)
    func command(_ bytes: Data, reply: @escaping @Sendable (Data?) -> Void)
}

/// Verify the accepted connection on the exported invocation stack, before creating any asynchronous work.
final class GatewayXPCEndpoint: NSObject, GatewayRootXPCProtocol, @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private let verify: () throws -> Void
    private let invalidate: () -> Void
    private let onHandshake: @Sendable () -> Void
    private let budget: AuthorityXPCWorkBudget
    private let synchronizeState: @Sendable (GatewayHostSnapshot) async throws -> Void
    private let execute: @Sendable (GatewayRootCommand) async throws -> Data
    private var ready = false
    private var closed = false
    private var busy = false
    private var task: Task<Void, Never>?
    private var operationID: UUID?

    convenience init(connection: NSXPCConnection, policy: XPCPeerPolicy, budget: AuthorityXPCWorkBudget,
                     onHandshake: @escaping @Sendable () -> Void, onClose: @escaping @Sendable () -> Void,
                     synchronize: @escaping @Sendable (GatewayHostSnapshot) async throws -> Void,
                     execute: @escaping @Sendable (GatewayRootCommand) async throws -> Data) throws {
        guard policy.expectedUserID == 0 else { throw GatewayServiceError.invalidConfiguration }
        _ = try policy.verifyCredentials(connection)
        let invocation = XPCInvocationGuard(connection: connection, policy: policy)
        self.init(verify: { _ = try invocation.verifyInvocation() }, budget: budget, onHandshake: onHandshake,
            invalidate: { [weak connection] in onClose(); connection?.invalidate() }, synchronize: synchronize, execute: execute)
        policy.configure(connection)
        connection.exportedInterface = NSXPCInterface(with: GatewayRootXPCProtocol.self)
        connection.exportedObject = self
        connection.interruptionHandler = { [weak self] in self?.close() }
        connection.invalidationHandler = { [weak self] in self?.close() }
    }
    init(verify: @escaping () throws -> Void, budget: AuthorityXPCWorkBudget,
         onHandshake: @escaping @Sendable () -> Void = {}, invalidate: @escaping () -> Void,
         synchronize: @escaping @Sendable (GatewayHostSnapshot) async throws -> Void,
         execute: @escaping @Sendable (GatewayRootCommand) async throws -> Data) {
        self.verify = verify; self.budget = budget; self.onHandshake = onHandshake; self.invalidate = invalidate
        synchronizeState = synchronize; self.execute = execute
    }
    func close() {
        let removed = lock.withLock { () -> (Bool, Task<Void, Never>?) in
            guard !closed else { return (false, nil) }
            closed = true; ready = false; return (true, task)
        }
        if removed.0 { invalidate(); removed.1?.cancel() }
    }
    func hello(reply: @escaping @Sendable (UInt64) -> Void) {
        do {
            try verify()
            try lock.withLock {
                guard !closed, !ready, !busy else { throw GatewayServiceError.unavailable }
                ready = true; onHandshake(); reply(1)
            }
        } catch { close(); reply(0) }
    }
    func synchronize(_ snapshot: Data, reply: @escaping @Sendable (Bool) -> Void) {
        submit(decode: { try GatewayHostSnapshot.decode(snapshot) }, failed: { reply(false) }) { [synchronizeState] value in
            try await synchronizeState(value)
            return { reply(true) }
        }
    }
    func command(_ bytes: Data, reply: @escaping @Sendable (Data?) -> Void) {
        submit(decode: { try GatewayRootCommand.decode(bytes) }, failed: { reply(nil) }) { [execute] command in
            let result = try await execute(command)
            return { reply(result) }
        }
    }
    private func submit<Value: Sendable>(decode: () throws -> Value, failed: @escaping @Sendable () -> Void,
                                        run: @escaping @Sendable (Value) async throws -> (@Sendable () -> Void)) {
        do {
            try verify()
            try lock.withLock {
                guard ready, !closed, !busy, budget.acquire() else { throw GatewayServiceError.unavailable }
                busy = true
                let value: Value
                do { value = try decode() } catch { busy = false; budget.release(); throw error }
                let id = UUID(); operationID = id
                task = Task { [self] in
                    defer { finish(id) }
                    do {
                        try Task.checkCancellation()
                        let respond = try await run(value)
                        try Task.checkCancellation()
                        lock.withLock { finish(id); if !closed { respond() } }
                    } catch { lock.withLock { finish(id); if !closed { failed() } } }
                }
            }
        } catch { close(); failed() }
    }
    private func finish(_ id: UUID) {
        lock.withLock {
            guard operationID == id else { return }
            operationID = nil; busy = false; task = nil; budget.release()
        }
    }
}
