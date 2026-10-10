import Darwin
import Foundation

private final class GatewayOwnedConnection: OwnedAuthorityConnection, @unchecked Sendable {
    let connection: NSXPCConnection
    let endpoint: GatewayXPCEndpoint
    init(_ connection: NSXPCConnection, _ endpoint: GatewayXPCEndpoint) { self.connection = connection; self.endpoint = endpoint }
    func activate() { connection.activate() }
    func close() { endpoint.close(); connection.invalidate() }
}

/// One Root control connection per gateway process. Loss retires the process before a replacement can dispatch.
final class GatewayXPCListener: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private let listener: NSXPCListener
    private let registry: AuthorityConnectionRegistry
    private let configuration: GatewayServiceConfiguration
    private let budget: AuthorityXPCWorkBudget
    private let lost: @Sendable () -> Void
    private let synchronize: @Sendable (GatewayHostSnapshot) async throws -> Void
    private let execute: @Sendable (GatewayRootCommand) async throws -> Data
    private var running = false
    private var closed = false

    init(configuration: GatewayServiceConfiguration, lost: @escaping @Sendable () -> Void,
         synchronize: @escaping @Sendable (GatewayHostSnapshot) async throws -> Void,
         execute: @escaping @Sendable (GatewayRootCommand) async throws -> Data) throws {
        self.configuration = configuration; self.lost = lost; self.synchronize = synchronize; self.execute = execute
        registry = try AuthorityConnectionRegistry(maximum: 1, timeoutMilliseconds: configuration.settings.handshakeTimeoutMillis)
        budget = try AuthorityXPCWorkBudget(maximum: configuration.settings.maximumOperations)
        listener = NSXPCListener(machServiceName: configuration.serviceName)
        super.init()
        configuration.authorityPolicy.configure(listener)
        listener.delegate = self
    }
    func start() throws {
        try lock.withLock {
            try configuration.requireProcess(realUID: getuid(), effectiveUID: geteuid())
            guard !running, !closed else { throw GatewayServiceError.unavailable }
            try registry.start(); running = true; listener.activate()
        }
    }
    func close() {
        lock.withLock { running = false; closed = true; listener.invalidate(); listener.delegate = nil }
        registry.close()
    }
    deinit { listener.invalidate(); registry.close() }
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        lock.withLock {
            guard listener === self.listener, running, !closed, let id = registry.reserve() else { connection.invalidate(); return false }
            do {
                let endpoint = try GatewayXPCEndpoint(connection: connection, policy: configuration.authorityPolicy, budget: budget,
                    onHandshake: { [registry] in registry.handshake(id) }, onClose: { [weak self, registry, lost] in
                        // Retire the lease synchronously, before actor cancellation or a new listener callback.
                        lost(); self?.close(); registry.remove(id)
                    }, synchronize: synchronize, execute: execute)
                return registry.install(GatewayOwnedConnection(connection, endpoint), id: id)
            } catch { registry.remove(id); connection.invalidate(); return false }
        }
    }
}
