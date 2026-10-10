import Darwin
import Foundation

private final class GatewayWakeOwnedConnection: OwnedAuthorityConnection, @unchecked Sendable {
    let connection: NSXPCConnection
    let endpoint: GatewayWakeXPCEndpoint
    init(_ connection: NSXPCConnection, _ endpoint: GatewayWakeXPCEndpoint) { self.connection = connection; self.endpoint = endpoint }
    func activate() { connection.activate() }
    func close() { endpoint.close(); connection.invalidate() }
}

/// Transport connection loss removes only that connection. It never retires the independent Root lease.
final class GatewayWakeXPCListener: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private let listener: NSXPCListener
    private let registry: AuthorityConnectionRegistry
    private let configuration: GatewayWakeEndpointConfiguration
    private let serviceUID: uid_t
    private let clock: AuthorityClock
    private let budget: AuthorityXPCWorkBudget
    private let execute: @Sendable (GatewayWakeSubmission, Data, GatewayWakeChallenge) async throws -> Void
    private var running = false
    private var closed = false

    init(configuration: GatewayWakeEndpointConfiguration, serviceUID: uid_t, clock: AuthorityClock,
         handshakeTimeoutMillis: UInt64,
         execute: @escaping @Sendable (GatewayWakeSubmission, Data, GatewayWakeChallenge) async throws -> Void) throws {
        guard serviceUID > 0, serviceUID != configuration.transportUID else { throw GatewayServiceError.invalidConfiguration }
        self.configuration = configuration; self.serviceUID = serviceUID; self.clock = clock; self.execute = execute
        registry = try AuthorityConnectionRegistry(maximum: configuration.maximumConnections, timeoutMilliseconds: handshakeTimeoutMillis)
        budget = try AuthorityXPCWorkBudget(maximum: configuration.maximumOperations)
        listener = NSXPCListener(machServiceName: configuration.serviceName)
        super.init()
        configuration.policy.configure(listener); listener.delegate = self
    }
    func start() throws {
        try lock.withLock {
            guard getuid() == serviceUID, geteuid() == serviceUID else { throw GatewayServiceError.wrongAccount }
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
                let endpoint = try GatewayWakeXPCEndpoint(connection: connection, policy: configuration.policy, budget: budget,
                    clock: clock, challengeLifetimeMillis: configuration.challengeLifetimeMillis,
                    onHandshake: { [registry] in registry.handshake(id) }, onClose: { [registry] in registry.remove(id) }, execute: execute)
                return registry.install(GatewayWakeOwnedConnection(connection, endpoint), id: id)
            } catch { registry.remove(id); connection.invalidate(); return false }
        }
    }
}
