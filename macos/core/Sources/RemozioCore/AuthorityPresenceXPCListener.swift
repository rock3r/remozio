import Darwin
import Foundation

/// Protected installation selects a distinct Mach service and the interactive account's signed app.
public struct AuthorityPresenceEndpointConfiguration: Sendable {
    public let serviceName: String
    public let appPolicy: XPCPeerPolicy
    public init(serviceName: String, appPolicy: XPCPeerPolicy) throws {
        guard GatewayWakeEndpointConfiguration.validServiceName(serviceName),
              appPolicy.expectedUserID > 0, appPolicy.expectedUserID < UInt32.max else { throw AuthorityPresenceError.invalidConfiguration }
        self.serviceName = serviceName; self.appPolicy = appPolicy
    }
}

private final class NativePresenceConnection: OwnedAuthorityConnection, @unchecked Sendable {
    private let connection: NSXPCConnection
    private let endpoint: AuthorityPresenceXPCEndpoint
    init(connection: NSXPCConnection, endpoint: AuthorityPresenceXPCEndpoint) { self.connection = connection; self.endpoint = endpoint }
    func activate() { connection.activate() }
    func close() { endpoint.close(); connection.invalidate() }
    deinit { connection.invalidate() }
}

/// Root owns this listener independently of the transport interface. Installation must register its Mach service.
public final class AuthorityPresenceXPCListener: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private let listener: NSXPCListener
    private let registry: AuthorityConnectionRegistry
    private let budget: AuthorityXPCWorkBudget
    private let policy: XPCPeerPolicy
    private let presence: AuthorityPresenceRuntime
    private let access: AuthorityPresenceAccess
    private let clock: AuthorityClock
    private var running = false
    private var closed = false
    public init(configuration: AuthorityPresenceEndpointConfiguration, journal: AuthorityJournal,
                presence: AuthorityPresenceRuntime, clock: AuthorityClock,
                maximumConnections: Int = 4, handshakeTimeoutMilliseconds: UInt64 = 5000, maximumOperations: Int = 4) throws {
        registry = try AuthorityConnectionRegistry(maximum: maximumConnections, timeoutMilliseconds: handshakeTimeoutMilliseconds)
        budget = try AuthorityXPCWorkBudget(maximum: maximumOperations)
        policy = configuration.appPolicy; self.presence = presence; self.clock = clock
        access = try AuthorityPresenceAccess(journal: journal, presence: presence, appPolicy: configuration.appPolicy,
            now: { try clock.now() })
        listener = NSXPCListener(machServiceName: configuration.serviceName)
        super.init()
        policy.configure(listener); listener.delegate = self
    }
    deinit { listener.invalidate(); registry.close() }
    public func start() throws {
        try lock.withLock {
            guard getuid() == 0, geteuid() == 0, !running, !closed else { throw AuthorityPresenceIPCError.unavailable }
            try access.verifyCurrent(); try registry.start(); running = true; listener.activate()
        }
    }
    public func close() {
        lock.withLock { closed = true; running = false; listener.invalidate(); listener.delegate = nil }
        registry.close()
    }
    public func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        lock.withLock {
            guard listener === self.listener, running, !closed, let id = registry.reserve() else { connection.invalidate(); return false }
            do {
                let binding = try AuthorityPresenceBinding(macID: presence.configuration.macID, accountID: presence.configuration.accountID,
                    clockEpoch: clock.epoch, connectionID: id)
                let endpoint = try AuthorityPresenceXPCEndpoint(connection: connection, policy: policy, binding: binding,
                    budget: budget, access: access, onHandshake: { [weak registry] in registry?.handshake(id) },
                    onClose: { [weak registry] in registry?.remove(id) })
                return registry.install(NativePresenceConnection(connection: connection, endpoint: endpoint), id: id)
            } catch { registry.remove(id); connection.invalidate(); return false }
        }
    }
}
