import Darwin
import Foundation

protocol OwnedAuthorityConnection: Sendable { func activate(); func close() }

/// Reservations cover setup and handshake, not just fully configured connections.
final class AuthorityConnectionRegistry: @unchecked Sendable {
    private struct Entry {
        var connection: (any OwnedAuthorityConnection)?
        var ready = false
        var deadline: Task<Void, Never>?
    }
    private let lock = NSRecursiveLock()
    private let maximum: Int
    private let timeoutMilliseconds: UInt64
    private var entries: [UUID: Entry] = [:]
    private var running = false
    private var closed = false
    init(maximum: Int, timeoutMilliseconds: UInt64) throws {
        guard (1...64).contains(maximum), (1...60_000).contains(timeoutMilliseconds) else { throw AuthorityXPCEndpointError.invalidConfiguration }
        self.maximum = maximum; self.timeoutMilliseconds = timeoutMilliseconds
    }
    deinit { close() }
    func start() throws {
        try lock.withLock {
            guard !running, !closed else { throw AuthorityXPCEndpointError.unavailable }; running = true
        }
    }
    func reserve() -> UUID? {
        lock.withLock {
            guard running, !closed, entries.count < maximum else { return nil }
            let id = UUID()
            let deadline = Task { [weak self, timeoutMilliseconds] in
                do { try await Task.sleep(for: .milliseconds(Int64(timeoutMilliseconds))) } catch { return }
                self?.expire(id)
            }
            entries[id] = Entry(deadline: deadline)
            return id
        }
    }
    func install(_ connection: any OwnedAuthorityConnection, id: UUID) -> Bool {
        let accepted = lock.withLock {
            guard var entry = entries[id], entry.connection == nil else { return false }
            entry.connection = connection; entries[id] = entry
            connection.activate()
            return entries[id] != nil
        }
        if !accepted { connection.close() }
        return accepted
    }
    func handshake(_ id: UUID) {
        lock.withLock {
            guard var entry = entries[id] else { return }
            entry.ready = true; entry.deadline?.cancel(); entry.deadline = nil; entries[id] = entry
        }
    }
    func remove(_ id: UUID) {
        let entry = lock.withLock { entries.removeValue(forKey: id) }
        entry?.deadline?.cancel(); entry?.connection?.close()
    }
    func expire(_ id: UUID) {
        let entry = lock.withLock { () -> Entry? in
            guard let entry = entries[id], !entry.ready else { return nil }
            return entries.removeValue(forKey: id)
        }
        entry?.deadline?.cancel(); entry?.connection?.close()
    }
    func close() {
        let removed = lock.withLock { () -> [Entry] in
            closed = true; running = false
            let removed = Array(entries.values); entries.removeAll(); return removed
        }
        for entry in removed { entry.deadline?.cancel(); entry.connection?.close() }
    }
}

private final class NativeAuthorityConnection: OwnedAuthorityConnection, @unchecked Sendable {
    let connection: NSXPCConnection
    let endpoint: AuthorityXPCEndpoint
    init(connection: NSXPCConnection, endpoint: AuthorityXPCEndpoint) { self.connection = connection; self.endpoint = endpoint }
    func activate() { connection.activate() }
    func close() { endpoint.close(); connection.invalidate() }
    deinit { connection.invalidate() }
}

/// Root Mach listener. Registration and protected installation are external prerequisites.
public final class AuthorityXPCListener: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private let listener: NSXPCListener
    private let registry: AuthorityConnectionRegistry
    private let policy: XPCPeerPolicy
    private let macID: Data
    private let accountID: Data
    private let budget: AuthorityXPCWorkBudget
    private let snapshot: @Sendable () throws -> DirectApprovalTrust
    private let validate: @Sendable (AuthorityPeerBinding) throws -> Bool
    private var running = false
    private var closed = false

    public init(serviceName: String, peerPolicy: XPCPeerPolicy, macID: Data, accountID: Data,
                maximumConnections: Int = 8, handshakeTimeoutMilliseconds: UInt64 = 5000,
                maximumOperations: Int = 8,
                snapshot: @escaping @Sendable () throws -> DirectApprovalTrust,
                validate: @escaping @Sendable (AuthorityPeerBinding) throws -> Bool) throws {
        guard serviceName.hasPrefix("dev.remozio."), (1...255).contains(serviceName.utf8.count),
              serviceName.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 46 || $0 == 45 }),
              peerPolicy.expectedUserID != 0, macID.count == 16, accountID.count == 16 else { throw AuthorityXPCEndpointError.invalidConfiguration }
        registry = try AuthorityConnectionRegistry(maximum: maximumConnections, timeoutMilliseconds: handshakeTimeoutMilliseconds)
        budget = try AuthorityXPCWorkBudget(maximum: maximumOperations)
        listener = NSXPCListener(machServiceName: serviceName)
        policy = peerPolicy; self.macID = macID; self.accountID = accountID
        self.snapshot = snapshot; self.validate = validate
        super.init()
        policy.configure(listener)
        listener.delegate = self
    }
    deinit { listener.invalidate(); registry.close() }
    public func start() throws {
        try lock.withLock {
            guard geteuid() == 0, !running, !closed else { throw AuthorityXPCEndpointError.unavailable }
            try registry.start(); running = true; listener.activate()
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
                let endpoint = try AuthorityXPCEndpoint(connection: connection, peerPolicy: policy, macID: macID, accountID: accountID,
                    budget: budget, onHandshake: { [weak registry] in registry?.handshake(id) },
                    onClose: { [weak registry] in registry?.remove(id) }, snapshot: snapshot, validate: validate)
                let owner = NativeAuthorityConnection(connection: connection, endpoint: endpoint)
                guard registry.install(owner, id: id) else { return false }
                return true
            } catch { registry.remove(id); connection.invalidate(); return false }
        }
    }
}
