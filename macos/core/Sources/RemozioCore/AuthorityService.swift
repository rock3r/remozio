import Foundation

/// Owns one authority listener and its journal for a single service lifetime.
/// Protected installation and configuration loading must precede construction.
public final class AuthorityService: @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private let journal: AuthorityJournal
    private let listener: AuthorityXPCListener
    private var maintenance: AuthorityMaintenanceLoop?
    private var started = false
    private var closed = false

    /// Transfers the database to this service. Construction failure releases its writer lease.
    public convenience init(configuration: AuthorityServiceConfiguration, database: sending JournalDatabase) throws {
        try self.init(configuration: configuration, journal: AuthorityJournal(database: database))
    }

    /// Shares the prepared request owner with the service. Service closure retires that owner too.
    public init(configuration: AuthorityServiceConfiguration, journal: AuthorityJournal,
                maintenanceIntervalMilliseconds: Int = 1000,
                maintain: (@Sendable () throws -> Void)? = nil) throws {
        self.journal = journal
        do {
            listener = try AuthorityXPCListener(serviceName: configuration.serviceName,
                peerPolicy: configuration.transportPolicy, macID: configuration.macID,
                accountID: configuration.accountID, journal: journal,
                maximumPayloadBytes: configuration.maximumPayloadBytes,
                minimumEnvelopeVersion: configuration.minimumEnvelopeVersion,
                auditVersions: configuration.auditVersions,
                maximumConnections: configuration.maximumConnections,
                handshakeTimeoutMilliseconds: configuration.handshakeTimeoutMilliseconds,
                maximumOperations: configuration.maximumOperations)
            if let maintain {
                maintenance = try AuthorityMaintenanceLoop(intervalMilliseconds: maintenanceIntervalMilliseconds,
                    work: maintain, failed: { [weak self] in try? self?.close() })
            }
        } catch {
            try? journal.close()
            throw error
        }
    }

    /// Samples authority time under the request lock and reconciles committed expiry before releasing it.
    /// Clock and reconciliation callbacks must be synchronous and must not reenter this service or journal.
    public convenience init(configuration: AuthorityServiceConfiguration, journal: AuthorityJournal,
                            maintenanceIntervalMilliseconds: Int = 1000,
                            expiryClock: @escaping @Sendable () throws -> AuthorityMoment,
                            receiptTime: @escaping @Sendable () -> UInt64? = { nil },
                            reconcileExpired: @escaping @Sendable ([ApprovalRequestState]) throws -> Void) throws {
        try self.init(configuration: configuration, journal: journal,
            maintenanceIntervalMilliseconds: maintenanceIntervalMilliseconds, maintain: {
                try journal.withRequests { requests in
                    let states = try requests.expirePending(now: expiryClock(), receiptTimeMs: receiptTime())
                    try reconcileExpired(states)
                }
            })
    }

    deinit { maintenance?.close(); listener.close(); try? journal.close() }

    /// A failed start retires this instance. Recovery requires a new protected startup.
    public func start() throws {
        try lock.withLock {
            guard !started, !closed else { throw AuthorityXPCEndpointError.unavailable }
            do {
                try listener.start()
                try maintenance?.start()
                started = true
            } catch {
                closed = true
                maintenance?.close()
                listener.close()
                try? journal.close()
                throw error
            }
        }
    }

    /// Stops admissions before waiting for any journal transaction and releasing storage.
    public func close() throws {
        try lock.withLock {
            closed = true
            maintenance?.close()
            listener.close()
            try journal.close()
        }
    }
}
