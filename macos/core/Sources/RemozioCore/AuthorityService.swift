import Foundation

/// Owns one authority listener and its journal for a single service lifetime.
/// Protected installation and configuration loading must precede construction.
public final class AuthorityService: @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private let journal: AuthorityJournal
    private let listener: AuthorityXPCListener
    private var started = false
    private var closed = false

    /// Transfers the database to this service. Construction failure releases its writer lease.
    public init(configuration: AuthorityServiceConfiguration, database: sending JournalDatabase) throws {
        let journal = AuthorityJournal(database: database)
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
        } catch {
            try? journal.close()
            throw error
        }
    }

    deinit { listener.close(); try? journal.close() }

    /// A failed start retires this instance. Recovery requires a new protected startup.
    public func start() throws {
        try lock.withLock {
            guard !started, !closed else { throw AuthorityXPCEndpointError.unavailable }
            do {
                try listener.start()
                started = true
            } catch {
                closed = true
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
            listener.close()
            try journal.close()
        }
    }
}
