import Foundation
import RemozioProtocol

/// Trusted root provider. Use the supplied clock for request checks, including a fresh sample after signing.
public typealias AuthorityRequestFrameProvider = @Sendable (
    ApprovalRequestCoordinator, AuthorityPeerBinding, Data, @Sendable () throws -> AuthorityMoment
) throws -> Data?

/// Trusted discovery provider. Use the authority clock and current local presence when scanning requests.
public typealias AuthorityPendingRequestsProvider = @Sendable (
    ApprovalRequestCoordinator, AuthorityPeerBinding, @Sendable () throws -> AuthorityMoment
) throws -> [Data]

/// Owns one authority listener and its journal for a single service lifetime.
/// Protected installation and configuration loading must precede construction.
public final class AuthorityService: @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private let journal: AuthorityJournal
    private let listener: AuthorityXPCListener
    private var maintenance: AuthorityMaintenanceLoop?
    private let requestClock: @Sendable () throws -> AuthorityMoment
    private var started = false
    private var closed = false

    /// Opens the provisioned launch stores. Version 2 retains independent continuity ownership until shutdown.
    public convenience init(configuration: AuthorityServiceConfiguration) throws {
        let journal: AuthorityJournal
        if configuration.continuityDirectory != nil {
            journal = try AuthorityJournal(recovering: AuthorityStorage.open(configuration: configuration),
                macID: configuration.macID, accountID: configuration.accountID)
        } else {
            let limits = try CBORLimits(maxBytes: 16_777_216, maxDepth: 32, maxItems: 262_144)
            journal = try AuthorityJournal(database: JournalDatabase.open(directoryPath: configuration.journalDirectory,
                macID: configuration.macID, accountID: configuration.accountID,
                recordLimits: limits, descriptorLimits: limits, decisionLimits: limits,
                maximumConsumptions: 1_000_000, busyMilliseconds: 5000))
        }
        try self.init(configuration: configuration, journal: journal)
    }

    /// Transfers the database to this service. Construction failure releases its writer lease.
    public convenience init(configuration: AuthorityServiceConfiguration, database: sending JournalDatabase) throws {
        try self.init(configuration: configuration, journal: AuthorityJournal(database: database))
    }

    /// Shares the prepared request owner with the service. Service closure retires that owner too.
    public convenience init(configuration: AuthorityServiceConfiguration, journal: AuthorityJournal,
                            maintenanceIntervalMilliseconds: Int = 1000,
                            maintain: (@Sendable () throws -> Void)? = nil,
                            requestFrame: AuthorityRequestFrameProvider? = nil,
         pendingRequestIDs: AuthorityPendingRequestsProvider? = nil) throws {
        try self.init(configuration: configuration, journal: journal, maintenanceIntervalMilliseconds: maintenanceIntervalMilliseconds,
            maintain: maintain, validateSelf: AuthoritySelfValidation.validate, requestFrame: requestFrame, pendingRequestIDs: pendingRequestIDs)
    }

    /// Internal lifecycle fixture. Public constructors always validate the running authority against retained policy.
    init(configuration: AuthorityServiceConfiguration, journal: AuthorityJournal,
         maintenanceIntervalMilliseconds: Int = 1000, maintain: (@Sendable () throws -> Void)? = nil,
         validateSelf: @Sendable (AuthorityJournal) throws -> Void,
         requestClock: (@Sendable () throws -> AuthorityMoment)? = nil,
         requestFrame: AuthorityRequestFrameProvider? = nil,
         pendingRequestIDs: AuthorityPendingRequestsProvider? = nil) throws {
        self.journal = journal
        do {
            if let requestClock { self.requestClock = requestClock }
            else {
                let clock = try AuthorityClock()
                self.requestClock = { try clock.now() }
            }
        } catch { try? journal.close(); throw error }
        do {
            try validateSelf(journal)
            let frameClock = self.requestClock
            let frameHandler: (@Sendable (ApprovalRequestCoordinator, AuthorityPeerBinding, Data) throws -> Data?)?
            if let requestFrame {
                frameHandler = { owner, binding, requestID in try requestFrame(owner, binding, requestID, frameClock) }
            } else { frameHandler = nil }
            let pendingHandler: (@Sendable (ApprovalRequestCoordinator, AuthorityPeerBinding) throws -> [Data])?
            if let pendingRequestIDs {
                pendingHandler = { owner, binding in try pendingRequestIDs(owner, binding, frameClock) }
            } else { pendingHandler = nil }
            listener = try AuthorityXPCListener(serviceName: configuration.serviceName,
                peerPolicy: configuration.transportPolicy, macID: configuration.macID,
                accountID: configuration.accountID, journal: journal,
                maximumPayloadBytes: configuration.maximumPayloadBytes,
                minimumEnvelopeVersion: configuration.minimumEnvelopeVersion,
                auditVersions: configuration.auditVersions,
                maximumConnections: configuration.maximumConnections,
                handshakeTimeoutMilliseconds: configuration.handshakeTimeoutMilliseconds,
                maximumOperations: configuration.maximumOperations, requestFrame: frameHandler, pendingRequestIDs: pendingHandler)
            let requestEpoch = try self.requestClock().epoch
            try journal.prepareRequests(clockEpoch: requestEpoch, maximumPayloadBytes: configuration.maximumPayloadBytes)
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
                            reconcileExpired: @escaping @Sendable ([ApprovalRequestState]) throws -> Void,
                            requestFrame: AuthorityRequestFrameProvider? = nil,
         pendingRequestIDs: AuthorityPendingRequestsProvider? = nil) throws {
        try self.init(configuration: configuration, journal: journal,
            maintenanceIntervalMilliseconds: maintenanceIntervalMilliseconds, expiryClock: expiryClock,
            receiptTime: receiptTime, reconcileExpired: reconcileExpired, validateSelf: AuthoritySelfValidation.validate, requestFrame: requestFrame, pendingRequestIDs: pendingRequestIDs)
    }

    /// Fixture seam for the same expiry path used by public construction.
    convenience init(configuration: AuthorityServiceConfiguration, journal: AuthorityJournal,
                     maintenanceIntervalMilliseconds: Int = 1000,
                     expiryClock: @escaping @Sendable () throws -> AuthorityMoment,
                     receiptTime: @escaping @Sendable () -> UInt64? = { nil },
                     reconcileExpired: @escaping @Sendable ([ApprovalRequestState]) throws -> Void,
                     validateSelf: @Sendable (AuthorityJournal) throws -> Void,
                     requestFrame: AuthorityRequestFrameProvider? = nil,
         pendingRequestIDs: AuthorityPendingRequestsProvider? = nil) throws {
        try self.init(configuration: configuration, journal: journal,
            maintenanceIntervalMilliseconds: maintenanceIntervalMilliseconds, maintain: {
                try journal.withRequests { requests in
                    let states = try requests.expirePending(now: expiryClock(), receiptTimeMs: receiptTime())
                    try reconcileExpired(states)
                }
            }, validateSelf: validateSelf, requestClock: expiryClock, requestFrame: requestFrame, pendingRequestIDs: pendingRequestIDs)
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
