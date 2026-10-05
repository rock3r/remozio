import CryptoKit
import Foundation
import Security
import RemozioProtocol

/// Owns the authority's sole journal connection. Only Sendable results can leave a serialized transaction.
public final class AuthorityJournal: @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private let database: JournalDatabase
    private var storage: AuthorityStorage?
    private var requests: ApprovalRequestCoordinator?
    private var requestOperationActive = false
    private var requestStartupAttempted = false

    /// Transfer exclusive ownership. The caller must not keep another user of this connection.
    public init(database: sending JournalDatabase) { self.database = database }

    /// Owns the configured stores for trust-only service work. Action recovery remains a separate gate.
    init(storage: sending AuthorityStorage) throws {
        do {
            switch try JournalCheckpointRecovery.reconcile(journal: storage.journal, continuity: storage.continuity) {
            case .unchanged, .finalized, .discarded: break
            case .historyDiscontinuity: throw AuthorityStorageStartupError.historyRecoveryRequired
            case .repairRequired: throw AuthorityStorageStartupError.repairRequired
            }
            database = storage.journal
            self.storage = storage
        } catch {
            try? storage.close()
            throw error
        }
    }

    /// Runs once after host identity validation, before activating a listener or admitting request work.
    /// An incomplete attempt retires both stores. The next attempt must reopen and reconcile them.
    func prepareRequests(clock: AuthorityClock, maximumPayloadBytes: Int) throws {
        try lock.withLock {
            try requireNoRequestOperation()
            guard let storage else { return }
            try database.read { _ in () }
            guard !requestStartupAttempted, requests == nil else { throw JournalStartupRecovery.Failure.alreadyStarted }
            requestStartupAttempted = true
            do {
                let limits = try CBORLimits(maxBytes: maximumPayloadBytes, maxDepth: 32, maxItems: 262_144)
                let auditLimits = try CBORLimits(maxBytes: 16_777_216, maxDepth: 32, maxItems: 262_144)
                let retainedBytes = 67_108_864
                guard maximumPayloadBytes <= retainedBytes else { throw ApprovalCoordinatorError.invalidConfiguration }
                let checkpoint = try storage.continuity.read().committed
                var fresh = Data(count: 16)
                guard fresh.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!) }) == errSecSuccess else {
                    throw ApprovalCoordinatorError.unavailable
                }
                let epoch = fresh
                let descriptor = try read { transaction in
                    guard let previous = try transaction.epoch(checkpoint.journalEpoch),
                          try transaction.epoch(epoch) == nil else { throw JournalStartupRecovery.Failure.invalidEpoch }
                    var previousID: CBORValue = .null, previousHead: CBORValue = .null, previousDigest: CBORValue = .null
                    if previous.head == 0 {
                        previousID = .bytes(previous.descriptor.epoch); previousHead = .unsigned(0)
                    } else if previous.retainedAfter < previous.head {
                        let page = try transaction.page(epoch: previous.descriptor.epoch, after: previous.head - 1,
                            maximumRecords: 1, maximumBytes: auditLimits.maxBytes)
                        guard let last = page.canonicalRecords.first else { throw AuditJournalError.corruptData }
                        previousID = .bytes(previous.descriptor.epoch); previousHead = .unsigned(previous.head)
                        previousDigest = .bytes(Data(SHA256.hash(data: last)))
                    }
                    // Fully pruned predecessors have no retained event digest. Do not invent a verified link.
                    return try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
                        0: .unsigned(1), 1: .bytes(previous.descriptor.macID), 2: .bytes(previous.descriptor.accountID),
                        3: .bytes(epoch), 4: .unsigned(checkpoint.currentAuthorityGeneration), 5: .unsigned(AuditEpochCause.restart.rawValue),
                        6: previousID, 7: previousHead, 8: previousDigest,
                    ]), limits: auditLimits), limits: auditLimits)
                }
                let recovery = try JournalStartupRecovery(journal: database, continuity: storage.continuity,
                    maximumRecords: 128, maximumBytes: 16_777_216)
                var progress = try recovery.start(descriptor: descriptor)
                while true {
                    switch progress {
                    case .recovering: progress = try recovery.advance()
                    case .historyDiscontinuity: throw AuthorityStorageStartupError.historyRecoveryRequired
                    case .repairRequired: throw AuthorityStorageStartupError.repairRequired
                    case .complete:
                        requests = try ApprovalRequestCoordinator(database: database, continuity: storage.continuity,
                            writer: recovery.completedWriter(), clockEpoch: clock.epoch, maximumRequests: 1024,
                            maximumRetainedBytes: retainedBytes, requestLimits: limits, captureLimits: limits,
                            decisionLimits: limits, signingLimits: auditLimits, auditLimits: auditLimits)
                        return
                    }
                }
            } catch {
                try? close()
                throw error
            }
        }
    }

    /// Transfers the database and epoch writer into one serialization boundary.
    /// Recovery and admission-storage gates must pass before construction.
    public init(requests: sending ApprovalRequestCoordinator) {
        database = requests.database
        self.requests = requests
    }

    /// Runs synchronous request work under the journal lock. The coordinator cannot escape in the result.
    /// The callback must not await or reenter this owner.
    public func withRequests<Value: Sendable>(_ body: @Sendable (ApprovalRequestCoordinator) throws -> Value) throws -> Value {
        try lock.withLock {
            try requireNoRequestOperation()
            try database.read { _ in () } // Reject closed storage or entry from a transaction callback.
            guard let requests else { throw ApprovalCoordinatorError.unavailable }
            requestOperationActive = true
            defer { requestOperationActive = false }
            return try body(requests)
        }
    }

    private func requireNoRequestOperation() throws {
        guard !requestOperationActive else { throw JournalDatabaseError.transactionActive }
    }

    public func read<Value: Sendable>(_ body: @Sendable (JournalTransaction) throws -> Value) throws -> Value {
        try lock.withLock {
            try requireNoRequestOperation()
            if let storage {
                let checkpoint = try storage.continuity.read()
                guard !checkpoint.recoveryRequired, checkpoint.pending == nil else { throw JournalDatabaseError.unavailable }
                return try database.read { transaction in
                    let actual = try CheckpointedJournal.checkpoint(transaction: transaction,
                        epoch: checkpoint.committed.journalEpoch, generation: checkpoint.committed.generation,
                        authorityGeneration: checkpoint.committed.authorityGeneration)
                    guard actual == checkpoint.committed else { throw JournalDatabaseError.unavailable }
                    return try body(transaction)
                }
            }
            return try database.read(body)
        }
    }
    public func write<Value: Sendable>(_ body: @Sendable (JournalTransaction) throws -> Value) throws -> Value {
        try lock.withLock {
            try requireNoRequestOperation()
            guard storage == nil else { throw JournalDatabaseError.readOnly }
            return try database.write(body)
        }
    }
    public func close() throws {
        try lock.withLock {
            try requireNoRequestOperation()
            try database.close()
            storage?.continuity.close()
            requests = nil
        }
    }

    public func trustSnapshot(maximumPayloadBytes: Int, minimumEnvelopeVersion: UInt64 = 1,
                              auditVersions: Set<UInt64> = []) throws -> DirectApprovalTrust {
        try read { try $0.directApprovalTrust(maximumPayloadBytes: maximumPayloadBytes,
            minimumEnvelopeVersion: minimumEnvelopeVersion, auditVersions: auditVersions) }
    }
    /// A current enrollment check, not permission to approve or execute a request.
    public func validatePeer(_ binding: AuthorityPeerBinding) throws -> Bool {
        do {
            try read { try $0.requireDirectApprovalBinding(binding) }
            return true
        } catch EnrollmentJournalError.staleRevision { return false }
          catch EnrollmentJournalError.unavailableEnrollment { return false }
    }
}
