import Foundation

public enum GatewayRecoveryAttemptError: Error, Equatable {
    case invalidConfiguration, wrongPhase, localStateChanged, stopped
}

/// Historical results only. Neither case grants authority or permits publishing a mapping.
public enum GatewayRecoveryCollection: Sendable {
    case head(VerifiedGatewayHead)
    case history(VerifiedGatewayHistory)
}

/// One serialized root-side attempt, constructed after independent authority continuity checks.
/// The host must invalidate it when registration activity or either key pin changes.
public final class GatewayRecoveryAttempt {
    public let expectedLocalRevision: UInt64
    public private(set) var result: GatewayRecoveryCollection?
    /// A committed restriction awaiting the host's independent checkpoint and delivery refresh.
    public private(set) var pendingCheckpoint: GatewayTrustEvidenceRecovery?
    private let database: JournalDatabase
    private let writer: AuditEpochWriter
    private let registration: GatewayRegistrationIdentity
    private let queries: GatewayHeadQueryOwner
    private let maximumRecords: Int
    private let maximumBytes: Int
    private let pageSize: Int
    private var collector: GatewayHistoryCollector?
    private enum Evidence {
        case head(VerifiedGatewayHead)
        case page(VerifiedGatewayControlHistory)
    }
    private var pending: Evidence?
    private var queryInFlight = false
    private var processing = false
    private var stopped = false

    public init(database: JournalDatabase, writer: AuditEpochWriter, registration: GatewayRegistrationIdentity,
                gatewayPublicKey: Data, clockEpoch: UUID, queryLifetimeMillis: UInt64 = 30_000,
                pageSize: Int = 16, maximumRecords: Int = 100_000, maximumBytes: Int = 64 * 1024 * 1024) throws {
        guard (1...16).contains(pageSize), (1...100_000).contains(maximumRecords),
              (1...64 * 1024 * 1024).contains(maximumBytes) else { throw GatewayRecoveryAttemptError.invalidConfiguration }
        expectedLocalRevision = try database.read { tx in
            let trust = try tx.approvalTrustSnapshot()
            guard trust.macID == registration.macID, trust.accountID == registration.accountID,
                  let epoch = try tx.epoch(writer.epoch), epoch.descriptor.macID == trust.macID,
                  epoch.descriptor.accountID == trust.accountID else { throw GatewayAuthorityError.wrongScope }
            return try tx.gatewayAuthorityHead(registration)
        }
        queries = try GatewayHeadQueryOwner(registration: registration, gatewayPublicKey: gatewayPublicKey,
            clockEpoch: clockEpoch, lifetimeMillis: queryLifetimeMillis, maximumQueries: 1)
        self.database = database; self.writer = writer; self.registration = registration
        self.pageSize = pageSize; self.maximumRecords = maximumRecords; self.maximumBytes = maximumBytes
    }

    /// An unanswered query can be replaced after its deadline. No extra history query can bypass pending recovery.
    public func makeQuery(now: AuthorityMoment) throws -> Data {
        try requireActive()
        guard pending == nil, !processing else { throw GatewayRecoveryAttemptError.wrongPhase }
        let query: Data
        if let collector {
            guard let after = collector.nextAfterRevision else { throw GatewayRecoveryAttemptError.wrongPhase }
            query = try queries.makeHistoryQuery(afterRevision: after, throughRevision: collector.throughRevision,
                maximumRecords: pageSize, now: now)
        } else {
            query = try queries.makeQuery(now: now)
        }
        queryInFlight = true
        return query
    }

    public func accept(_ reply: GatewayHeadReply, now: AuthorityMoment) throws {
        try requireActive()
        guard queryInFlight, collector == nil, pending == nil, !processing else { throw GatewayRecoveryAttemptError.wrongPhase }
        pending = .head(try queries.accept(reply, now: now))
        queryInFlight = false
    }

    public func accept(_ reply: GatewayControlHistoryReply, now: AuthorityMoment) throws {
        try requireActive()
        guard queryInFlight, collector != nil, pending == nil, !processing else { throw GatewayRecoveryAttemptError.wrongPhase }
        pending = .page(try queries.acceptHistory(reply, now: now))
        queryInFlight = false
    }

    /// Commit restrictions, then call the trusted host's checkpoint and effective-trust refresh operation.
    /// If that operation throws, retry this method: the committed transaction is not repeated.
    /// The callback must be idempotent and must not mutate the journal or reenter this owner.
    /// It is an integration boundary, not an implementation of a rollback witness or admission gate.
    public func processPending(receiptTimeMs: UInt64?, checkpointAndRefresh: (GatewayTrustEvidenceRecovery) throws -> Void) throws {
        try requireActive()
        guard let pending, !processing else { throw GatewayRecoveryAttemptError.wrongPhase }
        processing = true
        defer { processing = false }
        if pendingCheckpoint == nil {
            pendingCheckpoint = try database.write { tx in
                let trust = try tx.approvalTrustSnapshot()
                guard let epoch = try tx.epoch(writer.epoch) else { throw AuditJournalError.unavailableEpoch }
                switch pending {
                case .head(let head):
                    return try tx.recoverGatewayTrust(from: head, expectedTrustRevision: trust.revision,
                        receiptTimeMs: receiptTimeMs, writer: writer, expectedAuditHead: epoch.head)
                case .page(let page):
                    return try tx.recoverGatewayTrust(from: page, expectedTrustRevision: trust.revision,
                        receiptTimeMs: receiptTimeMs, writer: writer, expectedAuditHead: epoch.head)
                }
            }
        }
        guard let checkpoint = pendingCheckpoint else { throw GatewayRecoveryAttemptError.wrongPhase }
        try validateCheckpoint(checkpoint)
        try checkpointAndRefresh(checkpoint)
        try requireActive()
        try validateCheckpoint(checkpoint)
        pendingCheckpoint = nil
        self.pending = nil
        do {
            switch pending {
            case .head(let head):
                if head.evidence.revision <= expectedLocalRevision {
                    result = .head(head)
                } else {
                    collector = try GatewayHistoryCollector(head: head,
                        afterRevision: expectedLocalRevision == 0 ? 0 : expectedLocalRevision - 1,
                        maximumRecords: maximumRecords, maximumBytes: maximumBytes)
                }
            case .page(let page):
                guard let collector else { throw GatewayRecoveryAttemptError.wrongPhase }
                if let history = try collector.accept(page) { result = .history(history) }
            }
        } catch {
            invalidate()
            throw error
        }
        if result != nil { queries.invalidate() }
    }

    /// Stops transport and collection. It never rolls back restrictions already committed to the journal.
    public func invalidate() {
        stopped = true; queries.invalidate(); collector?.invalidate()
        pending = nil; pendingCheckpoint = nil; result = nil; queryInFlight = false
    }

    private func requireActive() throws {
        guard !stopped else { throw GatewayRecoveryAttemptError.stopped }
        guard result == nil else { throw GatewayRecoveryAttemptError.wrongPhase }
    }

    private func validateCheckpoint(_ checkpoint: GatewayTrustEvidenceRecovery) throws {
        let matches = try database.read { tx in
            _ = try tx.gatewayAuthorityHead(registration)
            return try tx.approvalTrustSnapshot().revision == checkpoint.trustRevision &&
                tx.epoch(writer.epoch)?.head == checkpoint.auditHead
        }
        guard matches else { invalidate(); throw GatewayRecoveryAttemptError.localStateChanged }
    }
}
