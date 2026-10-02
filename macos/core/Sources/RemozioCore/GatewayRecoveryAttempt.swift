import Foundation

public enum GatewayRecoveryAttemptError: Error, Equatable {
    case invalidConfiguration, wrongPhase, localStateChanged, invalidClock, stopped
}

/// Historical results only. Neither case grants authority or permits publishing a mapping.
public enum GatewayRecoveryCollection: Sendable {
    case head(VerifiedGatewayHead)
    case history(VerifiedGatewayHistory)
}

public enum GatewayRecoveryDisposition: Sendable, Equatable {
    case acknowledged, reconciled, localHeadChanged, missingLocalHistory, conflictingLocalHistory, requiresTrustRecovery
}

/// Local reconciliation state. Even successful delivery recovery does not restore approval authority.
public struct GatewayRecoveryResolution: Sendable {
    public let disposition: GatewayRecoveryDisposition
    public let trustRevision: UUID
    public let auditHead: UInt64
    public let localRevision: UInt64
    public let reportedRevision: UInt64
    public let acknowledgment: GatewayAcknowledgment?
    public let restrictedPhoneIDs: Set<Data>
}

/// One serialized root-side attempt, constructed after independent authority continuity checks.
/// The host must invalidate it when registration activity or either key pin changes.
public final class GatewayRecoveryAttempt {
    public let expectedLocalRevision: UInt64
    public private(set) var result: GatewayRecoveryCollection?
    /// A committed restriction awaiting the host's independent checkpoint and delivery refresh.
    public private(set) var pendingCheckpoint: GatewayTrustEvidenceRecovery?
    /// Present only while committed reconciliation awaits the host checkpoint and delivery refresh.
    public private(set) var pendingReconciliationCheckpoint: GatewayRecoveryResolution?
    /// A successful disposition appears here only after checkpoint and refresh complete.
    public private(set) var reconciliationResult: GatewayRecoveryResolution?
    private var reconciliationMoment: AuthorityMoment?
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

    /// Reconcile completed evidence against current local state, then checkpoint before reporting success.
    /// The trusted host supplies registration activity and an idempotent checkpoint and refresh operation.
    /// The callback must not mutate the journal or reenter this owner.
    /// Neither the callback nor a successful result may publish old controls or reopen approval authority.
    @discardableResult
    public func reconcile(registrationActive: Bool, now: AuthorityMoment,
                          checkpointAndRefresh: (GatewayRecoveryResolution) throws -> Void) throws -> GatewayRecoveryResolution {
        guard !stopped else { throw GatewayRecoveryAttemptError.stopped }
        guard let result, !processing, reconciliationResult == nil else { throw GatewayRecoveryAttemptError.wrongPhase }
        guard registrationActive else { invalidate(); throw GatewayAuthorityError.unavailableRegistration }
        let head: VerifiedGatewayHead
        switch result { case .head(let value): head = value; case .history(let value): head = value.head }
        let received: AuthorityMoment
        switch result { case .head(let value): received = value.receivedAt; case .history(let value): received = value.receivedAt }
        let previous = reconciliationMoment ?? received
        guard now.epoch == previous.epoch, now.milliseconds >= previous.milliseconds else {
            invalidate(); throw GatewayRecoveryAttemptError.invalidClock
        }
        reconciliationMoment = now
        processing = true
        defer { processing = false }
        if pendingReconciliationCheckpoint == nil {
            let resolution = try database.write { tx in
                let trust = try tx.approvalTrustSnapshot()
                let local = try tx.gatewayAuthorityHead(registration)
                let disposition: GatewayRecoveryDisposition
                if local != expectedLocalRevision {
                    disposition = .localHeadChanged
                } else {
                    switch result {
                    case .head(let verified):
                        switch try tx.acknowledgeGatewayHead(verified).disposition {
                        case .recorded, .alreadyRecorded, .olderThanRecorded: disposition = .acknowledged
                        case .missingLocalHistory: disposition = .missingLocalHistory
                        case .conflictingLocalHistory: disposition = .conflictingLocalHistory
                        }
                    case .history(let history):
                        switch try tx.reconcileGatewayDeliveryHistory(history, registrationActive: registrationActive,
                            expectedTrustRevision: trust.revision, expectedLocalRevision: expectedLocalRevision, now: now).disposition {
                        case .reconciled: disposition = .reconciled
                        case .localHeadChanged: disposition = .localHeadChanged
                        case .requiresTrustRecovery: disposition = .requiresTrustRecovery
                        case .conflictingLocalHistory: disposition = .conflictingLocalHistory
                        }
                    }
                }
                guard let epoch = try tx.epoch(writer.epoch) else { throw AuditJournalError.unavailableEpoch }
                return GatewayRecoveryResolution(disposition: disposition, trustRevision: trust.revision, auditHead: epoch.head,
                    localRevision: try tx.gatewayAuthorityHead(registration), reportedRevision: head.evidence.revision,
                    acknowledgment: try tx.gatewayAcknowledgment(registration), restrictedPhoneIDs: try tx.approvalTrustRestrictions())
            }
            guard resolution.disposition == .acknowledged || resolution.disposition == .reconciled else {
                reconciliationResult = resolution
                return resolution
            }
            pendingReconciliationCheckpoint = resolution
        }
        guard let checkpoint = pendingReconciliationCheckpoint else { throw GatewayRecoveryAttemptError.wrongPhase }
        try validateReconciliationCheckpoint(checkpoint)
        try checkpointAndRefresh(checkpoint)
        guard !stopped else { throw GatewayRecoveryAttemptError.stopped }
        try validateReconciliationCheckpoint(checkpoint)
        pendingReconciliationCheckpoint = nil
        reconciliationResult = checkpoint
        return checkpoint
    }

    private func validateReconciliationCheckpoint(_ checkpoint: GatewayRecoveryResolution) throws {
        let matches = try database.read { tx in
            try tx.gatewayAuthorityHead(registration) == checkpoint.localRevision &&
                tx.approvalTrustSnapshot().revision == checkpoint.trustRevision &&
                tx.epoch(writer.epoch)?.head == checkpoint.auditHead &&
                tx.gatewayAcknowledgment(registration) == checkpoint.acknowledgment
        }
        guard matches else { invalidate(); throw GatewayRecoveryAttemptError.localStateChanged }
    }

    /// Stops transport and collection. It never rolls back restrictions already committed to the journal.
    public func invalidate() {
        stopped = true; queries.invalidate(); collector?.invalidate()
        pending = nil; pendingCheckpoint = nil; result = nil; queryInFlight = false
        pendingReconciliationCheckpoint = nil; reconciliationResult = nil
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
