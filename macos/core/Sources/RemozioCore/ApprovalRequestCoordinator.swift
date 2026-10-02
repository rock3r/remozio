import Foundation
import RemozioProtocol
import Security

public enum ApprovalCoordinatorError: Error, Equatable {
    case invalidConfiguration, invalidDraft, capacityExceeded, unavailable, invalidClock, unknownRequest, notPending, wrongPhone, expired
}

public enum PendingRequestRetirement: Sendable {
    case cancelled, deadlineElapsed, targetTimedOut, targetDisappeared, authorityRestart
}

/// Trusted adapter input after capture validation. The coordinator supplies scope, request ID, and fresh challenge.
public struct ApprovalRequestDraft: Sendable {
    public let contract: RequestContract
    public let requiredFeatures: Set<UInt64>
    public let capture: Data
    public let actions: [CapturedAction]
    public let firstObservedAt: AuthorityMoment
    public let deadlineMilliseconds: UInt64
    public let createdUnixMilliseconds: UInt64
    public let expiresUnixMilliseconds: UInt64
    public init(contract: RequestContract, requiredFeatures: Set<UInt64>, capture: Data, actions: [CapturedAction],
                firstObservedAt: AuthorityMoment, deadlineMilliseconds: UInt64,
                createdUnixMilliseconds: UInt64, expiresUnixMilliseconds: UInt64) {
        self.contract = contract; self.requiredFeatures = requiredFeatures; self.capture = capture; self.actions = actions
        self.firstObservedAt = firstObservedAt; self.deadlineMilliseconds = deadlineMilliseconds
        self.createdUnixMilliseconds = createdUnixMilliseconds; self.expiresUnixMilliseconds = expiresUnixMilliseconds
    }
}

/// Local state observation. It is not a signed status response or an execution permit.
public struct ApprovalRequestState: Equatable, Sendable {
    public let requestID: Data
    public let phase: RequestPhase
    public let revision: UInt64
    public let firstObservedAt: AuthorityMoment
    public let deadlineMilliseconds: UInt64
}

/// The service serializes this non-Sendable owner with all other journal users and adapter observations.
/// Construct only after authority continuity and admission-storage gates pass. This owner never dispatches target actions.
public final class ApprovalRequestCoordinator {
    private let database: JournalDatabase
    private let writer: AuditEpochWriter
    private let mac: Data
    private let account: Data
    private let clockEpoch: UUID
    private let maximumRequests: Int
    private let maximumRetainedBytes: Int
    private let requestLimits: CBORLimits
    private let captureLimits: CBORLimits
    private let decisionLimits: CBORLimits
    private let signingLimits: CBORLimits
    private let auditLimits: CBORLimits
    private var lastTime: UInt64?
    private var stopped = false
    private var retainedBytes = 0
    private struct Entry {
        var state: ApprovalRequestState
        var retained: RetainedApprovalRequest?
        let category: AuditCategory
        var byteCount: Int
    }
    private var entries: [Data: Entry] = [:]

    public init(database: JournalDatabase, writer: AuditEpochWriter, clockEpoch: UUID,
                maximumRequests: Int, maximumRetainedBytes: Int, requestLimits: CBORLimits, captureLimits: CBORLimits,
                decisionLimits: CBORLimits, signingLimits: CBORLimits, auditLimits: CBORLimits) throws {
        guard (1...4096).contains(maximumRequests), (1...67_108_864).contains(maximumRetainedBytes),
              requestLimits.maxBytes <= maximumRetainedBytes else { throw ApprovalCoordinatorError.invalidConfiguration }
        let scope = try database.read { tx -> ApprovalTrustSnapshot in
            let trust = try tx.approvalTrustSnapshot()
            guard let epoch = try tx.epoch(writer.epoch), epoch.descriptor.macID == trust.macID,
                  epoch.descriptor.accountID == trust.accountID else { throw AuditJournalError.unavailableEpoch }
            return trust
        }
        self.database = database; self.writer = writer; self.clockEpoch = clockEpoch
        mac = scope.macID; account = scope.accountID
        self.maximumRequests = maximumRequests; self.maximumRetainedBytes = maximumRetainedBytes
        self.requestLimits = requestLimits; self.captureLimits = captureLimits; self.decisionLimits = decisionLimits
        self.signingLimits = signingLimits; self.auditLimits = auditLimits
    }

    public func admit(_ draft: ApprovalRequestDraft, now: AuthorityMoment, receiptTimeMs: UInt64?) throws -> IssuedRequestPayload {
        try checkClock(now)
        guard draft.firstObservedAt.epoch == clockEpoch, draft.firstObservedAt.milliseconds <= now.milliseconds,
              now.milliseconds < draft.deadlineMilliseconds else { throw ApprovalCoordinatorError.invalidDraft }
        guard entries.count < maximumRequests else { throw ApprovalCoordinatorError.capacityExceeded }
        let payload = try IssuedRequestPayload(contract: draft.contract, macID: mac, accountID: account,
            requestID: random(16), challenge: random(32), requiredFeatures: draft.requiredFeatures,
            createdUnixMilliseconds: draft.createdUnixMilliseconds, expiresUnixMilliseconds: draft.expiresUnixMilliseconds,
            canonicalCapture: draft.capture, permittedActions: draft.actions, bodyLimits: requestLimits, captureLimits: captureLimits)
        _ = try payload.requestDigest(bodyLimits: requestLimits, signingLimits: signingLimits)
        let bytes = try payload.encode(limits: requestLimits).count
        guard bytes <= maximumRetainedBytes - retainedBytes, entries[payload.requestID] == nil else {
            throw ApprovalCoordinatorError.capacityExceeded
        }
        let retained = try RetainedApprovalRequest(payload: payload, phase: .queued, admittedAt: draft.firstObservedAt,
            deadlineMilliseconds: draft.deadlineMilliseconds)
        let category = category(payload.contract.requestKind)
        try database.write { tx in
            let trust = try tx.approvalTrustSnapshot()
            guard trust.allowedContracts.contains(payload.contract), let features = trust.authorityCapabilities.contracts[payload.contract],
                  payload.requiredFeatures.isSubset(of: features) else { throw DecisionVerificationError.unsupportedContract }
            guard try tx.consumption(requestID: payload.requestID) == nil else { throw ApprovalCoordinatorError.invalidDraft }
            try append(tx, requestID: payload.requestID, category: category, kind: .requestCreated, outcome: .pending,
                reason: .none, receiptTimeMs: receiptTimeMs)
        }
        entries[payload.requestID] = Entry(state: ApprovalRequestState(requestID: payload.requestID, phase: .queued,
            revision: 0, firstObservedAt: draft.firstObservedAt, deadlineMilliseconds: draft.deadlineMilliseconds),
            retained: retained, category: category, byteCount: bytes)
        retainedBytes += bytes
        return payload
    }

    public func state(requestID: Data) throws -> ApprovalRequestState {
        try running()
        _ = try database.read { try head($0) }
        guard let entry = entries[requestID] else { throw ApprovalCoordinatorError.unknownRequest }
        return entry.state
    }

    /// A snapshot for signing or delivery. Refresh under the same service serialization before dispatching any transport work.
    public func pendingRequest(requestID: Data, now: AuthorityMoment, receiptTimeMs: UInt64?) throws -> RetainedApprovalRequest {
        try pending(requestID, now: now, receiptTimeMs: receiptTimeMs)
    }

    public func markPresented(requestID: Data, now: AuthorityMoment, receiptTimeMs: UInt64?) throws -> ApprovalRequestState {
        let retained = try pending(requestID, now: now, receiptTimeMs: receiptTimeMs)
        if retained.phase == .presented { return try state(requestID: requestID) }
        return try replace(requestID, phase: RequestLifecycle.transition(from: retained.phase, event: .present))
    }

    /// A Mac-observed pending lifecycle change. A phone decline must use its signed decision instead.
    public func retirePending(requestID: Data, reason: PendingRequestRetirement, now: AuthorityMoment,
                              receiptTimeMs: UInt64?) throws -> ApprovalRequestState {
        try checkClock(now)
        guard let entry = entries[requestID], let retained = entry.retained,
              retained.phase == .queued || retained.phase == .presented else { throw ApprovalCoordinatorError.notPending }
        let event: RequestEvent, auditReason: AuditReason
        switch reason {
        case .cancelled: event = .cancel; auditReason = .userCancelled
        case .deadlineElapsed:
            guard now.milliseconds >= retained.deadlineMilliseconds else { throw ApprovalCoordinatorError.invalidDraft }
            event = .expire; auditReason = .authorizationExpired
        case .targetTimedOut: event = .expire; auditReason = .targetTimedOut
        case .targetDisappeared: event = .loseTarget; auditReason = .targetDisappeared
        case .authorityRestart: event = .restartAuthority; auditReason = .authorityRestarted
        }
        let phase = try RequestLifecycle.transition(from: retained.phase, event: event)
        let kind: AuditEventKind = phase == .expired ? .expired : phase == .unknown ? .unknownOutcome : .cancelled
        let outcome: AuditOutcome = phase == .expired ? .expired : phase == .unknown ? .unresolved : .noDispatch
        try database.write { try append($0, requestID: requestID, category: entry.category, kind: kind,
            outcome: outcome, reason: auditReason, receiptTimeMs: receiptTimeMs) }
        return try replace(requestID, phase: phase)
    }

    /// The authenticated channel supplies phone and epoch. Incoming decision bytes never supply trusted enrollment or retained state.
    public func consume(canonicalDecision: Data, signature: Data, authenticatedPhoneID: Data, authenticatedEnrollmentEpoch: Data,
                        now: AuthorityMoment, receiptTimeMs: UInt64?) throws -> ConsumptionReceipt {
        try checkClock(now)
        let decision = try DecisionPayload.decode(canonicalDecision, limits: decisionLimits)
        guard decision.phoneID == authenticatedPhoneID else { throw ApprovalCoordinatorError.wrongPhone }
        let retained = try pending(decision.requestID, now: now, receiptTimeMs: receiptTimeMs)
        let receipt = try database.write { tx in
            let trust = try tx.requestDeliveryTrust()
            guard trust.enrollments.contains(where: {
                $0.approval.phoneID == authenticatedPhoneID && $0.epoch == authenticatedEnrollmentEpoch && $0.approval.active
            }) else { throw EnrollmentJournalError.unavailableEnrollment }
            return try tx.consume(canonicalDecision: canonicalDecision, signature: signature, retained: retained,
                expectedTrustRevision: trust.approval.revision, now: now, eventID: random(16), receiptTimeMs: receiptTimeMs,
                writer: writer, expectedHead: head(tx), requestLimits: requestLimits, signingLimits: signingLimits)
        }
        _ = try replace(decision.requestID, phase: receipt.event.outcome == .noDispatch ? .declined : .authorized)
        return receipt
    }

    /// Original binding for the root executor's separate checkpoint and target checks. This snapshot grants no dispatch permission.
    public func consumedRequest(requestID: Data, now: AuthorityMoment) throws -> RetainedApprovalRequest {
        try checkClock(now)
        _ = try database.read { try head($0) }
        guard let entry = entries[requestID], let retained = entry.retained,
              retained.phase == .authorized || retained.phase == .executing else { throw ApprovalCoordinatorError.notPending }
        return retained
    }

    /// Retained winner and result for Already handled responses. It cannot recreate a live request after restart.
    public func historicalOutcome(requestID: Data) throws -> ConsumptionOutcome? {
        try running()
        return try database.read { try $0.consumptionOutcome(requestID: requestID) }
    }

    /// Only controller-verified outcomes belong here. This records an observation and grants no permission to execute.
    public func recordOutcome(requestID: Data, expectedRevision: UInt64, event: RequestEvent,
                              now: AuthorityMoment, receiptTimeMs: UInt64?) throws -> ConsumptionOutcome {
        try checkClock(now)
        guard let entry = entries[requestID], entry.state.phase == .authorized || entry.state.phase == .executing else {
            throw ApprovalCoordinatorError.notPending
        }
        let outcome = try database.write { tx in
            try tx.transitionConsumption(requestID: requestID, expectedRevision: expectedRevision, event: event,
                eventID: random(16), receiptTimeMs: receiptTimeMs, writer: writer, expectedHead: head(tx))
        }
        _ = try replace(requestID, phase: outcome.phase)
        return outcome
    }

    /// Terminal metadata remains in the journal. Forgetting it never admits an old request or clears durable consumption.
    public func forgetTerminal(requestID: Data) throws {
        try running()
        guard let entry = entries[requestID], entry.state.phase.isTerminal else { throw ApprovalCoordinatorError.notPending }
        entries.removeValue(forKey: requestID)
    }

    private func pending(_ id: Data, now: AuthorityMoment, receiptTimeMs: UInt64?) throws -> RetainedApprovalRequest {
        try checkClock(now)
        guard let entry = entries[id], let retained = entry.retained,
              retained.phase == .queued || retained.phase == .presented else { throw ApprovalCoordinatorError.notPending }
        _ = try database.read { try head($0) }
        if now.milliseconds >= retained.deadlineMilliseconds {
            _ = try retirePending(requestID: id, reason: .deadlineElapsed, now: now, receiptTimeMs: receiptTimeMs)
            throw ApprovalCoordinatorError.expired
        }
        return retained
    }

    private func replace(_ id: Data, phase: RequestPhase) throws -> ApprovalRequestState {
        guard var entry = entries[id] else { throw ApprovalCoordinatorError.unknownRequest }
        entry.state = ApprovalRequestState(requestID: id, phase: phase, revision: entry.state.revision + 1,
            firstObservedAt: entry.state.firstObservedAt, deadlineMilliseconds: entry.state.deadlineMilliseconds)
        if !phase.isTerminal {
            guard let old = entry.retained else { throw ApprovalCoordinatorError.notPending }
            entry.retained = try .init(payload: old.payload, phase: phase, admittedAt: old.admittedAt, deadlineMilliseconds: old.deadlineMilliseconds)
        } else {
            entry.retained = nil
            retainedBytes -= entry.byteCount
            entry.byteCount = 0
        }
        entries[id] = entry
        return entry.state
    }

    private func append(_ tx: JournalTransaction, requestID: Data, category: AuditCategory, kind: AuditEventKind,
                        outcome: AuditOutcome, reason: AuditReason, receiptTimeMs: UInt64?) throws {
        let current = try head(tx)
        guard current < UInt64.max else { throw AuditJournalError.headMismatch }
        let event = try AuditEventMetadata(eventID: random(16), macID: mac, accountID: account, journalEpoch: writer.epoch,
            sequence: current + 1, requestID: requestID, eventTimeMs: nil, authorityReceiptTimeMs: receiptTimeMs,
            kind: kind, category: category, action: nil, decisionPhoneID: nil, authentication: .system, outcome: outcome,
            reason: reason, droppedEventCount: nil, peerDeviceID: nil)
        try tx.append(event.encode(limits: auditLimits), writer: writer, expectedHead: current)
    }
    private func head(_ tx: JournalTransaction) throws -> UInt64 {
        guard let epoch = try tx.epoch(writer.epoch) else { throw AuditJournalError.unavailableEpoch }
        return epoch.head
    }
    private func running() throws { if stopped { throw ApprovalCoordinatorError.unavailable } }
    private func checkClock(_ now: AuthorityMoment) throws {
        try running()
        guard now.epoch == clockEpoch, lastTime == nil || now.milliseconds >= lastTime! else {
            stopped = true; entries.removeAll(); retainedBytes = 0
            throw ApprovalCoordinatorError.invalidClock
        }
        lastTime = now.milliseconds
    }
    private func random(_ count: Int) throws -> Data {
        var value = Data(count: count)
        guard value.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }) == errSecSuccess else {
            throw ApprovalCoordinatorError.unavailable
        }
        return value
    }
    private func category(_ kind: RequestKind) -> AuditCategory {
        switch kind {
        case .command: .command
        case .onePasswordAccess: .onePasswordAccess
        case .onePasswordUnlock: .onePasswordUnlock
        case .littleSnitch: .littleSnitch
        }
    }
}
