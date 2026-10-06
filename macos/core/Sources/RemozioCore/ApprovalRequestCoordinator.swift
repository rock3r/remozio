import CryptoKit
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
    public let macID: Data
    public let accountID: Data
    public let requestDigest: Data
    public let challenge: Data
    public let reason: RequestStatusReason
    public let terminalAt: AuthorityMoment?
    public let decisionPhoneID: Data?
    public let requestID: Data
    public let phase: RequestPhase
    public let revision: UInt64
    public let firstObservedAt: AuthorityMoment
    public let deadlineMilliseconds: UInt64

    /// V1 status projection. The host supplies a fresh observation revision and authenticates the response separately.
    public func statusPayload(observationID: Data, observationRevision: UInt64, now: AuthorityMoment,
                              estimatedLifetimeMs: UInt64?, lateObservation: Bool) throws -> RequestStatusPayload {
        guard now.epoch == firstObservedAt.epoch, now.milliseconds >= firstObservedAt.milliseconds,
              terminalAt == nil || (terminalAt!.epoch == now.epoch && terminalAt!.milliseconds <= now.milliseconds) else {
            throw ApprovalCoordinatorError.invalidClock
        }
        let pending = phase == .queued || phase == .presented
        let wirePhase: RequestPhase = phase == .unknown && reason == .targetDisappeared ? .cancelled : phase
        return try RequestStatusPayload(macID: macID, accountID: accountID, requestID: requestID,
            requestDigest: requestDigest, challenge: challenge, revision: observationRevision, phase: wirePhase, reason: reason,
            observationID: observationID, observedAgeMs: now.milliseconds - firstObservedAt.milliseconds,
            authorizationRemainingMs: pending ? (now.milliseconds < deadlineMilliseconds ? deadlineMilliseconds - now.milliseconds : 0) : nil,
            estimatedLifetimeMs: estimatedLifetimeMs, lateObservation: lateObservation,
            terminalAgeMs: terminalAt.map { $0.milliseconds - firstObservedAt.milliseconds }, decisionPhoneID: decisionPhoneID)
    }
}

/// The service serializes this non-Sendable owner with all other journal users and adapter observations.
/// Construct only after authority continuity and admission-storage gates pass. This owner never dispatches target actions.
public final class ApprovalRequestCoordinator {
    let database: JournalDatabase
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
    private var checkpointed: CheckpointedJournal?
    private var retainedBytes = 0
    private var deliveryBytes = 0
    private struct Entry {
        var state: ApprovalRequestState
        var retained: RetainedApprovalRequest?
        let category: AuditCategory
        var byteCount: Int
        var delivery: PendingRequestDelivery?
        var frame: Data?
        var frameKey: Data?
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

    /// The host retains both store leases and completes startup recovery before supplying the writer.
    convenience init(database: JournalDatabase, continuity: ContinuityStore, writer: AuditEpochWriter, clockEpoch: UUID,
                     maximumRequests: Int, maximumRetainedBytes: Int, requestLimits: CBORLimits, captureLimits: CBORLimits,
                     decisionLimits: CBORLimits, signingLimits: CBORLimits, auditLimits: CBORLimits) throws {
        try self.init(database: database, writer: writer, clockEpoch: clockEpoch, maximumRequests: maximumRequests,
            maximumRetainedBytes: maximumRetainedBytes, requestLimits: requestLimits, captureLimits: captureLimits,
            decisionLimits: decisionLimits, signingLimits: signingLimits, auditLimits: auditLimits)
        let commits = CheckpointedJournal(journal: database, continuity: continuity)
        try commits.read { _ in () }
        checkpointed = commits
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
        let digest = try payload.requestDigest(bodyLimits: requestLimits, signingLimits: signingLimits)
        let bytes = try payload.encode(limits: requestLimits).count
        guard bytes <= maximumRetainedBytes - retainedBytes, entries[payload.requestID] == nil else {
            throw ApprovalCoordinatorError.capacityExceeded
        }
        let retained = try RetainedApprovalRequest(payload: payload, phase: .queued, admittedAt: draft.firstObservedAt,
            deadlineMilliseconds: draft.deadlineMilliseconds)
        let category = category(payload.contract.requestKind)
        try write { tx in
            let trust = try tx.approvalTrustSnapshot()
            guard trust.allowedContracts.contains(payload.contract), let features = trust.authorityCapabilities.contracts[payload.contract],
                  payload.requiredFeatures.isSubset(of: features) else { throw DecisionVerificationError.unsupportedContract }
            guard try tx.consumption(requestID: payload.requestID) == nil else { throw ApprovalCoordinatorError.invalidDraft }
            try append(tx, requestID: payload.requestID, category: category, kind: .requestCreated, outcome: .pending,
                reason: .none, receiptTimeMs: receiptTimeMs)
        }
        entries[payload.requestID] = Entry(state: ApprovalRequestState(macID: mac, accountID: account, requestDigest: digest, challenge: payload.challenge,
            reason: .none, terminalAt: nil, decisionPhoneID: nil, requestID: payload.requestID, phase: .queued,
            revision: 1, firstObservedAt: draft.firstObservedAt, deadlineMilliseconds: draft.deadlineMilliseconds),
            retained: retained, category: category, byteCount: bytes)
        retainedBytes += bytes
        return payload
    }

    public func state(requestID: Data) throws -> ApprovalRequestState {
        try running()
        _ = try read { try head($0) }
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
        return try replace(requestID, phase: RequestLifecycle.transition(from: retained.phase, event: .present), reason: .none, now: now)
    }

    /// Expires elapsed pending requests without phone traffic. Audit commits before any live state changes.
    public func expirePending(now: AuthorityMoment, receiptTimeMs: UInt64?) throws -> [ApprovalRequestState] {
        try checkClock(now)
        let expired = entries.keys.filter { id in
            guard let retained = entries[id]?.retained else { return false }
            return (retained.phase == .queued || retained.phase == .presented) && now.milliseconds >= retained.deadlineMilliseconds
        }.sorted { $0.lexicographicallyPrecedes($1) }
        try write { tx in
            _ = try head(tx)
            for id in expired {
                guard let entry = entries[id] else { throw ApprovalCoordinatorError.unknownRequest }
                try append(tx, requestID: id, category: entry.category, kind: .expired, outcome: .expired,
                    reason: .authorizationExpired, receiptTimeMs: receiptTimeMs)
            }
        }
        return try expired.map { try replace($0, phase: .expired, reason: .authorizationExpired, now: now) }
    }

    /// A Mac-observed pending lifecycle change. A phone decline must use its signed decision instead.
    public func retirePending(requestID: Data, reason: PendingRequestRetirement, now: AuthorityMoment,
                              receiptTimeMs: UInt64?) throws -> ApprovalRequestState {
        try checkClock(now)
        guard let entry = entries[requestID], let retained = entry.retained,
              retained.phase == .queued || retained.phase == .presented else { throw ApprovalCoordinatorError.notPending }
        let event: RequestEvent, auditReason: AuditReason, statusReason: RequestStatusReason
        switch reason {
        case .cancelled: event = .cancel; auditReason = .userCancelled; statusReason = .userCancelled
        case .deadlineElapsed:
            guard now.milliseconds >= retained.deadlineMilliseconds else { throw ApprovalCoordinatorError.invalidDraft }
            event = .expire; auditReason = .authorizationExpired; statusReason = .authorizationExpired
        case .targetTimedOut: event = .expire; auditReason = .targetTimedOut; statusReason = .targetTimedOut
        case .targetDisappeared: event = .loseTarget; auditReason = .targetDisappeared; statusReason = .targetDisappeared
        case .authorityRestart: event = .restartAuthority; auditReason = .authorityRestarted; statusReason = .authorityRestarted
        }
        let phase = try RequestLifecycle.transition(from: retained.phase, event: event)
        let kind: AuditEventKind = phase == .expired ? .expired : phase == .unknown ? .unknownOutcome : .cancelled
        let outcome: AuditOutcome = phase == .expired ? .expired : phase == .unknown ? .unresolved : .noDispatch
        try write { try append($0, requestID: requestID, category: entry.category, kind: kind,
            outcome: outcome, reason: auditReason, receiptTimeMs: receiptTimeMs) }
        return try replace(requestID, phase: phase, reason: statusReason, now: now)
    }

    /// The authenticated channel supplies phone and epoch. Incoming decision bytes never supply trusted enrollment or retained state.
    public func consume(canonicalDecision: Data, signature: Data, authenticatedPhoneID: Data, authenticatedEnrollmentEpoch: Data,
                        now: AuthorityMoment, receiptTimeMs: UInt64?) throws -> ConsumptionReceipt {
        try checkClock(now)
        let decision = try DecisionPayload.decode(canonicalDecision, limits: decisionLimits)
        guard decision.phoneID == authenticatedPhoneID else { throw ApprovalCoordinatorError.wrongPhone }
        let retained = try pending(decision.requestID, now: now, receiptTimeMs: receiptTimeMs)
        let receipt = try write { tx in
            let trust = try tx.requestDeliveryTrust()
            guard trust.enrollments.contains(where: {
                $0.approval.phoneID == authenticatedPhoneID && $0.epoch == authenticatedEnrollmentEpoch && $0.approval.active
            }) else { throw EnrollmentJournalError.unavailableEnrollment }
            return try tx.consume(canonicalDecision: canonicalDecision, signature: signature, retained: retained,
                expectedTrustRevision: trust.approval.revision, now: now, eventID: random(16), receiptTimeMs: receiptTimeMs,
                writer: writer, expectedHead: head(tx), requestLimits: requestLimits, signingLimits: signingLimits)
        }
        _ = try replace(decision.requestID, phase: receipt.event.outcome == .noDispatch ? .declined : .authorized,
            reason: receipt.event.outcome == .noDispatch ? .declined : .none, now: now, decisionPhoneID: receipt.decision.phoneID)
        return receipt
    }

    /// Reconcile queue ownership from current owner state, including terminal states whose capture was released.
    public func reconcileDelivery(requestID: Data, delivery: PendingRequestDelivery, routing: PresenceRouting,
                                  now: AuthorityMoment, receiptTimeMs: UInt64?,
                                  enqueue: (PhoneRequestDelivery) -> Bool) throws -> RequestDeliveryUpdate {
        let current = try deliveryState(requestID: requestID, now: now, receiptTimeMs: receiptTimeMs)
        guard current.phase == .queued || current.phase == .presented else {
            return delivery.close(current: current, routing: routing, now: now)
        }
        guard let retained = entries[requestID]?.retained else { throw ApprovalCoordinatorError.notPending }
        let trust = try read { try $0.requestDeliveryTrust() }
        return delivery.reconcile(current: retained, routing: routing, trust: trust, now: now, enqueue: enqueue)
    }

    /// Recheck current request and journal trust immediately before the first transport handoff.
    /// Prepare asynchronous resources first. The callback must not await, reenter, or mutate authority state.
    /// Return false only if no bytes or work were accepted. Always apply the returned withdrawals, even without a delivery.
    public func handoffDelivery(requestID: Data, delivery: PendingRequestDelivery, deliveryID: UUID,
                                routing: PresenceRouting, now: AuthorityMoment, receiptTimeMs: UInt64?,
                                accept: (PhoneRequestDelivery) -> Bool) throws -> RequestDeliveryDispatch {
        let current = try deliveryState(requestID: requestID, now: now, receiptTimeMs: receiptTimeMs)
        guard current.phase == .queued || current.phase == .presented else {
            return RequestDeliveryDispatch(delivery: nil, update: delivery.close(current: current, routing: routing, now: now))
        }
        guard let retained = entries[requestID]?.retained else { throw ApprovalCoordinatorError.notPending }
        let trust = try read { try $0.requestDeliveryTrust() }
        return delivery.handoff(id: deliveryID, current: retained, routing: routing, trust: trust, now: now, accept: accept)
    }

    /// Builds the signed frame from retained authority state, never from caller-supplied request bytes.
    /// Production supplies its non-exportable authority signer and public key from current local trust.
    /// Keep this call serialized with authority changes. Callbacks must not reenter or mutate this owner.
    /// Sample the clock and presence again after signing; transport acceptance has the same contract as handoffDelivery.
    public func handoffSignedDelivery(requestID: Data, delivery: PendingRequestDelivery, deliveryID: UUID,
                                      authorityPublicKey: Data, maximumBodyBytes: Int,
                                      now: () throws -> AuthorityMoment, routing: () throws -> PresenceRouting,
                                      receiptTimeMs: UInt64?, signer: (Data) throws -> Data,
                                      accept: (PhoneRequestDelivery, Data) -> Bool) throws -> RequestDeliveryDispatch {
        let initialTime = try now()
        let current = try deliveryState(requestID: requestID, now: initialTime, receiptTimeMs: receiptTimeMs)
        guard current.phase == .queued || current.phase == .presented else {
            return RequestDeliveryDispatch(delivery: nil, update: delivery.close(current: current, routing: try routing(), now: initialTime))
        }
        guard let retained = entries[requestID]?.retained else { throw ApprovalCoordinatorError.notPending }
        guard authorityPublicKey.count == 65, authorityPublicKey.first == 4,
              (try? P256.Signing.PublicKey(x963Representation: authorityPublicKey)) != nil else {
            throw DecisionVerificationError.invalidTrustedState
        }
        let body = try retained.payload.encode(limits: requestLimits)
        guard (1...(16_777_216 - ApprovalMessage.overheadBytes)).contains(maximumBodyBytes),
              body.count <= maximumBodyBytes else { throw ApprovalCoordinatorError.capacityExceeded }
        let input = try SigningInput.make(wireVersion: retained.payload.contract.wireVersion,
            messageType: .request, purpose: .issuedRequest, canonicalPayload: body,
            payloadLimits: requestLimits, inputLimits: signingLimits)
        let signature = try signer(input)
        guard try ApprovalSignature.verify(signature: signature, publicKey: authorityPublicKey,
            wireVersion: retained.payload.contract.wireVersion, messageType: .request, purpose: .issuedRequest,
            canonicalPayload: body, payloadLimits: requestLimits, inputLimits: signingLimits) else {
            throw DecisionVerificationError.invalidSignature
        }
        let frame = try ApprovalMessage(wireVersion: retained.payload.contract.wireVersion,
            type: .request, purpose: .issuedRequest, body: body, signature: signature).encode(maximumBodyBytes: maximumBodyBytes)
        let finalRouting = try routing()
        return try handoffDelivery(requestID: requestID, delivery: delivery, deliveryID: deliveryID,
            routing: finalRouting, now: now(), receiptTimeMs: receiptTimeMs) { accept($0, frame) }
    }

    /// Bounded discovery hints for one current enrollment, never approval or delivery acknowledgments.
    /// The host serializes this call with authority changes. Fetch each frame through retainedDeliveryFrame.
    public func pendingDeliveryRequestIDs(binding: AuthorityPeerBinding, routing: PresenceRouting,
                                          now: AuthorityMoment, receiptTimeMs: UInt64?) throws -> [Data] {
        try checkClock(now)
        let trust = try read { transaction in
            try transaction.requireDirectApprovalBinding(binding)
            return try transaction.requestDeliveryTrust()
        }
        if entries.values.contains(where: {
            ($0.state.phase == .queued || $0.state.phase == .presented) && now.milliseconds >= $0.state.deadlineMilliseconds
        }) {
            _ = try expirePending(now: now, receiptTimeMs: receiptTimeMs)
        }
        var result: [Data] = []
        for id in entries.keys.sorted(by: { $0.lexicographicallyPrecedes($1) }) {
            guard let retained = entries[id]?.retained,
                  retained.phase == .queued || retained.phase == .presented else { continue }
            let delivery = try deliveryController(requestID: id, retained: retained)
            let recipients = delivery.discover(current: retained, routing: routing, trust: trust, now: now)
            if recipients.contains(where: {
                $0.recipient.phoneID == binding.scope.phoneID && $0.recipient.enrollmentEpoch == binding.scope.enrollmentEpoch
            }) { result.append(id) }
        }
        return result
    }

    private func deliveryController(requestID: Data, retained: RetainedApprovalRequest) throws -> PendingRequestDelivery {
        if let existing = entries[requestID]?.delivery { return existing }
        let delivery = try PendingRequestDelivery(request: retained)
        entries[requestID]?.delivery = delivery
        return delivery
    }

    /// Root-owned retry storage for the request-frame provider. Serialize with all authority state.
    /// A returned frame is a possible handoff, not phone receipt or consent. Never persist this cache.
    /// Callbacks must be synchronous and must not reenter or mutate authority state.
    public func retainedDeliveryFrame(binding: AuthorityPeerBinding, requestID: Data, authorityPublicKey: Data,
                                      maximumBodyBytes: Int, now: () throws -> AuthorityMoment,
                                      routing: () throws -> PresenceRouting, receiptTimeMs: UInt64?,
                                      signer: (Data) throws -> Data) throws -> Data? {
        guard (1...(16_777_216 - ApprovalMessage.overheadBytes)).contains(maximumBodyBytes) else {
            throw ApprovalCoordinatorError.invalidConfiguration
        }
        try read { try $0.requireDirectApprovalBinding(binding) }
        let time = try now()
        let state: ApprovalRequestState
        do { state = try deliveryState(requestID: requestID, now: time, receiptTimeMs: receiptTimeMs) }
        catch ApprovalCoordinatorError.unknownRequest { return nil }
        guard state.phase == .queued || state.phase == .presented else { return nil }
        guard let entry = entries[requestID], let retained = entry.retained else { throw ApprovalCoordinatorError.notPending }
        let delivery = try deliveryController(requestID: requestID, retained: retained)
        let currentRouting = try routing()
        let update = try reconcileDelivery(requestID: requestID, delivery: delivery, routing: currentRouting, now: now(),
            receiptTimeMs: receiptTimeMs) { _ in true }
        guard let queued = update.active.first(where: {
            $0.recipient.phoneID == binding.scope.phoneID && $0.recipient.enrollmentEpoch == binding.scope.enrollmentEpoch
        }) else { return nil }
        let cached = entries[requestID]?.frame
        if cached != nil && entries[requestID]?.frameKey != authorityPublicKey { throw DecisionVerificationError.invalidTrustedState }
        if update.dispatched.contains(where: { $0.id == queued.id }) {
            guard let cached else { throw ApprovalCoordinatorError.unavailable }
            guard cached.count <= maximumBodyBytes + ApprovalMessage.overheadBytes else { throw ApprovalCoordinatorError.capacityExceeded }
            return cached
        }
        let cachedSignature = try cached.map {
            try ApprovalMessage.decode($0, maximumBodyBytes: maximumBodyBytes).signature
        }
        var result: Data?
        _ = try handoffSignedDelivery(requestID: requestID, delivery: delivery, deliveryID: queued.id,
            authorityPublicKey: authorityPublicKey, maximumBodyBytes: maximumBodyBytes, now: now, routing: routing,
            receiptTimeMs: receiptTimeMs, signer: { try cachedSignature ?? signer($0) }) { _, frame in
                let previous = entries[requestID]?.frame?.count ?? 0
                let maximum = maximumRetainedBytes + maximumRequests * ApprovalMessage.overheadBytes
                guard frame.count <= maximum - deliveryBytes + previous else { return false }
                entries[requestID]?.frame = frame
                entries[requestID]?.frameKey = authorityPublicKey
                deliveryBytes += frame.count - previous
                result = frame
                return true
            }
        return result
    }

    private func deliveryState(requestID: Data, now: AuthorityMoment, receiptTimeMs: UInt64?) throws -> ApprovalRequestState {
        try checkClock(now)
        var current = try state(requestID: requestID)
        if (current.phase == .queued || current.phase == .presented) && now.milliseconds >= current.deadlineMilliseconds {
            current = try retirePending(requestID: requestID, reason: .deadlineElapsed, now: now, receiptTimeMs: receiptTimeMs)
        }
        return current
    }

    /// Original binding for the root executor's separate checkpoint and target checks. This snapshot grants no dispatch permission.
    public func consumedRequest(requestID: Data, now: AuthorityMoment) throws -> RetainedApprovalRequest {
        try checkClock(now)
        _ = try read { try head($0) }
        guard let entry = entries[requestID], let retained = entry.retained,
              retained.phase == .authorized || retained.phase == .executing else { throw ApprovalCoordinatorError.notPending }
        return retained
    }

    /// Retained winner and result for Already handled responses. It cannot recreate a live request after restart.
    public func historicalOutcome(requestID: Data) throws -> ConsumptionOutcome? {
        try running()
        return try read { try $0.consumptionOutcome(requestID: requestID) }
    }

    /// Only controller-verified outcomes belong here. This records an observation and grants no permission to execute.
    public func recordOutcome(requestID: Data, expectedRevision: UInt64, event: RequestEvent,
                              now: AuthorityMoment, receiptTimeMs: UInt64?) throws -> ConsumptionOutcome {
        try checkClock(now)
        guard let entry = entries[requestID], entry.state.phase == .authorized || entry.state.phase == .executing else {
            throw ApprovalCoordinatorError.notPending
        }
        let outcome = try write { tx in
            try tx.transitionConsumption(requestID: requestID, expectedRevision: expectedRevision, event: event,
                eventID: random(16), receiptTimeMs: receiptTimeMs, writer: writer, expectedHead: head(tx))
        }
        let reason: RequestStatusReason
        switch outcome.phase {
        case .executing: reason = .none
        case .succeeded, .failed: reason = .verifiedResult
        case .unknown: reason = outcome.event.reason == .authorityRestarted ? .authorityRestarted : .outcomeUnavailable
        case .cancelled: reason = .noDispatchProved
        default: throw ConsumptionOutcomeError.corruptData
        }
        _ = try replace(requestID, phase: outcome.phase, reason: reason, now: now)
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
        _ = try read { try head($0) }
        if now.milliseconds >= retained.deadlineMilliseconds {
            _ = try retirePending(requestID: id, reason: .deadlineElapsed, now: now, receiptTimeMs: receiptTimeMs)
            throw ApprovalCoordinatorError.expired
        }
        return retained
    }

    private func replace(_ id: Data, phase: RequestPhase, reason: RequestStatusReason, now: AuthorityMoment,
                         decisionPhoneID: Data? = nil) throws -> ApprovalRequestState {
        guard var entry = entries[id] else { throw ApprovalCoordinatorError.unknownRequest }
        entry.state = ApprovalRequestState(macID: entry.state.macID, accountID: entry.state.accountID,
            requestDigest: entry.state.requestDigest, challenge: entry.state.challenge, reason: reason,
            terminalAt: phase.isTerminal ? now : nil, decisionPhoneID: decisionPhoneID ?? entry.state.decisionPhoneID,
            requestID: id, phase: phase, revision: entry.state.revision + 1,
            firstObservedAt: entry.state.firstObservedAt, deadlineMilliseconds: entry.state.deadlineMilliseconds)
        if phase != .queued && phase != .presented {
            deliveryBytes -= entry.frame?.count ?? 0
            entry.frame = nil; entry.frameKey = nil; entry.delivery = nil
        }
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
    private func read<Value>(_ body: (JournalTransaction) throws -> Value) throws -> Value {
        try running()
        if let checkpointed { return try checkpointed.read(body) }
        return try database.read(body)
    }

    private func write<Value>(_ body: (JournalTransaction) throws -> Value) throws -> Value {
        try running()
        if let checkpointed {
            return try checkpointed.write(epoch: writer.epoch, recoverRejectedBody: true, body)
        }
        return try database.write(body)
    }

    private func running() throws { if stopped || checkpointed?.retired == true { throw ApprovalCoordinatorError.unavailable } }
    private func checkClock(_ now: AuthorityMoment) throws {
        try running()
        guard now.epoch == clockEpoch, lastTime == nil || now.milliseconds >= lastTime! else {
            stopped = true; entries.removeAll(); retainedBytes = 0; deliveryBytes = 0
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
