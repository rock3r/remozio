import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import SQLite3
import XCTest
@testable import RemozioCore

final class ApprovalRequestCoordinatorTests: XCTestCase {
    private enum Failure: Error { case fixture }
    private let clock = UUID()
    private let key = P256.Signing.PrivateKey()
    private let decisionKey = P256.Signing.PrivateKey()
    private func id(_ n: UInt8, _ count: Int = 16) -> Data { Data(repeating: n, count: count) }
    private var limits: CBORLimits { get throws { try .init(maxBytes: 4096, maxDepth: 12, maxItems: 256) } }
    private var contract: RequestContract { get throws { try .init(requestKind: .command, wireVersion: 1, schemaVersion: 1) } }
    private var capabilities: ContractCapabilities { get throws { try .init(contracts: [contract: [1]]) } }
    private func now(_ n: UInt64 = 110) -> AuthorityMoment { .init(epoch: clock, milliseconds: n) }
    private func draft(capture: Data = Data([0xa0]), deadline: UInt64 = 200) throws -> ApprovalRequestDraft {
        try .init(contract: contract, requiredFeatures: [1], capture: capture,
            actions: [.init(choice: .execute, scope: .currentRequest), .init(choice: .decline, scope: .currentRequest)],
            firstObservedAt: now(100), deadlineMilliseconds: deadline, createdUnixMilliseconds: 1000, expiresUnixMilliseconds: 1100)
    }
    private func descriptor(_ epoch: UInt8) throws -> AuditEpochDescriptor {
        try .decode(DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(id(1)), 2: .bytes(id(2)), 3: .bytes(id(epoch)),
            4: .unsigned(UInt64(epoch)), 5: .unsigned(1), 6: .null, 7: .null, 8: .null]), limits: limits), limits: limits)
    }
    private func open(_ fixture: Fixture, initialize: Bool) throws -> JournalDatabase {
        try .init(lease: fixture.lease(), macID: id(1), accountID: id(2), recordLimits: limits, descriptorLimits: limits,
            decisionLimits: limits, maximumConsumptions: 30, busyMilliseconds: 100, initialize: initialize)
    }
    private func setup(_ fixture: Fixture) throws -> (JournalDatabase, AuditEpochWriter) {
        let db = try open(fixture, initialize: true)
        let revision = try db.write { try $0.configureApprovalAuthority(capabilities: capabilities, allowedContracts: [contract]) }
        let writer = try db.write { try $0.createEpoch(descriptor(3)) }
        let enrollment = try StoredApprovalEnrollment(epoch: id(9), notificationTag: id(10, 32),
            identityPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
            approval: ApprovalEnrollment(phoneID: id(5), active: true, capabilities: capabilities, keys: [
                EnrolledApprovalKey(id: id(6), keyClass: .biometric, publicKey: key.publicKey.x963Representation),
                EnrolledApprovalKey(id: id(7), keyClass: .decision, publicKey: decisionKey.publicKey.x963Representation),
            ]))
        _ = try db.write { try $0.addApprovalEnrollment(enrollment, expectedTrustRevision: revision,
            eventID: id(30), receiptTimeMs: 900, writer: writer, expectedAuditHead: 0) }
        return (db, writer)
    }
    private func owner(_ db: JournalDatabase, _ writer: AuditEpochWriter, maximum: Int = 8, bytes: Int = 32768) throws -> ApprovalRequestCoordinator {
        try .init(database: db, writer: writer, clockEpoch: clock, maximumRequests: maximum, maximumRetainedBytes: bytes,
            requestLimits: limits, captureLimits: limits, decisionLimits: limits, signingLimits: limits, auditLimits: limits)
    }
    private func decision(_ request: IssuedRequestPayload, decline: Bool = false) throws -> (Data, Data) {
        let body = try DecisionPayload(macID: request.macID, accountID: request.accountID, requestID: request.requestID,
            requestDigest: request.requestDigest(bodyLimits: limits, signingLimits: limits), challenge: request.challenge,
            phoneID: id(5), keyID: id(decline ? 7 : 6), action: request.permittedActions[decline ? 1 : 0]).encode(limits: limits)
        return (body, try (decline ? decisionKey : key).signature(for: SigningInput.make(wireVersion: 1, messageType: .decision, purpose: decline ? .cancellation : .biometricAuthorization,
            canonicalPayload: body, payloadLimits: limits, inputLimits: limits)).rawRepresentation)
    }
    private func consume(_ owner: ApprovalRequestCoordinator, _ request: IssuedRequestPayload, time: UInt64 = 110) throws -> ConsumptionReceipt {
        let (body, signature) = try decision(request)
        return try owner.consume(canonicalDecision: body, signature: signature, authenticatedPhoneID: id(5),
            authenticatedEnrollmentEpoch: id(9), now: now(time), receiptTimeMs: 1001)
    }
    private func events(_ db: JournalDatabase, _ writer: AuditEpochWriter) throws -> [AuditEventMetadata] {
        try db.read { try $0.page(epoch: writer.epoch, after: 0, maximumRecords: 50, maximumBytes: 32768).canonicalRecords.map {
            try AuditEventMetadata.decode($0, limits: limits)
        } }
    }

    func testAdmissionCreatesFreshBindingsAndAuditsMetadataBeforeReturning() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let secret = try DeterministicCBOR.encode(.map([0: .text("synthetic-sensitive-capture")]), limits: limits)
        let a = try owner.admit(draft(capture: secret), now: now(), receiptTimeMs: 1000)
        let b = try owner.admit(draft(capture: secret), now: now(), receiptTimeMs: 1000)
        XCTAssertNotEqual(a.requestID, b.requestID)
        XCTAssertNotEqual(a.challenge, b.challenge)
        XCTAssertEqual(a.macID, id(1)); XCTAssertEqual(a.accountID, id(2))
        let retained = try owner.pendingRequest(requestID: a.requestID, now: now(150), receiptTimeMs: nil)
        XCTAssertEqual(retained.payload, a); XCTAssertEqual(retained.admittedAt, now(100))
        XCTAssertEqual(retained.deadlineMilliseconds, 200)
        let records = try events(db, writer)
        XCTAssertEqual(records.map(\.kind), [.enrollmentAdded, .requestCreated, .requestCreated])
        XCTAssertEqual(records[1].requestID, a.requestID)
        XCTAssertFalse(try Data(contentsOf: URL(fileURLWithPath: fixture.path)).contains(Data("synthetic-sensitive-capture".utf8)))
    }

    func testPresentationIsIdempotentAndFirstDecisionOwnsStateAndLedger() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let request = try owner.admit(draft(), now: now(), receiptTimeMs: nil)
        let presented = try owner.markPresented(requestID: request.requestID, now: now(), receiptTimeMs: nil)
        XCTAssertEqual(presented.phase, .presented)
        XCTAssertEqual(try owner.markPresented(requestID: request.requestID, now: now(), receiptTimeMs: nil), presented)
        let winner = try consume(owner, request)
        XCTAssertEqual(try owner.state(requestID: request.requestID).phase, .authorized)
        XCTAssertEqual(try owner.consumedRequest(requestID: request.requestID, now: now()).payload, request)
        XCTAssertThrowsError(try consume(owner, request)) { XCTAssertEqual($0 as? ApprovalCoordinatorError, .notPending) }
        XCTAssertThrowsError(try owner.retirePending(requestID: request.requestID, reason: .cancelled, now: now(), receiptTimeMs: nil))
        XCTAssertEqual(try owner.historicalOutcome(requestID: request.requestID)?.receipt, winner)
        XCTAssertEqual(try events(db, writer).filter { $0.kind == .consumed }.count, 1)
    }

    func testRetiringPendingRequestPreventsEvenValidSignedDecisions() throws {
        for (reason, expected, statusReason) in [(PendingRequestRetirement.cancelled, RequestPhase.cancelled, RequestStatusReason.userCancelled), (.targetTimedOut, .expired, .targetTimedOut), (.targetDisappeared, .unknown, .targetDisappeared), (.authorityRestart, .cancelled, .authorityRestarted)] {
            let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
            let request = try owner.admit(draft(), now: now(), receiptTimeMs: nil)
            XCTAssertEqual(try owner.retirePending(requestID: request.requestID, reason: reason, now: now(), receiptTimeMs: nil).phase, expected)
            XCTAssertThrowsError(try consume(owner, request))
            XCTAssertNil(try owner.historicalOutcome(requestID: request.requestID))
            XCTAssertThrowsError(try owner.pendingRequest(requestID: request.requestID, now: now(), receiptTimeMs: nil))
            let state = try owner.state(requestID: request.requestID)
            XCTAssertEqual(state.reason, statusReason)
            XCTAssertEqual(state.terminalAt, now())
            XCTAssertNil(state.decisionPhoneID)
            if reason == .targetDisappeared { XCTAssertEqual(try events(db, writer).last?.reason, .targetDisappeared) }
        }
    }

    func testDeadlineIsEnforcedBeforeConsumptionAndExpiresExactlyOnce() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let request = try owner.admit(draft(), now: now(), receiptTimeMs: nil)
        XCTAssertThrowsError(try consume(owner, request, time: 200)) { XCTAssertEqual($0 as? ApprovalCoordinatorError, .expired) }
        XCTAssertEqual(try owner.state(requestID: request.requestID).phase, .expired)
        XCTAssertEqual(try owner.state(requestID: request.requestID).reason, .authorizationExpired)
        XCTAssertEqual(try owner.state(requestID: request.requestID).terminalAt, now(200))
        XCTAssertThrowsError(try owner.pendingRequest(requestID: request.requestID, now: now(201), receiptTimeMs: nil))
        XCTAssertEqual(try events(db, writer).filter { $0.kind == .expired }.count, 1)
        XCTAssertNil(try owner.historicalOutcome(requestID: request.requestID))
    }

    func testChannelEpochRevocationAndSignatureUseCurrentStoredTrust() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let request = try owner.admit(draft(), now: now(), receiptTimeMs: nil), (body, signature) = try decision(request)
        for (phone, epoch, sig) in [(id(8), id(9), signature), (id(5), id(8), signature), (id(5), id(9), Data(repeating: 0, count: 64))] {
            XCTAssertThrowsError(try owner.consume(canonicalDecision: body, signature: sig, authenticatedPhoneID: phone,
                authenticatedEnrollmentEpoch: epoch, now: now(), receiptTimeMs: nil))
        }
        XCTAssertEqual(try owner.state(requestID: request.requestID).phase, .queued)
        let revision = try db.read { try $0.approvalTrustSnapshot().revision }
        _ = try db.write { try $0.revokeApprovalEnrollment(phoneID: id(5), epoch: id(9), expectedTrustRevision: revision,
            eventID: id(31), receiptTimeMs: nil, writer: writer, expectedAuditHead: 2) }
        XCTAssertThrowsError(try consume(owner, request))
        XCTAssertNil(try owner.historicalOutcome(requestID: request.requestID))
    }

    func testJournalFailuresNeverPublishProvisionalAdmissionConsumptionOrRetirement() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer, maximum: 1)
        try fixture.sql("CREATE TRIGGER fail_audit BEFORE INSERT ON audit_records_v1 BEGIN SELECT RAISE(ABORT,'injected'); END")
        XCTAssertThrowsError(try owner.admit(draft(), now: now(), receiptTimeMs: nil))
        try fixture.sql("DROP TRIGGER fail_audit")
        let request = try owner.admit(draft(), now: now(), receiptTimeMs: nil)
        try fixture.sql("CREATE TRIGGER fail_audit BEFORE INSERT ON audit_records_v1 BEGIN SELECT RAISE(ABORT,'injected'); END")
        XCTAssertThrowsError(try consume(owner, request))
        XCTAssertEqual(try owner.state(requestID: request.requestID).phase, .queued)
        XCTAssertNil(try owner.historicalOutcome(requestID: request.requestID))
        XCTAssertThrowsError(try owner.retirePending(requestID: request.requestID, reason: .cancelled, now: now(), receiptTimeMs: nil))
        XCTAssertEqual(try owner.pendingRequest(requestID: request.requestID, now: now(), receiptTimeMs: nil).payload, request)
        try fixture.sql("DROP TRIGGER fail_audit")
        _ = try consume(owner, request)
    }

    func testOutcomesRetainBindingUntilTerminalAndNeverRetryUnknown() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let request = try owner.admit(draft(), now: now(), receiptTimeMs: nil)
        _ = try consume(owner, request)
        let dispatched = try owner.recordOutcome(requestID: request.requestID, expectedRevision: 0, event: .beginDispatch, now: now(210), receiptTimeMs: nil)
        XCTAssertEqual(dispatched.phase, .executing)
        XCTAssertEqual(try owner.consumedRequest(requestID: request.requestID, now: now(220)).payload, request)
        let unknown = try owner.recordOutcome(requestID: request.requestID, expectedRevision: 1, event: .loseOutcome, now: now(230), receiptTimeMs: nil)
        XCTAssertEqual(unknown.phase, .unknown)
        XCTAssertEqual(try owner.state(requestID: request.requestID).phase, .unknown)
        XCTAssertEqual(try owner.state(requestID: request.requestID).reason, .outcomeUnavailable)
        XCTAssertEqual(try owner.state(requestID: request.requestID).terminalAt, now(230))
        XCTAssertEqual(try owner.state(requestID: request.requestID).decisionPhoneID, id(5))
        XCTAssertThrowsError(try owner.recordOutcome(requestID: request.requestID, expectedRevision: 2, event: .verifySuccess, now: now(240), receiptTimeMs: nil))
        XCTAssertThrowsError(try owner.consumedRequest(requestID: request.requestID, now: now(240)))
        try owner.forgetTerminal(requestID: request.requestID)
        XCTAssertThrowsError(try owner.state(requestID: request.requestID))
        XCTAssertEqual(try owner.historicalOutcome(requestID: request.requestID), unknown)
    }

    func testCapacityCannotDiscardLiveOrConsumedRequestsAndClearsAfterTerminal() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer, maximum: 1)
        let request = try owner.admit(draft(), now: now(), receiptTimeMs: nil)
        XCTAssertThrowsError(try owner.admit(draft(), now: now(), receiptTimeMs: nil))
        XCTAssertThrowsError(try owner.forgetTerminal(requestID: request.requestID))
        _ = try consume(owner, request)
        XCTAssertThrowsError(try owner.forgetTerminal(requestID: request.requestID))
        _ = try owner.recordOutcome(requestID: request.requestID, expectedRevision: 0, event: .proveNoDispatch, now: now(), receiptTimeMs: nil)
        XCTAssertEqual(try owner.state(requestID: request.requestID).reason, .noDispatchProved)
        try owner.forgetTerminal(requestID: request.requestID)
        let replacement = try owner.admit(draft(), now: now(), receiptTimeMs: nil)
        XCTAssertNotEqual(replacement.requestID, request.requestID)
        XCTAssertEqual(try owner.historicalOutcome(requestID: request.requestID)?.phase, .cancelled)
    }

    func testClockDiscontinuityRetiresTheOwnerAndStorageClosureBlocksSnapshots() throws {
        for changedEpoch in [false, true] {
            let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
            let request = try owner.admit(draft(), now: now(), receiptTimeMs: nil)
            let bad = changedEpoch ? AuthorityMoment(epoch: UUID(), milliseconds: 111) : now(109)
            XCTAssertThrowsError(try owner.pendingRequest(requestID: request.requestID, now: bad, receiptTimeMs: nil))
            XCTAssertThrowsError(try owner.state(requestID: request.requestID)) { XCTAssertEqual($0 as? ApprovalCoordinatorError, .unavailable) }
            XCTAssertThrowsError(try owner.admit(draft(), now: now(111), receiptTimeMs: nil))
        }
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let request = try owner.admit(draft(), now: now(), receiptTimeMs: nil)
        try db.close()
        XCTAssertThrowsError(try owner.pendingRequest(requestID: request.requestID, now: now(), receiptTimeMs: nil))
        XCTAssertThrowsError(try owner.state(requestID: request.requestID))
    }

    func testRestartDoesNotRestorePendingOrConsumedExecutionBindings() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), first = try owner(db, writer)
        let pending = try first.admit(draft(), now: now(), receiptTimeMs: nil)
        let consumed = try first.admit(draft(), now: now(), receiptTimeMs: nil)
        let receipt = try consume(first, consumed)
        try db.close()
        let reopened = try open(fixture, initialize: false), nextWriter = try reopened.write { try $0.createEpoch(descriptor(4)) }
        let next = try owner(reopened, nextWriter)
        XCTAssertThrowsError(try next.pendingRequest(requestID: pending.requestID, now: now(), receiptTimeMs: nil))
        XCTAssertThrowsError(try next.consumedRequest(requestID: consumed.requestID, now: now()))
        XCTAssertEqual(try next.historicalOutcome(requestID: consumed.requestID)?.receipt, receipt)
    }

    func testDeclineUsesDecisionKeyAndReleasesCaptureWithoutExecution() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let request = try owner.admit(draft(), now: now(), receiptTimeMs: nil), (body, signature) = try decision(request, decline: true)
        let receipt = try owner.consume(canonicalDecision: body, signature: signature, authenticatedPhoneID: id(5),
            authenticatedEnrollmentEpoch: id(9), now: now(), receiptTimeMs: nil)
        XCTAssertEqual(receipt.event.outcome, .noDispatch)
        XCTAssertEqual(try owner.state(requestID: request.requestID).phase, .declined)
        XCTAssertEqual(try owner.state(requestID: request.requestID).reason, .declined)
        XCTAssertEqual(try owner.state(requestID: request.requestID).decisionPhoneID, id(5))
        XCTAssertThrowsError(try owner.consumedRequest(requestID: request.requestID, now: now()))
        XCTAssertThrowsError(try owner.recordOutcome(requestID: request.requestID, expectedRevision: 0, event: .beginDispatch, now: now(), receiptTimeMs: nil))
    }

    func testByteBudgetReleasesOnlyAtTerminalAndInvalidDraftsDoNotConsumeCapacity() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer, bytes: 4096)
        XCTAssertThrowsError(try owner.admit(draft(capture: Data([0xff])), now: now(), receiptTimeMs: nil))
        XCTAssertThrowsError(try owner.admit(draft(deadline: 110), now: now(), receiptTimeMs: nil))
        let capture = try DeterministicCBOR.encode(.map([0: .bytes(id(42, 2800))]), limits: limits)
        let request = try owner.admit(draft(capture: capture), now: now(), receiptTimeMs: nil)
        XCTAssertThrowsError(try owner.admit(draft(capture: capture), now: now(), receiptTimeMs: nil))
        _ = try consume(owner, request)
        XCTAssertThrowsError(try owner.admit(draft(capture: capture), now: now(), receiptTimeMs: nil))
        _ = try owner.recordOutcome(requestID: request.requestID, expectedRevision: 0, event: .proveNoDispatch, now: now(), receiptTimeMs: nil)
        _ = try owner.admit(draft(capture: capture), now: now(), receiptTimeMs: nil)
    }

    func testTargetTimeoutIsDistinctFromAnUnelapsedDeadline() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let request = try owner.admit(draft(), now: now(), receiptTimeMs: nil)
        XCTAssertThrowsError(try owner.retirePending(requestID: request.requestID, reason: .deadlineElapsed, now: now(), receiptTimeMs: nil))
        XCTAssertEqual(try owner.state(requestID: request.requestID).phase, .queued)
        _ = try owner.retirePending(requestID: request.requestID, reason: .targetTimedOut, now: now(), receiptTimeMs: nil)
        XCTAssertEqual(try events(db, writer).last?.reason, .targetTimedOut)
    }

    func testOwnedQueuedAndDisappearedStatesRoundTripThroughStatusCodec() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let request = try owner.admit(draft(), now: now(), receiptTimeMs: nil)
        for disappeared in [false, true] {
            if disappeared { _ = try owner.retirePending(requestID: request.requestID, reason: .targetDisappeared, now: now(), receiptTimeMs: nil) }
            let state = try owner.state(requestID: request.requestID)
            let status = try state.statusPayload(observationID: id(40), observationRevision: state.revision,
                now: now(130), estimatedLifetimeMs: nil, lateObservation: false)
            XCTAssertEqual(state.phase, disappeared ? .unknown : .queued)
            XCTAssertEqual(status.phase, disappeared ? .cancelled : .queued)
            XCTAssertEqual(status.reason, disappeared ? .targetDisappeared : .none)
            let later = try state.statusPayload(observationID: id(40), observationRevision: state.revision + 1,
                now: now(150), estimatedLifetimeMs: nil, lateObservation: false)
            XCTAssertEqual(later.terminalAgeMs, status.terminalAgeMs)
            XCTAssertEqual(later.observedAgeMs, 50)
            XCTAssertThrowsError(try state.statusPayload(observationID: id(40), observationRevision: 10,
                now: .init(epoch: UUID(), milliseconds: 130), estimatedLifetimeMs: nil, lateObservation: false))
            XCTAssertEqual(status.observedAgeMs, 30)
            XCTAssertEqual(status.terminalAgeMs, disappeared ? 10 : nil)
            XCTAssertEqual(try RequestStatusPayload.decode(status.encode(limits: limits), limits: limits), status)
        }
    }

    func testDeliveryClosesFromOwnerStateAfterEveryPendingExit() throws {
        enum Exit: CaseIterable { case cancelled, timedOut, disappeared, restart, declined, authorized, deadline }
        for exit in Exit.allCases {
            for started in [false, true] {
                let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
                let request = try owner.admit(draft(), now: now(), receiptTimeMs: nil)
                let retained = try owner.pendingRequest(requestID: request.requestID, now: now(), receiptTimeMs: nil)
                let delivery = try PendingRequestDelivery(request: retained)
                var router = PresenceRouter(configuration: try .init(observationLifetimeMilliseconds: 100, unavailableGraceMilliseconds: 0))
                let routing = router.evaluate(mode: .away, snapshot: .init(), now: .init(epoch: clock, milliseconds: 110))
                let queued = try owner.reconcileDelivery(requestID: request.requestID, delivery: delivery,
                    routing: routing, now: now(), receiptTimeMs: nil) { _ in true }
                XCTAssertEqual(queued.active.count, 1)
                let trust = try db.read { try $0.requestDeliveryTrust() }
                if started {
                    XCTAssertNotNil(delivery.beginDelivery(id: queued.active[0].id, current: retained, routing: routing,
                        trust: trust, now: now()).delivery)
                }
                switch exit {
                case .cancelled, .timedOut, .disappeared, .restart:
                    let reason: PendingRequestRetirement = switch exit {
                    case .cancelled: .cancelled
                    case .timedOut: .targetTimedOut
                    case .disappeared: .targetDisappeared
                    default: .authorityRestart
                    }
                    _ = try owner.retirePending(requestID: request.requestID, reason: reason, now: now(), receiptTimeMs: nil)
                case .declined:
                    let (body, signature) = try decision(request, decline: true)
                    _ = try owner.consume(canonicalDecision: body, signature: signature, authenticatedPhoneID: id(5),
                        authenticatedEnrollmentEpoch: id(9), now: now(), receiptTimeMs: nil)
                case .authorized: _ = try consume(owner, request)
                case .deadline: break
                }
                let time = now(exit == .deadline ? 200 : 120)
                let closed = try owner.reconcileDelivery(requestID: request.requestID, delivery: delivery,
                    routing: routing, now: time, receiptTimeMs: nil) { _ in XCTFail("Closed request must not enqueue"); return true }
                XCTAssertEqual(closed.closure, .requestPhase(try owner.state(requestID: request.requestID).phase))
                XCTAssertEqual(closed.withdrawn, queued.active)
                XCTAssertTrue(closed.active.isEmpty); XCTAssertTrue(closed.dispatched.isEmpty)
                let repeated = try owner.reconcileDelivery(requestID: request.requestID, delivery: delivery,
                    routing: routing, now: time, receiptTimeMs: nil) { _ in XCTFail(); return true }
                XCTAssertTrue(repeated.withdrawn.isEmpty)
                XCTAssertNil(delivery.beginDelivery(id: queued.active[0].id, current: retained, routing: routing,
                    trust: trust, now: time).delivery)
            }
        }
    }

    func testFailedExpiryCannotPublishDeliveryWithdrawalBeforeCommit() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let request = try owner.admit(draft(), now: now(), receiptTimeMs: nil)
        let delivery = try PendingRequestDelivery(request: owner.pendingRequest(requestID: request.requestID, now: now(), receiptTimeMs: nil))
        var router = PresenceRouter(configuration: try .init(observationLifetimeMilliseconds: 100, unavailableGraceMilliseconds: 0))
        let routing = router.evaluate(mode: .away, snapshot: .init(), now: .init(epoch: clock, milliseconds: 110))
        let queued = try owner.reconcileDelivery(requestID: request.requestID, delivery: delivery,
            routing: routing, now: now(), receiptTimeMs: nil) { _ in true }
        try fixture.sql("CREATE TRIGGER fail_audit BEFORE INSERT ON audit_records_v1 BEGIN SELECT RAISE(ABORT,'injected'); END")
        XCTAssertThrowsError(try owner.reconcileDelivery(requestID: request.requestID, delivery: delivery,
            routing: routing, now: now(200), receiptTimeMs: nil) { _ in XCTFail(); return true })
        XCTAssertEqual(try owner.state(requestID: request.requestID).phase, .queued)
        try fixture.sql("DROP TRIGGER fail_audit")
        let closed = try owner.reconcileDelivery(requestID: request.requestID, delivery: delivery,
            routing: routing, now: now(200), receiptTimeMs: nil) { _ in XCTFail(); return true }
        XCTAssertEqual(closed.withdrawn, queued.active)
        XCTAssertEqual(try owner.state(requestID: request.requestID).phase, .expired)
    }

    private func routing(_ mode: RoutingMode = .away) throws -> PresenceRouting {
        var router = PresenceRouter(configuration: try .init(observationLifetimeMilliseconds: 100, unavailableGraceMilliseconds: 0))
        return router.evaluate(mode: mode, snapshot: .init(), now: .init(epoch: clock, milliseconds: 110))
    }

    private func queuedDelivery(_ owner: ApprovalRequestCoordinator) throws -> (IssuedRequestPayload, PendingRequestDelivery, PhoneRequestDelivery) {
        let request = try owner.admit(draft(), now: now(), receiptTimeMs: nil)
        let delivery = try PendingRequestDelivery(request: owner.pendingRequest(requestID: request.requestID, now: now(), receiptTimeMs: nil))
        let queued = try owner.reconcileDelivery(requestID: request.requestID, delivery: delivery,
            routing: routing(), now: now(), receiptTimeMs: nil) { _ in true }
        return (request, delivery, try XCTUnwrap(queued.active.first))
    }

    func testHandoffBackpressureKeepsOriginalIdentityAndAcceptsOnlyOnce() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let (request, delivery, queued) = try queuedDelivery(owner)
        var attempts: [PhoneRequestDelivery] = []
        let refused = try owner.handoffDelivery(requestID: request.requestID, delivery: delivery, deliveryID: queued.id,
            routing: routing(), now: now(120), receiptTimeMs: nil) { attempts.append($0); return false }
        XCTAssertNil(refused.delivery); XCTAssertTrue(refused.update.dispatched.isEmpty)
        XCTAssertEqual(refused.update.active, [queued])
        let accepted = try owner.handoffDelivery(requestID: request.requestID, delivery: delivery, deliveryID: queued.id,
            routing: routing(), now: now(150), receiptTimeMs: nil) { attempts.append($0); return true }
        XCTAssertEqual(accepted.delivery, queued); XCTAssertEqual(accepted.update.dispatched, [queued])
        XCTAssertEqual(attempts, [queued, queued])
        let duplicate = try owner.handoffDelivery(requestID: request.requestID, delivery: delivery, deliveryID: queued.id,
            routing: routing(), now: now(160), receiptTimeMs: nil) { _ in XCTFail("Already handed off"); return true }
        XCTAssertNil(duplicate.delivery); XCTAssertEqual(duplicate.update.dispatched, [queued])
        XCTAssertEqual(try events(db, writer).map(\.kind), [.enrollmentAdded, .requestCreated])
    }

    func testHandoffRechecksPresenceAfterPreparationWithoutLosingQueuedWork() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let (request, delivery, queued) = try queuedDelivery(owner)
        let local = try owner.handoffDelivery(requestID: request.requestID, delivery: delivery, deliveryID: queued.id,
            routing: routing(.present), now: now(120), receiptTimeMs: nil) { _ in XCTFail("Now local"); return true }
        XCTAssertNil(local.delivery); XCTAssertEqual(local.update.active, [queued])
        XCTAssertTrue(local.update.withdrawn.isEmpty); XCTAssertTrue(local.update.dispatched.isEmpty)
        let resumed = try owner.handoffDelivery(requestID: request.requestID, delivery: delivery, deliveryID: queued.id,
            routing: routing(), now: now(130), receiptTimeMs: nil) { XCTAssertEqual($0, queued); return true }
        XCTAssertEqual(resumed.delivery, queued)
    }

    func testHandoffRechecksJournalRevocationAfterPreparation() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let (request, delivery, queued) = try queuedDelivery(owner)
        let revision = try db.read { try $0.approvalTrustSnapshot().revision }
        _ = try db.write { try $0.revokeApprovalEnrollment(phoneID: id(5), epoch: id(9), expectedTrustRevision: revision,
            eventID: id(31), receiptTimeMs: nil, writer: writer, expectedAuditHead: 2) }
        let result = try owner.handoffDelivery(requestID: request.requestID, delivery: delivery, deliveryID: queued.id,
            routing: routing(), now: now(120), receiptTimeMs: nil) { _ in XCTFail("Stale trust"); return true }
        XCTAssertNil(result.delivery); XCTAssertEqual(result.update.withdrawn, [queued])
        XCTAssertTrue(result.update.active.isEmpty)
    }

    func testHandoffClosesFromCurrentOwnerAfterResolutionAndCaptureRelease() throws {
        for decline in [false, true] {
            let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
            let (request, delivery, queued) = try queuedDelivery(owner)
            let (body, signature) = try decision(request, decline: decline)
            _ = try owner.consume(canonicalDecision: body, signature: signature, authenticatedPhoneID: id(5),
                authenticatedEnrollmentEpoch: id(9), now: now(120), receiptTimeMs: nil)
            let result = try owner.handoffDelivery(requestID: request.requestID, delivery: delivery, deliveryID: queued.id,
                routing: routing(), now: now(130), receiptTimeMs: nil) { _ in XCTFail("Already resolved"); return true }
            XCTAssertNil(result.delivery); XCTAssertEqual(result.update.withdrawn, [queued])
            XCTAssertEqual(result.update.closure, .requestPhase(decline ? .declined : .authorized))
        }
    }

    func testHandoffExpiryCommitsBeforeWithdrawalAndStorageFailureNeverSends() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let (request, delivery, queued) = try queuedDelivery(owner)
        try fixture.sql("CREATE TRIGGER fail_audit BEFORE INSERT ON audit_records_v1 BEGIN SELECT RAISE(ABORT,'injected'); END")
        XCTAssertThrowsError(try owner.handoffDelivery(requestID: request.requestID, delivery: delivery, deliveryID: queued.id,
            routing: routing(), now: now(200), receiptTimeMs: nil) { _ in XCTFail("Expiry commit failed"); return true })
        XCTAssertEqual(try owner.state(requestID: request.requestID).phase, .queued)
        try fixture.sql("DROP TRIGGER fail_audit")
        let result = try owner.handoffDelivery(requestID: request.requestID, delivery: delivery, deliveryID: queued.id,
            routing: routing(), now: now(200), receiptTimeMs: nil) { _ in XCTFail("Expired"); return true }
        XCTAssertNil(result.delivery); XCTAssertEqual(result.update.withdrawn, [queued])
        XCTAssertEqual(result.update.closure, .requestPhase(.expired))
        XCTAssertEqual(try events(db, writer).filter { $0.kind == .expired }.count, 1)
    }

    func testHandoffRejectsUnknownIdentityAndMismatchedController() throws {
        let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
        let (request, delivery, queued) = try queuedDelivery(owner)
        let unknown = try owner.handoffDelivery(requestID: request.requestID, delivery: delivery, deliveryID: UUID(),
            routing: routing(), now: now(120), receiptTimeMs: nil) { _ in XCTFail("Unknown identity"); return true }
        XCTAssertNil(unknown.delivery); XCTAssertEqual(unknown.update.active, [queued])
        let other = try owner.admit(draft(), now: now(120), receiptTimeMs: nil)
        let mismatched = try owner.handoffDelivery(requestID: other.requestID, delivery: delivery, deliveryID: queued.id,
            routing: routing(), now: now(130), receiptTimeMs: nil) { _ in XCTFail("Wrong request controller"); return true }
        XCTAssertNil(mismatched.delivery); XCTAssertEqual(mismatched.update.withdrawn, [queued])
        XCTAssertEqual(mismatched.update.closure, .requestChanged)
    }

    func testHandoffClockDiscontinuityAndClosedJournalCannotReachTransport() throws {
        for close in [false, true] {
            let fixture = try Fixture(), (db, writer) = try setup(fixture), owner = try owner(db, writer)
            let (request, delivery, queued) = try queuedDelivery(owner)
            if close { try db.close() }
            let time = close ? now(120) : AuthorityMoment(epoch: UUID(), milliseconds: 120)
            XCTAssertThrowsError(try owner.handoffDelivery(requestID: request.requestID, delivery: delivery, deliveryID: queued.id,
                routing: routing(), now: time, receiptTimeMs: nil) { _ in XCTFail("Unavailable authority"); return true })
        }
    }

    private final class Fixture {
        let root: URL
        var path: String { root.appendingPathComponent("store/journal.sqlite").path }
        init() throws {
            guard let canonical = realpath(FileManager.default.temporaryDirectory.path, nil) else { throw Failure.fixture }
            defer { free(canonical) }
            root = URL(fileURLWithPath: String(cString: canonical)).appendingPathComponent(UUID().uuidString)
            let directory = root.appendingPathComponent("store").path
            try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            for name in ["writer.lock", "journal.sqlite"] {
                let fd = Darwin.open(directory + "/" + name, O_CREAT | O_EXCL | O_WRONLY, 0o600)
                guard fd >= 0 else { throw Failure.fixture }; Darwin.close(fd)
            }
        }
        deinit { try? FileManager.default.removeItem(at: root) }
        func lease() throws -> ProtectedJournalLease { try .init(anchor: root.path, relativeDirectory: "store", owner: getuid()) }
        func sql(_ sql: String) throws {
            var db: OpaquePointer?
            guard sqlite3_open(path, &db) == SQLITE_OK, let db else { throw Failure.fixture }
            defer { sqlite3_close(db) }
            guard sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else { throw Failure.fixture }
        }
    }
}
