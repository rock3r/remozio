import CryptoKit
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class PendingRequestDeliveryTests: XCTestCase {
    private let epoch = UUID()
    private func id(_ n: UInt8, _ count: Int = 16) -> Data { Data(repeating: n, count: count) }
    private func now(_ value: UInt64 = 110) -> AuthorityMoment { .init(epoch: epoch, milliseconds: value) }
    private var contract: RequestContract { get throws { try .init(requestKind: .command, wireVersion: 1, schemaVersion: 1) } }
    private func request(phase: RequestPhase = .queued, requestID: UInt8 = 3, deadline: UInt64 = 200) throws -> RetainedApprovalRequest {
        let limits = try CBORLimits(maxBytes: 4096, maxDepth: 12, maxItems: 256)
        let payload = try IssuedRequestPayload(contract: contract, macID: id(1), accountID: id(2), requestID: id(requestID),
            challenge: id(4, 32), requiredFeatures: [1], createdUnixMilliseconds: 1000, expiresUnixMilliseconds: 1100,
            canonicalCapture: Data([0xa0]), permittedActions: [.init(choice: .execute, scope: .currentRequest)],
            bodyLimits: limits, captureLimits: limits)
        return try .init(payload: payload, phase: phase, admittedAt: now(100), deadlineMilliseconds: deadline)
    }
    private func phone(_ n: UInt8, epoch: UInt8 = 9, active: Bool = true, features: Set<UInt64> = [1]) throws -> StoredApprovalEnrollment {
        try .init(epoch: id(epoch), notificationTag: id(n, 32), identityPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
            approval: .init(phoneID: id(n), active: active, capabilities: .init(contracts: [contract: features]), keys: [
                .init(id: id(20), keyClass: .decision, publicKey: P256.Signing.PrivateKey().publicKey.x963Representation),
                .init(id: id(21), keyClass: .biometric, publicKey: P256.Signing.PrivateKey().publicKey.x963Representation),
            ]))
    }
    private func trust(_ phones: [StoredApprovalEnrollment], account: UInt8 = 2, allowed: Bool = true) throws -> RequestDeliveryTrust {
        try .init(approval: .init(macID: id(1), accountID: id(account), revision: UUID(),
            authorityCapabilities: .init(contracts: [contract: [1]]), allowedContracts: allowed ? [contract] : [],
            enrollments: phones.map(\.approval)), enrollments: phones)
    }
    private func route(_ mode: RoutingMode) throws -> PresenceRouting {
        var router = PresenceRouter(configuration: try .init(observationLifetimeMilliseconds: 100, unavailableGraceMilliseconds: 0))
        return router.evaluate(mode: mode, snapshot: .init(), now: .init(epoch: epoch, milliseconds: 110))
    }
    private func reconcile(_ session: PendingRequestDelivery, mode: RoutingMode = .away, phones: [StoredApprovalEnrollment],
                           time: UInt64 = 110, phase: RequestPhase = .queued,
                           enqueue: (PhoneRequestDelivery) -> Bool = { _ in true }) throws -> RequestDeliveryUpdate {
        try session.reconcile(current: request(phase: phase), routing: route(mode), trust: trust(phones), now: now(time), enqueue: enqueue)
    }

    private func discover(_ session: PendingRequestDelivery, current: RetainedApprovalRequest,
                          mode: RoutingMode = .away, phones: [StoredApprovalEnrollment], time: UInt64 = 110) throws -> Set<DeliveryRecipient> {
        let snapshot = try trust(phones), routing = try route(mode)
        return Set(phones.filter {
            session.canDiscover(current: current, routing: routing, authority: snapshot.approval,
                recipient: DeliveryRecipient($0), enrollment: $0.approval, now: now(time))
        }.map(DeliveryRecipient.init))
    }

    func testDiscoveryLeavesNotificationEnqueueAvailable() throws {
        let request = try request(), session = try PendingRequestDelivery(request: request), phones = try [phone(5), phone(6)]
        let discovered = try discover(session, current: request, phones: phones)
        XCTAssertEqual(discovered.count, 2)
        XCTAssertEqual(try discover(session, current: request, phones: phones), discovered)
        XCTAssertTrue(try discover(session, current: request, mode: .present, phones: phones).isEmpty)
        var accepted: [PhoneRequestDelivery] = []
        let queued = try reconcile(session, phones: phones) { accepted.append($0); return true }
        XCTAssertEqual(Set(accepted.map(\.recipient)), discovered)
        XCTAssertEqual(Set(queued.newlyEnqueued.map(\.recipient)), discovered)
        _ = try reconcile(session, phones: phones) { _ in XCTFail("Queue already owns retries"); return true }
    }

    func testDiscoveryDoesNotConsumeQueueWithdrawals() throws {
        let request = try request(), session = try PendingRequestDelivery(request: request), phones = try [phone(5), phone(6)]
        let queued = try reconcile(session, phones: phones)
        let remaining = [phones[1]]
        for _ in 0..<2 {
            let discovered = try discover(session, current: request, phones: remaining)
            XCTAssertEqual(discovered, Set([DeliveryRecipient(phones[1])]))
        }
        let update = try reconcile(session, phones: remaining)
        XCTAssertEqual(update.withdrawn, queued.active.filter { $0.recipient.phoneID == id(5) })
        XCTAssertTrue(try reconcile(session, phones: remaining).withdrawn.isEmpty)
    }

    func testDiscoveryRespectsRecipientCapacityAndRetirementWithoutAllocatingEntries() throws {
        let request = try request(), session = try PendingRequestDelivery(request: request, maximumRecipients: 1)
        let a = try phone(5), b = try phone(6), replacement = try phone(5, epoch: 10)
        for _ in 0..<3 {
            XCTAssertEqual(try discover(session, current: request, phones: [a, b]), Set([DeliveryRecipient(a), DeliveryRecipient(b)]))
        }
        let queued = try reconcile(session, phones: [b])
        XCTAssertEqual(queued.active.map(\.recipient.phoneID), [id(6)])
        XCTAssertTrue(try discover(session, current: request, phones: [a]).isEmpty)
        _ = try reconcile(session, phones: [])
        XCTAssertTrue(try discover(session, current: request, phones: [b, replacement]).isEmpty)
    }

    func testDiscoveryChecksOnlySelectedEnrollmentAndCurrentRequest() throws {
        let request = try request(), session = try PendingRequestDelivery(request: request), a = try phone(5)
        XCTAssertTrue(try discover(session, current: request, phones: [phone(5, features: [])]).isEmpty)
        XCTAssertTrue(try discover(session, current: request, phones: [phone(5, active: false)]).isEmpty)
        XCTAssertTrue(try discover(session, current: request, phones: [a], time: 200).isEmpty)
        XCTAssertTrue(try discover(session, current: self.request(phase: .cancelled), phones: [a]).isEmpty)
        XCTAssertTrue(try discover(session, current: self.request(requestID: 4), phones: [a]).isEmpty)
        let queued = try reconcile(session, phones: [a]).active
        _ = try session.beginDelivery(id: XCTUnwrap(queued.first).id, current: request, routing: route(.away), trust: trust([a]), now: now())
        XCTAssertEqual(try discover(session, current: request, mode: .present, phones: [a]), Set([DeliveryRecipient(a)]))
        XCTAssertTrue(try discover(session, current: request, mode: .present, phones: [phone(5, epoch: 10)]).isEmpty)
    }

    func testLocalThenAwayPreservesIdentityAgeAndDeadlineForEveryPhone() throws {
        let request = try request(), session = try PendingRequestDelivery(request: request), phones = try [phone(5), phone(6)]
        let local = try reconcile(session, mode: .present, phones: phones) { _ in XCTFail("Local request must not enqueue"); return true }
        XCTAssertTrue(local.active.isEmpty)
        let away = try reconcile(session, phones: phones, time: 180)
        XCTAssertEqual(away.newlyEnqueued.count, 2)
        XCTAssertEqual(Set(away.active.map(\.recipient.phoneID)), Set([id(5), id(6)]))
        for delivery in away.active {
            XCTAssertEqual(delivery.requestID, request.payload.requestID)
            XCTAssertEqual(delivery.admittedAt, request.admittedAt)
            XCTAssertEqual(delivery.deadlineMilliseconds, request.deadlineMilliseconds)
        }
    }

    func testPresenceOscillationKeepsReviewAndNeverRenotifies() throws {
        let session = try PendingRequestDelivery(request: request()), phones = try [phone(5)]
        let first = try reconcile(session, phones: phones).active
        for (offset, mode) in [RoutingMode.present, .away, .present, .automatic, .away].enumerated() {
            let update = try reconcile(session, mode: mode, phones: phones, time: UInt64(111 + offset), phase: .presented) { _ in
                XCTFail("Already enqueued"); return true
            }
            XCTAssertEqual(update.active, first)
            XCTAssertTrue(update.withdrawn.isEmpty)
            XCTAssertTrue(update.newlyEnqueued.isEmpty)
        }
    }

    func testFailedLocalEnqueueRetriesSameIdentityOnlyWhileAway() throws {
        let session = try PendingRequestDelivery(request: request()), phones = try [phone(5)]
        var attempted: PhoneRequestDelivery?
        let failure = try reconcile(session, phones: phones) { attempted = $0; return false }
        XCTAssertTrue(failure.active.isEmpty)
        _ = try reconcile(session, mode: .present, phones: phones) { _ in XCTFail(); return true }
        let retried = try reconcile(session, phones: phones) { XCTAssertEqual($0, attempted); return true }
        XCTAssertEqual(retried.active, [try XCTUnwrap(attempted)])
    }

    func testExpiryNeverHandsOffStaleLocalRequestsAndWithdrawsDeliveredOnes() throws {
        for delivered in [false, true] {
            let session = try PendingRequestDelivery(request: request()), phones = try [phone(5)]
            if delivered { _ = try reconcile(session, phones: phones) }
            let expired = try reconcile(session, phones: phones, time: 200) { _ in XCTFail(); return true }
            XCTAssertEqual(expired.closure, .expired)
            XCTAssertEqual(expired.withdrawn.count, delivered ? 1 : 0)
            XCTAssertTrue(expired.active.isEmpty)
            let retry = try reconcile(session, phones: phones, time: 190) { _ in XCTFail(); return true }
            XCTAssertEqual(retry.closure, .expired)
            XCTAssertTrue(retry.withdrawn.isEmpty)
        }
    }

    func testConsumptionAndEveryNonPendingPhaseWithdrawWithoutRerouting() throws {
        for phase in RequestPhase.allCases where phase != .queued && phase != .presented {
            let session = try PendingRequestDelivery(request: request()), phones = try [phone(5), phone(6)]
            let delivered = try reconcile(session, phones: phones).active
            let stopped = try reconcile(session, mode: .present, phones: phones, phase: phase) { _ in XCTFail(); return true }
            XCTAssertEqual(stopped.closure, .requestPhase(phase))
            XCTAssertEqual(stopped.withdrawn, delivered)
            XCTAssertTrue(stopped.active.isEmpty)
            XCTAssertTrue(try reconcile(session, phones: phones).active.isEmpty)
        }
    }

    func testRevocationAndReplacementCannotReviveOldDelivery() throws {
        let session = try PendingRequestDelivery(request: request()), a = try phone(5), b = try phone(6)
        let first = try reconcile(session, phones: [a, b])
        let revoked = try reconcile(session, phones: [b])
        XCTAssertEqual(revoked.withdrawn.map(\.recipient.phoneID), [id(5)])
        XCTAssertEqual(revoked.active.map(\.recipient.phoneID), [id(6)])
        let stale = try reconcile(session, phones: [a, b])
        XCTAssertEqual(stale.active, revoked.active)
        let replacement = try reconcile(session, phones: [phone(5, epoch: 10), b])
        XCTAssertEqual(replacement.newlyEnqueued.count, 1)
        XCTAssertEqual(replacement.newlyEnqueued.first?.recipient.enrollmentEpoch, id(10))
        XCTAssertFalse(first.active.map(\.id).contains(try XCTUnwrap(replacement.newlyEnqueued.first?.id)))
    }

    func testNewPhoneWaitsWhilePresentAndUnsupportedPhoneReceivesNothing() throws {
        let session = try PendingRequestDelivery(request: request()), a = try phone(5), b = try phone(6)
        _ = try reconcile(session, phones: [a])
        let local = try reconcile(session, mode: .present, phones: [a, b])
        XCTAssertEqual(local.active.count, 1)
        let away = try reconcile(session, phones: [a, b, phone(7, features: []), phone(8, active: false)])
        XCTAssertEqual(away.newlyEnqueued.map(\.recipient.phoneID), [id(6)])
        XCTAssertEqual(away.active.count, 2)
    }

    func testChangedRequestDeadlineClockAndAuthorityFailClosed() throws {
        for variant in 0..<6 {
            let session = try PendingRequestDelivery(request: request()), phones = try [phone(5)]
            _ = try reconcile(session, phones: phones)
            let changed = try session.reconcile(current: request(requestID: variant == 0 ? 8 : 3, deadline: variant == 1 ? 201 : 200),
                routing: route(.away), trust: trust(phones, account: variant == 4 ? 8 : 2, allowed: variant != 5),
                now: variant == 2 ? .init(epoch: UUID(), milliseconds: 111) : now(variant == 3 ? 109 : 111)) { _ in XCTFail(); return true }
            XCTAssertNotNil(changed.closure)
            XCTAssertEqual(changed.withdrawn.count, 1)
            XCTAssertTrue(changed.active.isEmpty)
            XCTAssertTrue(try reconcile(session, phones: phones, time: 112).active.isEmpty)
        }
    }

    func testCapacityIsBoundedAndVisibleIncludingRetiredIdentities() throws {
        let session = try PendingRequestDelivery(request: request(), maximumRecipients: 1), phones = try [phone(5), phone(6)]
        let first = try reconcile(session, phones: phones)
        XCTAssertEqual(first.active.count, 1)
        XCTAssertEqual(first.capacityLimitedRecipients.map(\.phoneID), [id(6)])
        let next = try reconcile(session, phones: [phone(5, epoch: 10)])
        XCTAssertTrue(next.active.isEmpty)
        XCTAssertEqual(next.withdrawn.count, 1)
        XCTAssertEqual(next.capacityLimitedRecipients.count, 1)
    }

    func testQueueAcceptanceDoesNotBypassPresenceRecheckBeforeDispatch() throws {
        let session = try PendingRequestDelivery(request: request()), phones = try [phone(5)]
        let queued = try reconcile(session, phones: phones)
        let delivery = try XCTUnwrap(queued.active.first)
        XCTAssertTrue(queued.dispatched.isEmpty)
        let local = try session.beginDelivery(id: delivery.id, current: request(), routing: route(.present), trust: trust(phones), now: now())
        XCTAssertNil(local.delivery)
        XCTAssertTrue(local.update.dispatched.isEmpty)
        let away = try session.beginDelivery(id: delivery.id, current: request(), routing: route(.away), trust: trust(phones), now: now())
        XCTAssertEqual(away.delivery, delivery)
        XCTAssertEqual(away.update.dispatched, [delivery])
        let duplicate = try session.beginDelivery(id: delivery.id, current: request(), routing: route(.away), trust: trust(phones), now: now())
        XCTAssertNil(duplicate.delivery)
        XCTAssertEqual(try reconcile(session, mode: .present, phones: phones).dispatched, [delivery])
    }

    func testDelayedDispatchRechecksExpiryRevocationAndConsumption() throws {
        for variant in 0..<3 {
            let session = try PendingRequestDelivery(request: request()), phones = try [phone(5)]
            let delivery = try XCTUnwrap(reconcile(session, phones: phones).active.first)
            let attempt = try session.beginDelivery(id: delivery.id, current: request(phase: variant == 2 ? .authorized : .queued),
                routing: route(.away), trust: trust(variant == 1 ? [] : phones), now: now(variant == 0 ? 200 : 110))
            XCTAssertNil(attempt.delivery)
            XCTAssertEqual(attempt.update.withdrawn, [delivery])
            XCTAssertTrue(attempt.update.dispatched.isEmpty)
        }
    }

    func testInvalidAdmissionAndCapacityAreRejected() throws {
        XCTAssertThrowsError(try PendingRequestDelivery(request: request(phase: .authorized)))
        for capacity in [0, 1025] { XCTAssertThrowsError(try PendingRequestDelivery(request: request(), maximumRecipients: capacity)) }
    }
}
