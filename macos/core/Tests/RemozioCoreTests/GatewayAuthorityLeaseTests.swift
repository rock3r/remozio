import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class GatewayAuthorityLeaseTests: XCTestCase {
    private final class Clock: Sendable {
        let epoch = UUID()
        let value = Mutex<UInt64>(100)
        func now() -> AuthorityMoment { value.withLock { AuthorityMoment(epoch: epoch, milliseconds: $0) } }
    }
    func testLeaseExpiresAndOnlyFreshSameIncarnationCanRenew() throws {
        let clock = Clock(), root = UUID()
        let lease = try GatewayAuthorityLease(epoch: clock.epoch, maximumLifetime: 1000, sample: clock.now)
        XCTAssertThrowsError(try lease.validate())
        try lease.renew(rootEpoch: root, sequence: 1, observedAt: 90, deadline: 110)
        try lease.validate()
        clock.value.withLock { $0 = 110 }
        XCTAssertThrowsError(try lease.validate())
        XCTAssertThrowsError(try lease.renew(rootEpoch: root, sequence: 1, observedAt: 110, deadline: 120))
        XCTAssertThrowsError(try lease.renew(rootEpoch: UUID(), sequence: 2, observedAt: 110, deadline: 120))
        try lease.renew(rootEpoch: root, sequence: 2, observedAt: 110, deadline: 120)
        try lease.validate()
        lease.retire()
        XCTAssertThrowsError(try lease.renew(rootEpoch: root, sequence: 3, observedAt: 110, deadline: 130))
        XCTAssertThrowsError(try lease.validate())
    }
    func testRejectsFutureExpiredExcessiveAndOverflowedTimes() throws {
        let clock = Clock(), root = UUID()
        for (observed, deadline): (UInt64, UInt64) in [(101, 110), (90, 100), (90, 1091), (UInt64.max, 1)] {
            let lease = try GatewayAuthorityLease(epoch: clock.epoch, maximumLifetime: 1000, sample: clock.now)
            XCTAssertThrowsError(try lease.renew(rootEpoch: root, sequence: 1, observedAt: observed, deadline: deadline))
            XCTAssertThrowsError(try lease.validate())
        }
    }
    func testClockRegressionPermanentlyRetiresLease() throws {
        let clock = Clock(), root = UUID()
        let lease = try GatewayAuthorityLease(epoch: clock.epoch, maximumLifetime: 1000, sample: clock.now)
        try lease.renew(rootEpoch: root, sequence: 1, observedAt: 90, deadline: 110)
        clock.value.withLock { $0 = 99 }
        XCTAssertThrowsError(try lease.validate())
        clock.value.withLock { $0 = 101 }
        XCTAssertThrowsError(try lease.renew(rootEpoch: root, sequence: 2, observedAt: 101, deadline: 120))
    }
    func testEpochTranslationPreservesRequestExpiryAndRejectsOtherRootIncarnations() throws {
        let clock = Clock(), root = UUID()
        let lease = try GatewayAuthorityLease(epoch: clock.epoch, maximumLifetime: 1000, sample: clock.now)
        try lease.renew(rootEpoch: root, sequence: 1, observedAt: 90, deadline: 500)
        func delivery(epoch: UUID = root) -> PhoneRequestDelivery {
            PhoneRequestDelivery(id: UUID(), recipient: DeliveryRecipient(phoneID: Data(repeating: 1, count: 16),
                enrollmentEpoch: Data(repeating: 2, count: 16)), requestID: Data(repeating: 3, count: 16),
                admittedAt: AuthorityMoment(epoch: epoch, milliseconds: 90), deadlineMilliseconds: 110)
        }
        let original = delivery(), translated = try lease.normalize(original)
        XCTAssertEqual(translated.id, original.id)
        XCTAssertEqual(translated.admittedAt.epoch, clock.epoch)
        XCTAssertEqual(translated.admittedAt.milliseconds, 90)
        XCTAssertEqual(translated.deadlineMilliseconds, 110)
        XCTAssertThrowsError(try lease.normalize(delivery(epoch: UUID())))
        clock.value.withLock { $0 = 110 }
        try lease.renew(rootEpoch: root, sequence: 2, observedAt: 110, deadline: 600)
        XCTAssertThrowsError(try lease.normalize(original))
    }
}
