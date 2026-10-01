import Foundation
import XCTest
@testable import RemozioCore

final class PresenceRouterTests: XCTestCase {
    private let epoch = UUID()
    private func moment(_ time: UInt64, epoch: UUID? = nil) -> PresenceMoment { .init(epoch: epoch ?? self.epoch, milliseconds: time) }
    private func observation<T: Sendable>(_ value: T, _ time: UInt64) -> PresenceObservation<T> { .init(value, observedAt: moment(time)) }
    private func router(grace: UInt64 = 5_000) throws -> PresenceRouter {
        PresenceRouter(configuration: try .init(observationLifetimeMilliseconds: 10_000, unavailableGraceMilliseconds: grace))
    }
    private func snapshot(_ time: UInt64, input: UInt64? = nil) -> PresenceSnapshot {
        .init(remoteWorkspace: observation(.notUsable, time), locked: observation(false, time),
              displays: observation([.awake(.readable)], time), lastQualifyingInputMilliseconds: observation(input ?? time, time))
    }

    func testManualModesWinWithoutSignalsAndDoNotExpire() throws {
        var router = try router()
        for time in [UInt64(0), 1_000_000, UInt64.max] {
            XCTAssertEqual(router.evaluate(mode: .present, snapshot: .init(), now: moment(time)),
                           PresenceRouting(destination: .localMac, reason: .manualPresent, detectionLimited: false))
            XCTAssertEqual(router.evaluate(mode: .away, snapshot: snapshot(time), now: moment(time)),
                           PresenceRouting(destination: .phones, reason: .manualAway, detectionLimited: false))
        }
    }

    func testUsableRemoteSessionWinsOverLockDarkAndIdle() throws {
        var router = try router()
        var sample = snapshot(200_000, input: 0)
        sample.remoteWorkspace = observation(.usable, 200_000)
        sample.locked = observation(true, 200_000)
        sample.displays = observation([.asleep, .awake(.dark)], 200_000)
        let result = router.evaluate(mode: .automatic, snapshot: sample, now: moment(200_000))
        XCTAssertEqual(result.destination, .localMac)
        XCTAssertEqual(result.reason, .remoteDesktop)
        XCTAssertEqual(router.evaluate(mode: .away, snapshot: sample, now: moment(200_001)).destination, .phones)
    }

    func testDisconnectStaleAndFutureRemoteObservationsCannotKeepLockedMacPresent() throws {
        for remote in [observation(RemoteWorkspace.notUsable, 20_000), observation(.usable, 10_000), observation(.usable, 20_001)] {
            var router = try router()
            var sample = snapshot(20_000)
            sample.remoteWorkspace = remote
            sample.locked = observation(true, 20_000)
            let result = router.evaluate(mode: .automatic, snapshot: sample, now: moment(20_000))
            XCTAssertEqual(result.destination, .phones)
            XCTAssertEqual(result.reason, .locked)
        }
    }

    func testMultiDisplayBrightnessAndLidClosedCases() throws {
        let cases: [([DisplayPresence], RequestDestination, PresenceReason)] = [
            ([.awake(.dark), .awake(.readable)], .localMac, .active),
            ([.asleep, .awake(.readable)], .localMac, .active),
            ([.awake(.unknown)], .localMac, .active),
            ([.awake(.dark), .asleep], .phones, .displaysDark),
            ([.asleep, .asleep], .phones, .displaysOff),
            ([], .phones, .displaysOff),
            ([.awake(.dark), .unknown], .phones, .detectorUnavailable),
            ([.unknown], .phones, .detectorUnavailable),
        ]
        for (displays, destination, reason) in cases {
            var router = try router()
            var sample = snapshot(100)
            sample.displays = observation(displays, 100)
            let result = router.evaluate(mode: .automatic, snapshot: sample, now: moment(100))
            XCTAssertEqual(result.destination, destination)
            XCTAssertEqual(result.reason, reason)
        }
    }

    func testIdleBoundaryAndConfiguredInterval() throws {
        var router = try router()
        XCTAssertEqual(router.evaluate(mode: .automatic, snapshot: snapshot(119_999, input: 0), now: moment(119_999)).reason, .active)
        XCTAssertEqual(router.evaluate(mode: .automatic, snapshot: snapshot(120_000, input: 0), now: moment(120_000)).reason, .idle)
        var custom = PresenceRouter(configuration: try .init(idleMilliseconds: 1_000, observationLifetimeMilliseconds: 100, unavailableGraceMilliseconds: 0))
        XCTAssertEqual(custom.evaluate(mode: .automatic, snapshot: snapshot(1_000, input: 0), now: moment(1_000)).reason, .idle)
    }

    func testUnavailableGraceDoesNotResetOnRepeatedEvaluation() throws {
        var router = try router()
        _ = router.evaluate(mode: .automatic, snapshot: snapshot(0), now: moment(0))
        XCTAssertEqual(router.evaluate(mode: .automatic, snapshot: .init(), now: moment(1_000)),
                       PresenceRouting(destination: .localMac, reason: .detectorUnavailable, detectionLimited: true))
        XCTAssertEqual(router.evaluate(mode: .automatic, snapshot: .init(), now: moment(5_999)).destination, .localMac)
        XCTAssertEqual(router.evaluate(mode: .automatic, snapshot: .init(), now: moment(6_000)).destination, .phones)
        XCTAssertEqual(router.evaluate(mode: .automatic, snapshot: .init(), now: moment(9_000)).destination, .phones)
        XCTAssertEqual(router.evaluate(mode: .automatic, snapshot: snapshot(10_000), now: moment(10_000)).destination, .localMac)
        XCTAssertEqual(router.evaluate(mode: .automatic, snapshot: .init(), now: moment(11_000)).destination, .localMac)
    }

    func testDelayedEvaluationCannotRenewExpiredObservationGrace() throws {
        var router = try router()
        _ = router.evaluate(mode: .automatic, snapshot: snapshot(0), now: moment(9_999))
        XCTAssertEqual(router.evaluate(mode: .automatic, snapshot: .init(), now: moment(14_999)).destination, .localMac)
        XCTAssertEqual(router.evaluate(mode: .automatic, snapshot: .init(), now: moment(15_000)).destination, .phones)
        var delayed = try self.router()
        _ = delayed.evaluate(mode: .automatic, snapshot: snapshot(0), now: moment(0))
        XCTAssertEqual(delayed.evaluate(mode: .automatic, snapshot: .init(), now: moment(60_000)).destination, .phones)
    }

    func testUnknownAtStartupAndZeroGraceUsePhones() throws {
        var startup = try router()
        XCTAssertEqual(startup.evaluate(mode: .automatic, snapshot: .init(), now: moment(0)).destination, .phones)
        var immediate = try router(grace: 0)
        _ = immediate.evaluate(mode: .automatic, snapshot: snapshot(0), now: moment(0))
        XCTAssertEqual(immediate.evaluate(mode: .automatic, snapshot: .init(), now: moment(1)).destination, .phones)
    }

    func testClockEpochAndRegressionDiscardCachedRoute() throws {
        var router = try router()
        _ = router.evaluate(mode: .automatic, snapshot: snapshot(100), now: moment(100))
        XCTAssertEqual(router.evaluate(mode: .automatic, snapshot: snapshot(50), now: moment(50)).reason, .detectorUnavailable)
        XCTAssertEqual(router.evaluate(mode: .automatic, snapshot: snapshot(51), now: moment(51)).destination, .localMac)
        let result = router.evaluate(mode: .automatic, snapshot: snapshot(52), now: moment(52, epoch: UUID()))
        XCTAssertEqual(result.destination, .phones)
        XCTAssertEqual(result.reason, .detectorUnavailable)
    }

    func testStaleLocalAndInvalidInputTimestampsAreUnknown() throws {
        for sample in [snapshot(0), snapshot(20_000, input: 20_001)] {
            var router = try router()
            XCTAssertEqual(router.evaluate(mode: .automatic, snapshot: sample, now: moment(20_000)).reason, .detectorUnavailable)
        }
    }

    func testUnsupportedRemoteDetectionUsesLocalSignalsWithLimitation() throws {
        var router = try router()
        var sample = snapshot(0)
        sample.remoteWorkspace = observation(.unsupported, 0)
        let result = router.evaluate(mode: .automatic, snapshot: sample, now: moment(0))
        XCTAssertEqual(result.destination, .localMac)
        XCTAssertEqual(result.reason, .active)
        XCTAssertTrue(result.detectionLimited)
    }

    func testConfigurationRejectsZeroIdleAndFreshness() {
        XCTAssertThrowsError(try PresenceConfiguration(idleMilliseconds: 0, observationLifetimeMilliseconds: 1, unavailableGraceMilliseconds: 1))
        XCTAssertThrowsError(try PresenceConfiguration(observationLifetimeMilliseconds: 0, unavailableGraceMilliseconds: 1))
    }
}
