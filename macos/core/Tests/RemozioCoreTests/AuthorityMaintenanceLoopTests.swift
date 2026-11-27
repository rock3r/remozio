import Foundation
import XCTest
@testable import RemozioCore

final class AuthorityMaintenanceLoopTests: XCTestCase {
    private enum Failure: Error { case injected }
    func testBoundsAndCloseBeforeStart() throws {
        for interval in [0, 99, 60_001] {
            XCTAssertThrowsError(try AuthorityMaintenanceLoop(intervalMilliseconds: interval, work: {}, failed: {}))
        }
        let loop = try AuthorityMaintenanceLoop(intervalMilliseconds: 100, work: { XCTFail("Closed timer ran") }, failed: {})
        loop.close(); loop.close()
        XCTAssertThrowsError(try loop.start())
    }
    func testDelayedMaintenanceUsesTheFirstIntervalForEachNewOwner() throws {
        for _ in 0..<2 {
            let tick = expectation(description: "first delayed callback")
            let start = DispatchTime.now().uptimeNanoseconds
            let loop = try AuthorityMaintenanceLoop(intervalMilliseconds: 100, runImmediately: false, work: {
                XCTAssertGreaterThanOrEqual(DispatchTime.now().uptimeNanoseconds - start, 90_000_000)
                tick.fulfill()
                throw Failure.injected
            }, failed: {})
            try loop.start()
            wait(for: [tick], timeout: 2)
            loop.close()
            XCTAssertThrowsError(try loop.start())
        }
    }

    func testFailureRunsOnceAndRetiresTimer() throws {
        let failure = expectation(description: "failure callback")
        failure.assertForOverFulfill = true
        let work = expectation(description: "work callback")
        work.assertForOverFulfill = true
        let loop = try AuthorityMaintenanceLoop(intervalMilliseconds: 100,
            work: { work.fulfill(); throw Failure.injected }, failed: { failure.fulfill() })
        try loop.start()
        wait(for: [work, failure], timeout: 2)
        XCTAssertThrowsError(try loop.start())
        loop.close()
    }
    func testCloseWaitsForActiveWorkAndPreventsSubsequentTicks() throws {
        let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
        let attempted = DispatchSemaphore(value: 0), finished = DispatchSemaphore(value: 0)
        let work = expectation(description: "one callback")
        work.assertForOverFulfill = true
        let loop = try AuthorityMaintenanceLoop(intervalMilliseconds: 100, work: {
            work.fulfill(); entered.signal()
            guard release.wait(timeout: .now() + 5) == .success else { throw Failure.injected }
        }, failed: { XCTFail("Unexpected failure") })
        try loop.start()
        XCTAssertEqual(entered.wait(timeout: .now() + 2), .success)
        DispatchQueue.global().async { attempted.signal(); loop.close(); finished.signal() }
        XCTAssertEqual(attempted.wait(timeout: .now() + 2), .success)
        XCTAssertEqual(finished.wait(timeout: .now() + 0.05), .timedOut)
        release.signal()
        XCTAssertEqual(finished.wait(timeout: .now() + 2), .success)
        wait(for: [work], timeout: 1)
        XCTAssertThrowsError(try loop.start())
    }
}
