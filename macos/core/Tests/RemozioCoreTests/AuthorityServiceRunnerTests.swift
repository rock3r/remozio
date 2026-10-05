import Foundation
import SQLite3
import XCTest
@testable import RemozioCore

final class AuthorityServiceRunnerTests: XCTestCase {
    func testRetryBoundsAndCloseBeforeStart() throws {
        for (initial, maximum) in [(0, 1000), (99, 1000), (60_001, 100_000), (1000, 999), (1000, 300_001)] {
            XCTAssertThrowsError(try AuthorityServiceRunner(initialRetryMilliseconds: initial,
                maximumRetryMilliseconds: maximum, open: { XCTFail("Invalid runner opened"); return {} }, report: { _ in }))
        }
        let runner = try AuthorityServiceRunner(initialRetryMilliseconds: 100, maximumRetryMilliseconds: 100,
            open: { XCTFail("Closed runner opened"); return {} }, report: { _ in })
        XCTAssertEqual(runner.status, .idle)
        try runner.close(); try runner.close()
        XCTAssertEqual(runner.status, .closed)
        XCTAssertThrowsError(try runner.start())
    }

    func testTransientFailuresRetryWithCappedBackoffThenOwnOneService() throws {
        let probe = Probe(), running = expectation(description: "running")
        let runner = try AuthorityServiceRunner(initialRetryMilliseconds: 100, maximumRetryMilliseconds: 200, open: {
            switch probe.open() {
            case 1: throw JournalLeaseError.busy
            case 2: throw ContinuityStoreError.storage(SQLITE_BUSY)
            case 3: throw JournalDatabaseError.storage(SQLITE_IOERR)
            case 4: throw AuditJournalError.storage(SQLITE_FULL)
            default: return { probe.close() }
            }
        }, report: {
            probe.record($0)
            if $0 == .running { running.fulfill() }
        })
        try runner.start()
        XCTAssertThrowsError(try runner.start())
        wait(for: [running], timeout: 3)
        XCTAssertEqual(runner.status, .running)
        XCTAssertEqual(probe.statuses.compactMap { status -> Int? in
            if case .waiting(let delay) = status { return delay }; return nil
        }, [100, 200, 200, 200])
        try runner.close(); try runner.close()
        XCTAssertEqual(probe.counts.opens, 5)
        XCTAssertEqual(probe.counts.closes, 1)
        XCTAssertEqual(runner.status, .closed)
    }

    func testPermanentAndHistoryFailuresDoNotScheduleRetries() throws {
        let failures: [any Error] = [JournalDatabaseError.wrongScope, ContinuityStoreError.incompatibleStore,
            JournalLeaseError.unsafeMetadata, AuthorityStorageStartupError.historyRecoveryRequired,
            AuthorityStorageStartupError.repairRequired]
        for failure in failures {
            let probe = Probe(), failed = expectation(description: "terminal failure")
            let repeated = expectation(description: "no repeated attempt")
            repeated.isInverted = true
            let runner = try AuthorityServiceRunner(initialRetryMilliseconds: 100, maximumRetryMilliseconds: 100, open: {
                if probe.open() > 1 { repeated.fulfill() }
                throw failure
            }, report: { if case .failed = $0 { failed.fulfill() } })
            try runner.start()
            wait(for: [failed], timeout: 2)
            wait(for: [repeated], timeout: 0.2)
            XCTAssertEqual(runner.status, .failed(AuthorityStartupFailure(error: failure)))
            XCTAssertThrowsError(try runner.start())
            try runner.close()
            XCTAssertEqual(probe.counts.opens, 1)
        }
    }

    func testCloseCancelsScheduledRetry() throws {
        let probe = Probe(), waiting = expectation(description: "retry scheduled")
        let repeated = expectation(description: "cancelled retry")
        repeated.isInverted = true
        let runner = try AuthorityServiceRunner(initialRetryMilliseconds: 200, maximumRetryMilliseconds: 200, open: {
            if probe.open() > 1 { repeated.fulfill() }
            throw JournalLeaseError.busy
        }, report: { if case .waiting = $0 { waiting.fulfill() } })
        try runner.start()
        wait(for: [waiting], timeout: 2)
        try runner.close()
        wait(for: [repeated], timeout: 0.4)
        XCTAssertEqual(probe.counts.opens, 1)
        XCTAssertEqual(runner.status, .closed)
    }

    func testCloseWaitsForFactoryAndDisposesItsResultWithoutReportingRunning() throws {
        let probe = Probe(), entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
        let closing = DispatchSemaphore(value: 0), closed = DispatchSemaphore(value: 0)
        let runner = try AuthorityServiceRunner(initialRetryMilliseconds: 100, maximumRetryMilliseconds: 100, open: {
            _ = probe.open(); entered.signal()
            guard release.wait(timeout: .now() + 5) == .success else { throw JournalLeaseError.busy }
            return { probe.close() }
        }, report: { probe.record($0) })
        try runner.start()
        XCTAssertEqual(entered.wait(timeout: .now() + 2), .success)
        DispatchQueue.global().async {
            closing.signal()
            do { try runner.close() } catch { XCTFail("Close failed") }
            closed.signal()
        }
        XCTAssertEqual(closing.wait(timeout: .now() + 2), .success)
        XCTAssertEqual(closed.wait(timeout: .now() + 0.05), .timedOut)
        release.signal()
        XCTAssertEqual(closed.wait(timeout: .now() + 2), .success)
        XCTAssertFalse(probe.statuses.contains(.running))
        XCTAssertEqual(probe.counts.opens, 1)
        XCTAssertEqual(probe.counts.closes, 1)
        XCTAssertEqual(runner.status, .closed)
    }

    func testFailedShutdownCanBeRetriedWithoutOpeningAnotherService() throws {
        let probe = Probe(), running = expectation(description: "running")
        let runner = try AuthorityServiceRunner(initialRetryMilliseconds: 100, maximumRetryMilliseconds: 100, open: {
            _ = probe.open()
            return { if probe.close() == 1 { throw JournalDatabaseError.transactionActive } }
        }, report: { if $0 == .running { running.fulfill() } })
        try runner.start()
        wait(for: [running], timeout: 2)
        XCTAssertThrowsError(try runner.close())
        XCTAssertThrowsError(try runner.start())
        try runner.close()
        XCTAssertEqual(probe.counts.opens, 1)
        XCTAssertEqual(probe.counts.closes, 2)
    }

    private final class Probe: @unchecked Sendable {
        private let lock = NSLock()
        private var opens = 0, closes = 0
        private var events: [AuthorityServiceRunner.Status] = []
        func open() -> Int { lock.withLock { opens += 1; return opens } }
        @discardableResult func close() -> Int { lock.withLock { closes += 1; return closes } }
        func record(_ status: AuthorityServiceRunner.Status) { lock.withLock { events.append(status) } }
        var counts: (opens: Int, closes: Int) { lock.withLock { (opens, closes) } }
        var statuses: [AuthorityServiceRunner.Status] { lock.withLock { events } }
    }
}
