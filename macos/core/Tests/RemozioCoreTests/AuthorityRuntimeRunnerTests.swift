import Foundation
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

final class AuthorityRuntimeRunnerTests: XCTestCase, @unchecked Sendable {
    private actor Probe {
        var opens = 0
        var starts = 0
        var closes = 0
        var retired = false
        var failClose = false
        var failStart = false
        func open() -> Int { opens += 1; return opens }
        func setRetired() { retired = true }
        func setFailures(start: Bool = false, close: Bool = false) { failStart = start; failClose = close }
        func start() throws { starts += 1; if failStart { throw JournalLeaseError.busy } }
        func close() throws {
            closes += 1
            if failClose { failClose = false; throw JournalDatabaseError.transactionActive }
        }
        func snapshot() -> (Int, Int, Int) { (opens, starts, closes) }
        nonisolated var instance: AuthorityRuntimeInstance {
            .init(start: { try await self.start() }, close: { try await self.close() }, retired: { await self.retired })
        }
    }
    private actor Gate {
        var entered = false
        private var continuation: CheckedContinuation<Void, Never>?
        func hold() async { await withCheckedContinuation { entered = true; continuation = $0 } }
        func release() { continuation?.resume(); continuation = nil }
    }
    private func waitUntil(_ condition: () async -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(3))
        while !(await condition()) {
            guard ContinuousClock.now < deadline else { throw GatewayRootChannelError.timedOut }
            try await Task.sleep(for: .milliseconds(5))
        }
    }
    func testBoundsAndCloseBeforeStart() async throws {
        for (initial, maximum) in [(0, 100), (99, 1000), (60_001, 100_000), (1000, 999), (1000, 300_001)] {
            XCTAssertThrowsError(try AuthorityRuntimeRunner(initialRetryMilliseconds: initial, maximumRetryMilliseconds: maximum,
                open: { XCTFail("Invalid runner opened"); throw JournalLeaseError.busy }, report: { _ in }))
        }
        let probe = Probe(), runner = try AuthorityRuntimeRunner(open: { _ = await probe.open(); return probe.instance }, report: { _ in })
        try await runner.close(); try await runner.close()
        do { try await runner.start(); XCTFail("Closed runner started") } catch {}
        let counts = await probe.snapshot(); XCTAssertEqual(counts.0, 0)
        XCTAssertEqual(runner.status, .closed)
    }
    func testTransientStartupReloadsAndCapsRetryBeforeStartingOneRuntime() async throws {
        let probe = Probe(), statuses = Mutex<[AuthorityRuntimeRunner.Status]>([])
        let runner = try AuthorityRuntimeRunner(initialRetryMilliseconds: 100, maximumRetryMilliseconds: 200, open: {
            let attempt = await probe.open()
            if attempt <= 3 { throw JournalLeaseError.busy }
            return probe.instance
        }, report: { status in statuses.withLock { $0.append(status) } })
        try await runner.start()
        try await waitUntil { runner.status == .running }
        XCTAssertEqual(statuses.withLock { values in values.compactMap { value -> Int? in
            if case .waiting(let delay) = value { return delay }; return nil
        } }, [100, 200, 200])
        do { try await runner.start(); XCTFail("Runner started twice") } catch {}
        try await runner.close()
        let counts = await probe.snapshot()
        XCTAssertEqual(counts.0, 4); XCTAssertEqual(counts.1, 1); XCTAssertEqual(counts.2, 1)
    }
    func testPermanentConfigurationAndHistoryErrorsDoNotRetry() async throws {
        for failure in [AuthorityStartupFailure.configurationFailure, .historyRecoveryRequired, .repairRequired] {
            let probe = Probe()
            let runner = try AuthorityRuntimeRunner(initialRetryMilliseconds: 100, maximumRetryMilliseconds: 100, open: {
                _ = await probe.open()
                switch failure {
                case .historyRecoveryRequired: throw AuthorityStorageStartupError.historyRecoveryRequired
                case .repairRequired: throw AuthorityStorageStartupError.repairRequired
                default: throw JournalDatabaseError.wrongScope
                }
            }, report: { _ in })
            try await runner.start()
            try await waitUntil { runner.status == .failed(failure) }
            try await Task.sleep(for: .milliseconds(150))
            try await runner.close()
            let counts = await probe.snapshot(); XCTAssertEqual(counts.0, 1); XCTAssertEqual(counts.1, 0)
        }
    }
    func testCloseWhileOpeningOwnsReturnedRuntimeWithoutStartingIt() async throws {
        let probe = Probe(), gate = Gate(), statuses = Mutex<[AuthorityRuntimeRunner.Status]>([])
        let runner = try AuthorityRuntimeRunner(open: {
            _ = await probe.open(); await gate.hold(); return probe.instance
        }, report: { status in statuses.withLock { $0.append(status) } })
        try await runner.start()
        try await waitUntil { await gate.entered }
        let closing = Task { try await runner.close() }
        try await Task.sleep(for: .milliseconds(30))
        XCTAssertEqual(runner.status, .starting)
        await gate.release(); try await closing.value
        let counts = await probe.snapshot(); XCTAssertEqual(counts.1, 0); XCTAssertEqual(counts.2, 1)
        XCTAssertFalse(statuses.withLock { $0.contains(.running) })
        XCTAssertEqual(runner.status, .closed)
    }
    func testFailedStartAndCleanupRetainRuntimeWithoutAnotherOpen() async throws {
        let probe = Probe(); await probe.setFailures(start: true, close: true)
        let runner = try AuthorityRuntimeRunner(initialRetryMilliseconds: 100, maximumRetryMilliseconds: 100,
            open: { _ = await probe.open(); return probe.instance }, report: { _ in })
        try await runner.start()
        try await waitUntil { runner.status == .shutdownFailed }
        try await Task.sleep(for: .milliseconds(150))
        try await runner.close()
        let counts = await probe.snapshot()
        XCTAssertEqual(counts.0, 1); XCTAssertEqual(counts.1, 1); XCTAssertEqual(counts.2, 2)
    }
    func testFailedCloseCanRetryAndSuccessfulCloseIsIdempotent() async throws {
        let probe = Probe()
        let runner = try AuthorityRuntimeRunner(open: { _ = await probe.open(); return probe.instance }, report: { _ in })
        try await runner.start(); try await waitUntil { runner.status == .running }
        await probe.setFailures(close: true)
        do { try await runner.close(); XCTFail("Cleanup failure hidden") } catch {}
        XCTAssertEqual(runner.status, .shutdownFailed)
        try await runner.close(); try await runner.close()
        let counts = await probe.snapshot(); XCTAssertEqual(counts.0, 1); XCTAssertEqual(counts.2, 2)
        XCTAssertEqual(runner.status, .closed)
    }
    func testRetiredRuntimeClosesAndDoesNotReopen() async throws {
        let probe = Probe()
        let runner = try AuthorityRuntimeRunner(monitorMilliseconds: 10,
            open: { _ = await probe.open(); return probe.instance }, report: { _ in })
        try await runner.start(); try await waitUntil { runner.status == .running }
        await probe.setRetired()
        try await waitUntil { runner.status == .retired }
        try await runner.close()
        let counts = await probe.snapshot(); XCTAssertEqual(counts.0, 1); XCTAssertEqual(counts.2, 1)
    }
    func testAlreadyRetiredRuntimeNeverReportsRunning() async throws {
        let probe = Probe(), statuses = Mutex<[AuthorityRuntimeRunner.Status]>([])
        await probe.setRetired()
        let runner = try AuthorityRuntimeRunner(open: {
            _ = await probe.open()
            return probe.instance
        }, report: { status in statuses.withLock { $0.append(status) } })
        try await runner.start()
        try await waitUntil { runner.status == .retired }
        try await runner.close()
        XCTAssertFalse(statuses.withLock { $0.contains(.running) })
        let counts = await probe.snapshot()
        XCTAssertEqual(counts.0, 1)
        XCTAssertEqual(counts.2, 1)
    }
    func testConcurrentCloseSharesCleanup() async throws {
        let probe = Probe(), gate = Gate()
        let runner = try AuthorityRuntimeRunner(open: {
            _ = await probe.open()
            return AuthorityRuntimeInstance(start: { try await probe.start() }, close: {
                await gate.hold()
                try await probe.close()
            }, retired: { await probe.retired })
        }, report: { _ in })
        try await runner.start()
        try await waitUntil { runner.status == .running }
        let first = Task { try await runner.close() }
        try await waitUntil { await gate.entered }
        let second = Task { try await runner.close() }
        await gate.release()
        try await first.value
        try await second.value
        XCTAssertEqual(runner.status, .closed)
        let counts = await probe.snapshot()
        XCTAssertEqual(counts.0, 1)
        XCTAssertEqual(counts.2, 1)
    }
    func testReleaseCancelsWorkerAndClosesOwnedRuntime() async throws {
        let probe = Probe()
        var runner: AuthorityRuntimeRunner? = try AuthorityRuntimeRunner(open: { _ = await probe.open(); return probe.instance }, report: { _ in })
        try await runner?.start()
        try await waitUntil { runner?.status == .running }
        runner = nil
        try await waitUntil { await probe.snapshot().2 == 1 }
    }
    func testExpirationPolicyAcceptsOwnedCommandsAndRejectsUnattachedAdapters() throws {
        func state(kind: RequestKind, phase: RequestPhase = .expired, reason: RequestStatusReason = .authorizationExpired) -> ApprovalRequestState {
            let now = AuthorityMoment(epoch: UUID(), milliseconds: 100)
            return .init(requestKind: kind, macID: Data(), accountID: Data(), requestDigest: Data(), challenge: Data(),
                reason: reason, terminalAt: now, decisionPhoneID: nil, requestID: Data(), phase: phase,
                revision: 1, firstObservedAt: now, deadlineMilliseconds: 100)
        }
        for reason in [RequestStatusReason.authorizationExpired, .targetTimedOut] {
            XCTAssertNoThrow(try AuthorityRuntimeRunner.reconcileCoordinatorExpiration([state(kind: .command, reason: reason)]))
        }
        for kind in [RequestKind.onePasswordAccess, .onePasswordUnlock, .littleSnitch] {
            XCTAssertThrowsError(try AuthorityRuntimeRunner.reconcileCoordinatorExpiration([state(kind: kind)]))
        }
        XCTAssertThrowsError(try AuthorityRuntimeRunner.reconcileCoordinatorExpiration([state(kind: .command, phase: .queued)]))
    }
}
