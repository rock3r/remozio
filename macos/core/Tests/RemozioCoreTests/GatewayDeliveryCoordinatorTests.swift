import CryptoKit
import Darwin
import Foundation
import Synchronization
import XCTest
import RemozioProtocol
@testable import RemozioCore

final class GatewayDeliveryCoordinatorTests: XCTestCase, @unchecked Sendable {
    private enum Failure: Error { case injected }
    private func id(_ n: UInt8, _ count: Int = 16) -> Data { Data(repeating: n, count: count) }
    private final class Clock: Sendable {
        let epoch = UUID()
        let value = Mutex<UInt64>(100)
        func sample() -> GatewayDeliveryCoordinator.Sample {
            value.withLock { .init(wall: 1000 + $0 - 100, moment: AuthorityMoment(epoch: epoch, milliseconds: $0)) }
        }
        func advance(_ amount: UInt64) { value.withLock { $0 += amount } }
    }
    private actor Provider {
        var results: [FCMDeliveryResult]
        private(set) var times: [UInt64] = []
        private var holding = false
        private var honorCancellation = true
        private var failures = 0
        private var pending: [Int: CheckedContinuation<FCMDeliveryResult, any Error>] = [:]
        init(_ results: [FCMDeliveryResult]) { self.results = results }
        func hold(honorCancellation: Bool = true) { holding = true; self.honorCancellation = honorCancellation }
        func failNext() { failures += 1 }
        func send(at time: UInt64) async throws -> FCMDeliveryResult {
            times.append(time)
            if failures > 0 { failures -= 1; throw FCMError.network }
            guard holding else { return results.isEmpty ? .accepted : results.removeFirst() }
            let id = times.count
            return try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { continuation in
                    if Task.isCancelled && honorCancellation { continuation.resume(throwing: CancellationError()) }
                    else { pending[id] = continuation }
                }
            } onCancel: { Task { await self.cancel(id) } }
        }
        private func cancel(_ id: Int) {
            if honorCancellation { pending.removeValue(forKey: id)?.resume(throwing: CancellationError()) }
        }
        func release() {
            holding = false
            let values = pending.values; pending = [:]
            for continuation in values { continuation.resume(returning: .accepted) }
        }
    }
    private actor OAuthGate {
        private(set) var started = false
        private var continuation: CheckedContinuation<FCMTokenLease, any Error>?
        func refresh() async throws -> FCMTokenLease {
            started = true
            return try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { continuation in
                    if Task.isCancelled { continuation.resume(throwing: CancellationError()) }
                    else { self.continuation = continuation }
                }
            } onCancel: { Task { await self.cancel() } }
        }
        func cancel() { continuation?.resume(throwing: CancellationError()); continuation = nil }
        func release() throws {
            continuation?.resume(returning: FCMTokenLease(value: try FCMAccessToken("synthetic"), expiresAt: .now.advanced(by: .seconds(3600))))
            continuation = nil
        }
    }
    private final class Counter: Sendable { let value = Mutex(0) }
    private final class Fixture {
        let root: URL
        let key = P256.Signing.PrivateKey()
        let clock = Clock()
        let refreshes = Counter()
        init() throws {
            guard geteuid() != 0 else { throw XCTSkip("Requires an unprivileged fixture") }
            guard let path = realpath(FileManager.default.temporaryDirectory.path, nil) else { throw GatewayDatabaseError.storage(errno) }
            defer { free(path) }
            root = URL(fileURLWithPath: String(cString: path)).appendingPathComponent(UUID().uuidString)
            try FileManager.default.createDirectory(at: root.appendingPathComponent("store"), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            for name in ["writer.lock", "gateway.sqlite"] {
                let fd = Darwin.open(root.appendingPathComponent("store/" + name).path, O_CREAT | O_EXCL | O_WRONLY, 0o600)
                guard fd >= 0 else { throw GatewayDatabaseError.storage(errno) }; Darwin.close(fd)
            }
        }
        deinit { try? FileManager.default.removeItem(at: root) }
        func id(_ n: UInt8, _ count: Int = 16) -> Data { Data(repeating: n, count: count) }
        func identity() throws -> GatewayRegistrationIdentity {
            try .init(ownerID: id(1), macID: id(2), accountID: id(3), gatewayID: id(4), lifecycleEpoch: id(5), rootPublicKey: key.publicKey.x963Representation)
        }
        func enrollment(active: Bool = true) throws -> GatewayPhoneEnrollment {
            try .init(phoneID: id(6), epoch: id(7), tag: id(6, 32), active: active)
        }
        func coordinator(_ provider: Provider, attempts: Int = 3, lifetime: UInt64 = 10_000, tokenSource: FCMTokenSource? = nil, sender: FCMWakeSender? = nil, retryBase: UInt64 = 1, retryCap: UInt64 = 1, coordinatorIdentity: GatewayRegistrationIdentity? = nil) throws -> GatewayDeliveryCoordinator {
            let clock = clock, refreshes = refreshes
            let source = try tokenSource ?? FCMTokenSource(now: { .now }, refresh: {
                refreshes.value.withLock { $0 += 1 }
                return FCMTokenLease(value: try FCMAccessToken("synthetic"), expiresAt: .now.advanced(by: .seconds(3600)))
            })
            let limits = try CBORLimits(maxBytes: 2048, maxDepth: 8, maxItems: 128)
            let db = try GatewayDatabase(lease: ProtectedGatewayLease(anchor: root.path, relativeDirectory: "store", serviceUID: geteuid(), ancestorUID: geteuid()),
                identity: identity(), payloadLimits: limits, signingLimits: limits, maximumOperations: 20,
                maximumPendingPerEnrollment: 5, maximumLifetimeMillis: lifetime, clockEpoch: clock.epoch, busyMilliseconds: 100,
                initialize: true, probePolicy: GatewayProbePolicy(maximumAttempts: attempts, minimumRetryDelayMillis: 50, maximumTTLSeconds: 60))
            return try GatewayDeliveryCoordinator(database: db, identity: coordinatorIdentity ?? identity(), tokens: source,
                policy: GatewayDeliveryPolicy(maximumFlights: 2, minimumSendIntervalMillis: 10, retryBaseDelayMillis: retryBase, maximumRetryBackoffMillis: retryCap), sample: { clock.sample() },
                sleep: { clock.advance($0) }, send: { probe, token in
                    if let sender { return try await sender.send(probe, accessToken: token) }
                    return try await provider.send(at: clock.sample().moment.milliseconds)
                })
        }
        func revoke(_ coordinator: GatewayDeliveryCoordinator) async throws {
            let limits = try CBORLimits(maxBytes: 2048, maxDepth: 8, maxItems: 128)
            let value = try GatewayPhoneRevocation(binding: GatewayPhoneEpochBinding(ownerID: id(1), macID: id(2), accountID: id(3),
                gatewayID: id(4), lifecycleEpoch: id(5), phoneID: id(6), enrollmentEpoch: id(7)),
                revision: 2, operationID: id(50), issuedAtUnixMillis: 1000, expiresAtUnixMillis: 11_000)
            let payload = try value.encode(limits: limits)
            let input = try GatewayRecipientSigningInput.make(wireVersion: 1, kind: .phoneRevocation,
                canonicalPayload: payload, payloadLimits: limits, inputLimits: limits)
            _ = try await coordinator.applyRecipient(canonicalPayload: payload, signature: key.signature(for: input).rawRepresentation,
                wireVersion: 1, kind: .phoneRevocation, phoneID: id(6))
        }
        func admit(_ coordinator: GatewayDeliveryCoordinator, n: UInt8 = 1, expires: UInt64 = 11_000) async throws {
            let limits = try CBORLimits(maxBytes: 2048, maxDepth: 8, maxItems: 128)
            let candidate = try GatewayTokenCandidate(binding: GatewayTokenBinding(ownerID: id(1), macID: id(2), accountID: id(3), gatewayID: id(4),
                lifecycleEpoch: id(5), phoneID: id(6), enrollmentEpoch: id(7), candidateID: id(n), tokenDigest: Data(SHA256.hash(data: Data("synthetic".utf8))),
                challenge: id(n, 32), enrollmentTag: id(6, 32)), revision: UInt64(n), operationID: id(n), issuedAtUnixMillis: 1000, expiresAtUnixMillis: expires)
            let payload = try candidate.encode(limits: limits)
            let input = try GatewayTokenCandidateSigningInput.make(wireVersion: 1, canonicalPayload: payload, payloadLimits: limits, inputLimits: limits)
            _ = try await coordinator.admitCandidate(canonicalPayload: payload, signature: key.signature(for: input).rawRepresentation,
                wireVersion: 1, registrationToken: "synthetic", phoneID: id(6))
        }
    }

    func testAcceptedProbeIsNotSentAgainAndStartupHasPacingDelay() async throws {
        let fixture = try Fixture(), provider = Provider([.accepted]), coordinator = try fixture.coordinator(provider)
        try await coordinator.replaceTrustedEnrollments([fixture.enrollment()], active: true)
        try await fixture.admit(coordinator)
        let result = try await coordinator.deliverProbe(operationID: id(1), phoneID: id(6))
        XCTAssertEqual(result?.status, .accepted); XCTAssertEqual(result?.number, 1)
        _ = try await coordinator.deliverProbe(operationID: id(1), phoneID: id(6))
        let times = await provider.times
        XCTAssertEqual(times, [110]); XCTAssertEqual(fixture.refreshes.value.withLock { $0 }, 1)
        try await coordinator.shutdown()
    }

    func testProviderDelayAndAttemptBudgetAreAppliedAcrossRetries() async throws {
        let fixture = try Fixture(), provider = Provider([.retryable(minimumDelaySeconds: 0.1001), .retryable(minimumDelaySeconds: 0), .accepted])
        let coordinator = try fixture.coordinator(provider)
        try await coordinator.replaceTrustedEnrollments([fixture.enrollment()], active: true)
        try await fixture.admit(coordinator)
        let result = try await coordinator.deliverProbe(operationID: id(1), phoneID: id(6))
        XCTAssertEqual(result?.number, 3); XCTAssertEqual(result?.status, .accepted)
        let times = await provider.times
        XCTAssertEqual(times, [110, 211, 261])
        try await coordinator.shutdown()
    }

    func testAuthenticationFailureRefreshesGrantButDoesNotRenewCandidateBudget() async throws {
        let fixture = try Fixture(), provider = Provider([.authenticationRequired, .authenticationRequired, .accepted])
        let coordinator = try fixture.coordinator(provider, attempts: 2)
        try await coordinator.replaceTrustedEnrollments([fixture.enrollment()], active: true)
        try await fixture.admit(coordinator)
        let result = try await coordinator.deliverProbe(operationID: id(1), phoneID: id(6))
        XCTAssertEqual(result?.status, .terminal); XCTAssertEqual(result?.number, 2)
        XCTAssertEqual(fixture.refreshes.value.withLock { $0 }, 2)
        let times = await provider.times
        XCTAssertEqual(times.count, 2)
        try await coordinator.shutdown()
    }

    func testUnrepresentableRetryAndOriginalDeadlineStopWithoutAnotherSend() async throws {
        for delay in [Double.infinity, Double.nan, Double.greatestFiniteMagnitude, -1, 20] {
            let fixture = try Fixture(), provider = Provider([.retryable(minimumDelaySeconds: delay)])
            let coordinator = try fixture.coordinator(provider)
            try await coordinator.replaceTrustedEnrollments([fixture.enrollment()], active: true)
            try await fixture.admit(coordinator)
            let result = try await coordinator.deliverProbe(operationID: id(1), phoneID: id(6))
            XCTAssertEqual(result?.status, .terminal)
            let times = await provider.times
            XCTAssertEqual(times.count, 1)
            try await coordinator.shutdown()
        }
    }

    func testInactiveEnrollmentAndExpiredCandidateDoNotReachProvider() async throws {
        let fixture = try Fixture(), provider = Provider([]), coordinator = try fixture.coordinator(provider)
        try await coordinator.replaceTrustedEnrollments([fixture.enrollment()], active: true)
        try await fixture.admit(coordinator)
        try await coordinator.replaceTrustedEnrollments([fixture.enrollment(active: false)], active: true)
        do { _ = try await coordinator.deliverProbe(operationID: id(1), phoneID: id(6)); XCTFail("Inactive phone sent") } catch {}
        try await coordinator.replaceTrustedEnrollments([fixture.enrollment()], active: true)
        fixture.clock.advance(10_000)
        do { _ = try await coordinator.deliverProbe(operationID: id(1), phoneID: id(6)); XCTFail("Expired candidate sent") } catch {}
        let times = await provider.times
        XCTAssertTrue(times.isEmpty)
        try await coordinator.shutdown()
    }
    private func until(_ condition: @Sendable () async -> Bool) async throws {
        for _ in 0..<200 {
            if await condition() { return }
            try await Task.sleep(for: .milliseconds(10))
        }
        throw FixtureFailure.timeout
    }
    private enum FixtureFailure: Error { case timeout }

    func testConcurrencyLimitDuplicateAndPacingAcrossCandidates() async throws {
        let fixture = try Fixture(), provider = Provider([]), coordinator = try fixture.coordinator(provider)
        try await coordinator.replaceTrustedEnrollments([fixture.enrollment()], active: true)
        for n: UInt8 in 1...3 { try await fixture.admit(coordinator, n: n) }
        await provider.hold()
        let first = Task { try await coordinator.deliverProbe(operationID: id(1), phoneID: id(6)) }
        let second = Task { try await coordinator.deliverProbe(operationID: id(2), phoneID: id(6)) }
        defer { first.cancel(); second.cancel() }
        try await until { await provider.times.count == 2 }
        do { _ = try await coordinator.deliverProbe(operationID: id(1), phoneID: id(6)); XCTFail("Duplicate flight") }
        catch { XCTAssertEqual(error as? GatewayDeliveryError, .alreadyRunning) }
        do { _ = try await coordinator.deliverProbe(operationID: id(3), phoneID: id(6)); XCTFail("Capacity exceeded") }
        catch { XCTAssertEqual(error as? GatewayDeliveryError, .capacityExceeded) }
        first.cancel(); _ = await first.result
        try await until { await coordinator.activeProbeCount == 1 }
        await provider.release()
        _ = try await second.value
        let third = try await coordinator.deliverProbe(operationID: id(3), phoneID: id(6))
        XCTAssertEqual(third?.status, .accepted)
        let times = await provider.times
        XCTAssertEqual(times.count, 3)
        for pair in zip(times, times.dropFirst()) { XCTAssertGreaterThanOrEqual(pair.1 - pair.0, 10) }
        try await coordinator.shutdown()
    }

    func testChangedTrustCancelsOAuthBeforeProviderAndIdenticalTrustPreservesFlight() async throws {
        let fixture = try Fixture(), provider = Provider([]), gate = OAuthGate()
        let source = try FCMTokenSource(now: { .now }, refresh: { try await gate.refresh() })
        let coordinator = try fixture.coordinator(provider, tokenSource: source)
        try await coordinator.replaceTrustedEnrollments([fixture.enrollment()], active: true)
        try await fixture.admit(coordinator)
        let first = Task { try await coordinator.deliverProbe(operationID: id(1), phoneID: id(6)) }
        defer { first.cancel() }
        try await until { await gate.started }
        try await coordinator.replaceTrustedEnrollments([fixture.enrollment(active: false)], active: true)
        do { _ = try await first.value; XCTFail("Cancelled OAuth accepted") } catch {}
        let noAttempt = try await coordinator.progress(operationID: id(1)), times = await provider.times
        XCTAssertNil(noAttempt); XCTAssertTrue(times.isEmpty)
        try await coordinator.shutdown()

        let other = try Fixture(), otherProvider = Provider([]), otherCoordinator = try other.coordinator(otherProvider)
        try await otherCoordinator.replaceTrustedEnrollments([other.enrollment()], active: true)
        try await other.admit(otherCoordinator)
        await otherProvider.hold()
        let task = Task { try await otherCoordinator.deliverProbe(operationID: id(1), phoneID: id(6)) }
        defer { task.cancel() }
        try await until { await otherProvider.times.count == 1 }
        try await otherCoordinator.replaceTrustedEnrollments([other.enrollment()], active: true)
        await otherProvider.release()
        let result = try await task.value
        XCTAssertEqual(result?.status, .accepted)
        try await otherCoordinator.shutdown()
    }

    func testLateAcceptedCallbackAfterTrustCancellationCannotBecomeAccepted() async throws {
        let fixture = try Fixture(), provider = Provider([]), coordinator = try fixture.coordinator(provider)
        try await coordinator.replaceTrustedEnrollments([fixture.enrollment()], active: true)
        try await fixture.admit(coordinator)
        await provider.hold(honorCancellation: false)
        let task = Task { try await coordinator.deliverProbe(operationID: id(1), phoneID: id(6)) }
        defer { task.cancel() }
        try await until { await provider.times.count == 1 }
        try await coordinator.replaceTrustedEnrollments([], active: true)
        await provider.release()
        do { _ = try await task.value; XCTFail("Late acceptance survived cancellation") } catch {}
        let result = try await coordinator.progress(operationID: id(1))
        XCTAssertEqual(result?.status, .terminal)
        try await coordinator.shutdown()
    }

    func testShutdownCancelsPendingProviderAndClosesOnlyAfterTaskFinishes() async throws {
        let fixture = try Fixture(), provider = Provider([]), coordinator = try fixture.coordinator(provider)
        try await coordinator.replaceTrustedEnrollments([fixture.enrollment()], active: true)
        try await fixture.admit(coordinator)
        await provider.hold()
        let task = Task { try await coordinator.deliverProbe(operationID: id(1), phoneID: id(6)) }
        defer { task.cancel() }
        try await until { await provider.times.count == 1 }
        async let one: Void = coordinator.shutdown()
        async let two: Void = coordinator.shutdown()
        _ = try await (one, two)
        do { _ = try await task.value; XCTFail("Stopped flight succeeded") } catch {}
        do { _ = try await coordinator.progress(operationID: id(1)); XCTFail("Closed owner remained usable") }
        catch { XCTAssertEqual(error as? GatewayDeliveryError, .stopped) }
    }

    func testNetworkLossRetriesButProviderRejectionDoesNotRevokeEnrollment() async throws {
        let fixture = try Fixture(), provider = Provider([.registrationInvalid, .accepted]), coordinator = try fixture.coordinator(provider)
        try await coordinator.replaceTrustedEnrollments([fixture.enrollment()], active: true)
        try await fixture.admit(coordinator)
        await provider.failNext()
        let first = try await coordinator.deliverProbe(operationID: id(1), phoneID: id(6))
        XCTAssertEqual(first?.status, .terminal); XCTAssertEqual(first?.number, 2)
        try await fixture.admit(coordinator, n: 2)
        let second = try await coordinator.deliverProbe(operationID: id(2), phoneID: id(6))
        XCTAssertEqual(second?.status, .accepted)
        let times = await provider.times
        XCTAssertEqual(times.count, 3)
        try await coordinator.shutdown()
    }

    func testExpiryDuringOAuthPreventsDispatch() async throws {
        let fixture = try Fixture(), provider = Provider([]), gate = OAuthGate()
        let source = try FCMTokenSource(now: { .now }, refresh: { try await gate.refresh() })
        let coordinator = try fixture.coordinator(provider, tokenSource: source)
        try await coordinator.replaceTrustedEnrollments([fixture.enrollment()], active: true)
        try await fixture.admit(coordinator)
        let task = Task { try await coordinator.deliverProbe(operationID: id(1), phoneID: id(6)) }
        defer { task.cancel() }
        try await until { await gate.started }
        fixture.clock.advance(10_000)
        try await gate.release()
        do { _ = try await task.value; XCTFail("Expired during OAuth") } catch {}
        let times = await provider.times
        XCTAssertTrue(times.isEmpty)
        try await coordinator.shutdown()
    }

    func testSignedRevocationCancelsSendAndTrustReloadCannotClearTombstone() async throws {
        let fixture = try Fixture(), provider = Provider([]), coordinator = try fixture.coordinator(provider)
        try await coordinator.replaceTrustedEnrollments([fixture.enrollment()], active: true)
        try await fixture.admit(coordinator)
        await provider.hold()
        let task = Task { try await coordinator.deliverProbe(operationID: id(1), phoneID: id(6)) }
        defer { task.cancel() }
        try await until { await provider.times.count == 1 }
        try await fixture.revoke(coordinator)
        do { _ = try await task.value; XCTFail("Revoked flight succeeded") } catch {}
        let progress = try await coordinator.progress(operationID: id(1))
        XCTAssertEqual(progress?.status, .terminal)
        try await coordinator.replaceTrustedEnrollments([fixture.enrollment()], active: true)
        do { try await fixture.admit(coordinator, n: 3); XCTFail("Tombstone cleared") }
        catch { XCTAssertEqual(error as? GatewayDatabaseError, .revokedEnrollment) }
        try await coordinator.shutdown()
    }

    func testCoordinatorUsesRealSenderThroughInterceptedHTTPTransport() async throws {
        let fixture = try Fixture(), provider = Provider([])
        let sender = try FCMWakeSender(project: "coordinator-fixture", packageName: "dev.remozio.android",
            transport: FCMHTTPTransport(timeoutSeconds: 2, protocolClasses: [CoordinatorHTTPFixture.self]))
        let coordinator = try fixture.coordinator(provider, sender: sender)
        try await coordinator.replaceTrustedEnrollments([fixture.enrollment()], active: true)
        try await fixture.admit(coordinator)
        let result = try await coordinator.deliverProbe(operationID: id(1), phoneID: id(6))
        XCTAssertEqual(result?.status, .accepted)
        let requests = CoordinatorHTTPFixture.requests.withLock { $0 }
        XCTAssertEqual(requests.count, 1)
        XCTAssertEqual(requests.first?.url?.absoluteString, "https://fcm.googleapis.com/v1/projects/coordinator-fixture/messages:send")
        XCTAssertEqual(requests.first?.value(forHTTPHeaderField: "Authorization"), "Bearer synthetic")
        try await coordinator.shutdown()
    }

    func testLocalBackoffGrowsWithBoundedJitterAndStopsAtConfiguredCap() async throws {
        let fixture = try Fixture(), provider = Provider([.retryable(minimumDelaySeconds: 0), .retryable(minimumDelaySeconds: 0),
            .retryable(minimumDelaySeconds: 0), .accepted])
        let coordinator = try fixture.coordinator(provider, attempts: 4, retryBase: 100, retryCap: 400)
        try await coordinator.replaceTrustedEnrollments([fixture.enrollment()], active: true)
        try await fixture.admit(coordinator)
        let result = try await coordinator.deliverProbe(operationID: id(1), phoneID: id(6))
        XCTAssertEqual(result?.status, .accepted)
        let times = await provider.times
        XCTAssertEqual(times.count, 4)
        if times.count == 4 {
            XCTAssertTrue((100...125).contains(times[1] - times[0]))
            XCTAssertTrue((200...250).contains(times[2] - times[1]))
            XCTAssertEqual(times[3] - times[2], 400)
        }
        try await coordinator.shutdown()
    }

    func testClockRegressionStopsOwnerButShutdownStillReleasesDatabase() async throws {
        let fixture = try Fixture(), provider = Provider([]), coordinator = try fixture.coordinator(provider)
        try await coordinator.replaceTrustedEnrollments([fixture.enrollment()], active: true)
        try await fixture.admit(coordinator)
        fixture.clock.value.withLock { $0 = 99 }
        do { _ = try await coordinator.deliverProbe(operationID: id(1), phoneID: id(6)); XCTFail("Regressed clock accepted") }
        catch { XCTAssertEqual(error as? GatewayDeliveryError, .invalidClock) }
        try await coordinator.shutdown()
        let lease = try ProtectedGatewayLease(anchor: fixture.root.path, relativeDirectory: "store", serviceUID: geteuid(), ancestorUID: geteuid())
        lease.close()
        let times = await provider.times
        XCTAssertTrue(times.isEmpty)
    }

    func testRecoveryRepliesVerifyAtRootAndContainNoTokenOrProviderWork() async throws {
        let fixture = try Fixture(), provider = Provider([]), coordinator = try fixture.coordinator(provider)
        let gatewayKey = P256.Signing.PrivateKey()
        let owner = try GatewayHeadQueryOwner(registration: fixture.identity(), gatewayPublicKey: gatewayKey.publicKey.x963Representation,
            clockEpoch: fixture.clock.epoch)
        let now = fixture.clock.sample().moment
        let emptyQuery = try owner.makeQuery(now: now)
        let emptyReply = try await coordinator.recoveryHeadReply(canonicalQuery: emptyQuery) { try gatewayKey.signature(for: $0).rawRepresentation }
        XCTAssertEqual(try owner.accept(emptyReply, now: now).evidence.revision, 0)
        try await coordinator.replaceTrustedEnrollments([fixture.enrollment()], active: true)
        try await fixture.admit(coordinator)
        try await fixture.revoke(coordinator)
        let query = try owner.makeQuery(now: now)
        let reply = try await coordinator.recoveryHeadReply(canonicalQuery: query) { try gatewayKey.signature(for: $0).rawRepresentation }
        let head = try owner.accept(reply, now: now)
        XCTAssertEqual(head.evidence.revision, 2)
        let collector = try GatewayHistoryCollector(head: head, afterRevision: 0)
        for after: UInt64 in [0, 1] {
            let query = try owner.makeHistoryQuery(afterRevision: after, throughRevision: 2, maximumRecords: 1, now: now)
            let reply = try await coordinator.recoveryHistoryReply(canonicalQuery: query) { try gatewayKey.signature(for: $0).rawRepresentation }
            XCTAssertNil(reply.canonicalPayload.range(of: Data("synthetic".utf8)))
            let page = try owner.acceptHistory(reply, now: now)
            let history = try collector.accept(page)
            if after == 0 { XCTAssertNil(history) }
            else {
                XCTAssertEqual(history?.records.count, 2)
                guard case .recipient(let receipt) = history?.records.last else { return XCTFail("Missing removal receipt") }
                XCTAssertEqual(receipt.kind, .phoneRevocation)
            }
        }
        let times = await provider.times
        XCTAssertTrue(times.isEmpty)
        XCTAssertEqual(fixture.refreshes.value.withLock { $0 }, 0)
        try await coordinator.shutdown()
    }

    func testRecoveryHistoryKeepsPinnedRangeWhileNewControlsArrive() async throws {
        let fixture = try Fixture(), provider = Provider([]), coordinator = try fixture.coordinator(provider)
        try await coordinator.replaceTrustedEnrollments([fixture.enrollment()], active: true)
        try await fixture.admit(coordinator)
        try await fixture.admit(coordinator, n: 2)
        let key = P256.Signing.PrivateKey(), now = fixture.clock.sample().moment
        let owner = try GatewayHeadQueryOwner(registration: fixture.identity(), gatewayPublicKey: key.publicKey.x963Representation, clockEpoch: now.epoch)
        let headReply = try await coordinator.recoveryHeadReply(canonicalQuery: owner.makeQuery(now: now)) { try key.signature(for: $0).rawRepresentation }
        let head = try owner.accept(headReply, now: now)
        let collector = try GatewayHistoryCollector(head: head, afterRevision: 0)
        let firstReply = try await coordinator.recoveryHistoryReply(canonicalQuery: owner.makeHistoryQuery(afterRevision: 0,
            throughRevision: 2, maximumRecords: 1, now: now)) { try key.signature(for: $0).rawRepresentation }
        XCTAssertNil(try collector.accept(owner.acceptHistory(firstReply, now: now)))
        try await fixture.admit(coordinator, n: 3)
        let lastReply = try await coordinator.recoveryHistoryReply(canonicalQuery: owner.makeHistoryQuery(afterRevision: 1,
            throughRevision: 2, maximumRecords: 1, now: now)) { try key.signature(for: $0).rawRepresentation }
        let history = try XCTUnwrap(collector.accept(owner.acceptHistory(lastReply, now: now)))
        XCTAssertEqual(history.records.map(\.revision), [1, 2])
        let latestReply = try await coordinator.recoveryHeadReply(canonicalQuery: owner.makeQuery(now: now)) { try key.signature(for: $0).rawRepresentation }
        XCTAssertEqual(try owner.accept(latestReply, now: now).evidence.revision, 3)
        try await coordinator.shutdown()
    }

    func testRecoveryReadsRemainAvailableDuringOAuthWaitAndInactiveDelivery() async throws {
        let fixture = try Fixture(), provider = Provider([]), gate = OAuthGate()
        let source = try FCMTokenSource(now: { .now }, refresh: { try await gate.refresh() })
        let coordinator = try fixture.coordinator(provider, tokenSource: source)
        try await coordinator.replaceTrustedEnrollments([fixture.enrollment()], active: true)
        try await fixture.admit(coordinator)
        let task = Task { try await coordinator.deliverProbe(operationID: id(1), phoneID: id(6)) }
        defer { task.cancel() }
        try await until { await gate.started }
        let key = P256.Signing.PrivateKey(), now = fixture.clock.sample().moment
        let owner = try GatewayHeadQueryOwner(registration: fixture.identity(), gatewayPublicKey: key.publicKey.x963Representation, clockEpoch: now.epoch)
        let reply = try await coordinator.recoveryHeadReply(canonicalQuery: owner.makeQuery(now: now)) { try key.signature(for: $0).rawRepresentation }
        XCTAssertEqual(try owner.accept(reply, now: now).evidence.revision, 1)
        try await coordinator.replaceTrustedEnrollments([fixture.enrollment()], active: false)
        do { _ = try await task.value; XCTFail("Inactive delivery succeeded") } catch {}
        let pageReply = try await coordinator.recoveryHistoryReply(canonicalQuery: owner.makeHistoryQuery(afterRevision: 0,
            throughRevision: 1, now: now)) { try key.signature(for: $0).rawRepresentation }
        XCTAssertEqual(try owner.acceptHistory(pageReply, now: now).page.records.count, 1)
        let times = await provider.times
        XCTAssertTrue(times.isEmpty)
        try await coordinator.shutdown()
    }

    func testRecoveryRepliesRejectMalformedQueriesAndWrongScopeBeforeSigning() async throws {
        let fixture = try Fixture(), provider = Provider([]), coordinator = try fixture.coordinator(provider)
        try await coordinator.replaceTrustedEnrollments([fixture.enrollment()], active: true)
        try await fixture.admit(coordinator)
        let key = P256.Signing.PrivateKey(), calls = Counter(), now = fixture.clock.sample().moment
        let other = try GatewayRegistrationIdentity(ownerID: id(1), macID: id(22), accountID: id(3), gatewayID: id(4),
            lifecycleEpoch: id(5), rootPublicKey: fixture.key.publicKey.x963Representation)
        let owner = try GatewayHeadQueryOwner(registration: other, gatewayPublicKey: key.publicKey.x963Representation, clockEpoch: now.epoch)
        let wrongHead = try owner.makeQuery(now: now)
        let wrongPage = try owner.makeHistoryQuery(afterRevision: 0, throughRevision: 1, now: now)
        for query in [Data(), Data(repeating: 0, count: 2048), wrongHead, wrongPage] {
            do {
                _ = try await coordinator.recoveryHeadReply(canonicalQuery: query) { _ in calls.value.withLock { $0 += 1 }; return Data() }
                XCTFail("Invalid head query accepted")
            } catch {}
            do {
                _ = try await coordinator.recoveryHistoryReply(canonicalQuery: query) { _ in calls.value.withLock { $0 += 1 }; return Data() }
                XCTFail("Invalid history query accepted")
            } catch {}
        }
        XCTAssertEqual(calls.value.withLock { $0 }, 0)
        let times = await provider.times
        XCTAssertTrue(times.isEmpty)
        XCTAssertEqual(fixture.refreshes.value.withLock { $0 }, 0)
        try await coordinator.shutdown()
    }

    func testRecoverySignerFailureDoesNotChangeStoreOrConsumeRootQuery() async throws {
        let fixture = try Fixture(), provider = Provider([]), coordinator = try fixture.coordinator(provider)
        let key = P256.Signing.PrivateKey(), now = fixture.clock.sample().moment
        let owner = try GatewayHeadQueryOwner(registration: fixture.identity(), gatewayPublicKey: key.publicKey.x963Representation, clockEpoch: now.epoch)
        let query = try owner.makeQuery(now: now)
        do { _ = try await coordinator.recoveryHeadReply(canonicalQuery: query) { _ in throw Failure.injected }; XCTFail("Signer succeeded") }
        catch { XCTAssertTrue(error is Failure) }
        do { _ = try await coordinator.recoveryHeadReply(canonicalQuery: query) { _ in Data() }; XCTFail("Short signature accepted") }
        catch { XCTAssertEqual(error as? GatewayHeadReplyError, .invalidSignature) }
        let reply = try await coordinator.recoveryHeadReply(canonicalQuery: query) { try key.signature(for: $0).rawRepresentation }
        XCTAssertEqual(try owner.accept(reply, now: now).evidence.revision, 0)
        XCTAssertThrowsError(try owner.accept(reply, now: now))
        try await coordinator.shutdown()
    }

    func testRecoveryReadsRejectMismatchedHostIdentityAndStoppedOwner() async throws {
        let fixture = try Fixture(), provider = Provider([]), calls = Counter()
        let other = try GatewayRegistrationIdentity(ownerID: id(1), macID: id(22), accountID: id(3), gatewayID: id(4),
            lifecycleEpoch: id(5), rootPublicKey: fixture.key.publicKey.x963Representation)
        let coordinator = try fixture.coordinator(provider, coordinatorIdentity: other)
        let key = P256.Signing.PrivateKey(), now = fixture.clock.sample().moment
        let owner = try GatewayHeadQueryOwner(registration: fixture.identity(), gatewayPublicKey: key.publicKey.x963Representation, clockEpoch: now.epoch)
        let head = try owner.makeQuery(now: now), page = try owner.makeHistoryQuery(afterRevision: 0, throughRevision: 1, now: now)
        for stopped in [false, true] {
            if stopped { try await coordinator.shutdown() }
            do {
                _ = try await coordinator.recoveryHeadReply(canonicalQuery: head) { _ in calls.value.withLock { $0 += 1 }; return Data() }
                XCTFail("Unavailable owner replied")
            } catch {
                if stopped { XCTAssertEqual(error as? GatewayDeliveryError, .stopped) }
                else { XCTAssertEqual(error as? GatewayDatabaseError, .wrongScope) }
            }
            do {
                _ = try await coordinator.recoveryHistoryReply(canonicalQuery: page) { _ in calls.value.withLock { $0 += 1 }; return Data() }
                XCTFail("Unavailable owner replied")
            } catch {
                if stopped { XCTAssertEqual(error as? GatewayDeliveryError, .stopped) }
                else { XCTAssertEqual(error as? GatewayDatabaseError, .wrongScope) }
            }
        }
        XCTAssertEqual(calls.value.withLock { $0 }, 0)
    }

    func testPolicyRejectsUnboundedAndInconsistentValues() throws {
        XCTAssertThrowsError(try GatewayDeliveryPolicy(maximumFlights: 0, minimumSendIntervalMillis: 1))
        XCTAssertThrowsError(try GatewayDeliveryPolicy(maximumFlights: 65, minimumSendIntervalMillis: 1))
        XCTAssertThrowsError(try GatewayDeliveryPolicy(maximumFlights: 1, minimumSendIntervalMillis: 0))
        XCTAssertThrowsError(try GatewayDeliveryPolicy(maximumFlights: 1, minimumSendIntervalMillis: 1, retryBaseDelayMillis: 0))
        XCTAssertThrowsError(try GatewayDeliveryPolicy(maximumFlights: 1, minimumSendIntervalMillis: 1, retryBaseDelayMillis: 100, maximumRetryBackoffMillis: 99))
    }

}


private final class CoordinatorHTTPFixture: URLProtocol, @unchecked Sendable {
    static let requests = Mutex<[URLRequest]>([])
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        Self.requests.withLock { $0.append(request) }
        let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: nil)!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Data(#"{"name":"projects/coordinator-fixture/messages/opaque"}"#.utf8))
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}
