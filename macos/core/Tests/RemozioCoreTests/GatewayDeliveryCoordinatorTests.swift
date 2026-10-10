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
        private(set) var wakes: [FCMWake] = []
        private var holding = false
        private var honorCancellation = true
        private var failures = 0
        private var pending: [Int: CheckedContinuation<FCMDeliveryResult, any Error>] = [:]
        init(_ results: [FCMDeliveryResult]) { self.results = results }
        func hold(honorCancellation: Bool = true) { holding = true; self.honorCancellation = honorCancellation }
        func failNext() { failures += 1 }
        func send(wake: FCMWake, at time: UInt64) async throws -> FCMDeliveryResult {
            wakes.append(wake)
            return try await send(at: time)
        }
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
        func release(result: FCMDeliveryResult = .accepted) {
            holding = false
            let values = pending.values; pending = [:]
            for continuation in values { continuation.resume(returning: result) }
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
    private actor SchedulerTimer {
        private var continuation: CheckedContinuation<Void, any Error>?
        var waiting: Bool { continuation != nil }
        func sleep(_ milliseconds: UInt64) async throws {
            try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
                    if Task.isCancelled { continuation.resume(throwing: CancellationError()) }
                    else { self.continuation = continuation }
                }
            } onCancel: { Task { await self.cancel() } }
        }
        func tick() { continuation?.resume(); continuation = nil }
        func cancel() { continuation?.resume(throwing: CancellationError()); continuation = nil }
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
        func enrollment(active: Bool = true, phone: UInt8 = 6) throws -> GatewayPhoneEnrollment {
            try .init(phoneID: id(phone), epoch: id(7), tag: id(phone, 32), active: active)
        }
        func coordinator(_ provider: Provider, attempts: Int = 3, lifetime: UInt64 = 10_000, tokenSource: FCMTokenSource? = nil, sender: FCMWakeSender? = nil, retryBase: UInt64 = 1, retryCap: UInt64 = 1, coordinatorIdentity: GatewayRegistrationIdentity? = nil, wakePolicy: GatewayWakePolicy? = nil, maximumFlights: Int = 2, schedulerTimer: SchedulerTimer? = nil, validateAuthority: @escaping @Sendable () throws -> Void = {}) throws -> GatewayDeliveryCoordinator {
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
            let wakeSend: (@Sendable (FCMWake, FCMAccessToken) async throws -> FCMDeliveryResult)?
            if wakePolicy != nil {
                wakeSend = { wake, token in
                    if let sender { return try await sender.send(wake, accessToken: token) }
                    return try await provider.send(wake: wake, at: clock.sample().moment.milliseconds)
                }
            } else { wakeSend = nil }
            return try GatewayDeliveryCoordinator(database: db, identity: coordinatorIdentity ?? identity(), tokens: source,
                policy: GatewayDeliveryPolicy(maximumFlights: maximumFlights, minimumSendIntervalMillis: 10, retryBaseDelayMillis: retryBase, maximumRetryBackoffMillis: retryCap), sample: { clock.sample() },
                sleep: { clock.advance($0) }, send: { probe, token in
                    if let sender { return try await sender.send(probe, accessToken: token) }
                    return try await provider.send(at: clock.sample().moment.milliseconds)
                }, wakePolicy: wakePolicy, sendWake: wakeSend, validateAuthority: validateAuthority, schedulerSleep: { milliseconds in
                    if let schedulerTimer { try await schedulerTimer.sleep(milliseconds) }
                    else { try await Task.sleep(for: .milliseconds(milliseconds)) }
                })
        }
        func revoke(_ coordinator: GatewayDeliveryCoordinator, revision: UInt64 = 2, phone: UInt8 = 6) async throws {
            let limits = try CBORLimits(maxBytes: 2048, maxDepth: 8, maxItems: 128)
            let value = try GatewayPhoneRevocation(binding: GatewayPhoneEpochBinding(ownerID: id(1), macID: id(2), accountID: id(3),
                gatewayID: id(4), lifecycleEpoch: id(5), phoneID: id(phone), enrollmentEpoch: id(7)),
                revision: revision, operationID: id(50), issuedAtUnixMillis: 1000, expiresAtUnixMillis: 11_000)
            let payload = try value.encode(limits: limits)
            let input = try GatewayRecipientSigningInput.make(wireVersion: 1, kind: .phoneRevocation,
                canonicalPayload: payload, payloadLimits: limits, inputLimits: limits)
            _ = try await coordinator.applyRecipient(canonicalPayload: payload, signature: key.signature(for: input).rawRepresentation,
                wireVersion: 1, kind: .phoneRevocation, phoneID: id(phone))
        }
        func admit(_ coordinator: GatewayDeliveryCoordinator, n: UInt8 = 1, expires: UInt64 = 11_000, phone: UInt8 = 6, token: String = "synthetic") async throws {
            let limits = try CBORLimits(maxBytes: 2048, maxDepth: 8, maxItems: 128)
            let candidate = try GatewayTokenCandidate(binding: GatewayTokenBinding(ownerID: id(1), macID: id(2), accountID: id(3), gatewayID: id(4),
                lifecycleEpoch: id(5), phoneID: id(phone), enrollmentEpoch: id(7), candidateID: id(n), tokenDigest: Data(SHA256.hash(data: Data(token.utf8))),
                challenge: id(n, 32), enrollmentTag: id(phone, 32)), revision: UInt64(n), operationID: id(n), issuedAtUnixMillis: 1000, expiresAtUnixMillis: expires)
            let payload = try candidate.encode(limits: limits)
            let input = try GatewayTokenCandidateSigningInput.make(wireVersion: 1, canonicalPayload: payload, payloadLimits: limits, inputLimits: limits)
            _ = try await coordinator.admitCandidate(canonicalPayload: payload, signature: key.signature(for: input).rawRepresentation,
                wireVersion: 1, registrationToken: token, phoneID: id(phone))
        }
        func activate(_ coordinator: GatewayDeliveryCoordinator, n: UInt8 = 1, phone: UInt8 = 6, token: String = "synthetic") async throws {
            let limits = try CBORLimits(maxBytes: 2048, maxDepth: 8, maxItems: 128)
            let binding = try GatewayTokenBinding(ownerID: id(1), macID: id(2), accountID: id(3), gatewayID: id(4),
                lifecycleEpoch: id(5), phoneID: id(phone), enrollmentEpoch: id(7), candidateID: id(n),
                tokenDigest: Data(SHA256.hash(data: Data(token.utf8))), challenge: id(n, 32), enrollmentTag: id(phone, 32))
            let value = try GatewayMappingActivation(binding: binding, revision: UInt64(n) + 1, operationID: id(n + 100),
                issuedAtUnixMillis: 1000, expiresAtUnixMillis: 11_000)
            let payload = try value.encode(limits: limits)
            let signature = try key.signature(for: GatewayRecipientSigningInput.make(wireVersion: 1, kind: .activation,
                canonicalPayload: payload, payloadLimits: limits, inputLimits: limits)).rawRepresentation
            _ = try await coordinator.applyRecipient(canonicalPayload: payload, signature: signature, wireVersion: 1, kind: .activation, phoneID: id(phone))
        }
        func delivery(_ n: UInt8 = 1, deadline: UInt64 = 10_100, phone: UInt8 = 6, identifier: UUID = UUID()) throws -> PhoneRequestDelivery {
            let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1)
            let enrollment = try StoredApprovalEnrollment(epoch: id(7), notificationTag: id(phone, 32), identityPublicKey: key.publicKey.x963Representation,
                approval: ApprovalEnrollment(phoneID: id(phone), active: true, capabilities: ContractCapabilities(contracts: [contract: []]), keys: [
                    EnrolledApprovalKey(id: id(11), keyClass: .biometric, publicKey: P256.Signing.PrivateKey().publicKey.x963Representation),
                    EnrolledApprovalKey(id: id(12), keyClass: .decision, publicKey: P256.Signing.PrivateKey().publicKey.x963Representation),
                ]))
            return PhoneRequestDelivery(id: identifier, recipient: DeliveryRecipient(enrollment), requestID: id(n),
                admittedAt: AuthorityMoment(epoch: clock.epoch, milliseconds: 100), deadlineMilliseconds: deadline)
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

    func testAuthorityLossDuringOAuthPreventsProviderHandoff() async throws {
        let fixture = try Fixture(), provider = Provider([]), gate = OAuthGate()
        let source = try FCMTokenSource(now: { .now }, refresh: { try await gate.refresh() })
        // A shared reference models the synchronous native lease guard.
        final class Permission: Sendable { let allowed = Mutex(true) }
        let permission = Permission()
        let coordinator = try fixture.coordinator(provider, tokenSource: source, validateAuthority: {
            guard permission.allowed.withLock({ $0 }) else { throw GatewayServiceError.unavailable }
        })
        try await coordinator.replaceTrustedEnrollments([fixture.enrollment()], active: true)
        try await fixture.admit(coordinator)
        try await coordinator.startProbe(operationID: id(1), phoneID: id(6))
        try await until { await gate.started }
        permission.allowed.withLock { $0 = false }
        try await gate.release()
        try await until { await coordinator.activeProbeCount == 0 }
        let times = await provider.times, progress = try await coordinator.progress(operationID: id(1))
        XCTAssertTrue(times.isEmpty)
        XCTAssertNil(progress)
        try await coordinator.shutdown()
    }

    func testHeartbeatPreservesHeldWakeAndOriginalDeadline() async throws {
        let fixture = try Fixture(), provider = Provider([]), rootEpoch = UUID()
        let clock = fixture.clock
        let lease = try GatewayAuthorityLease(epoch: fixture.clock.epoch, maximumLifetime: 1000, sample: {
            clock.sample().moment
        })
        let wakePolicy = try GatewayWakePolicy(maximumEntries: 8, maximumAttempts: 3, minimumEnrollmentIntervalMillis: 10,
            maximumLifetimeMillis: 10000, maximumTTLSeconds: 60)
        let coordinator = try fixture.coordinator(provider, wakePolicy: wakePolicy, validateAuthority: { try lease.validate() })
        func snapshot(_ sequence: UInt64) throws -> GatewayHostSnapshot {
            try GatewayHostSnapshot(registration: fixture.identity(), rootEpoch: rootEpoch, sequence: sequence,
                observedAtMilliseconds: fixture.clock.sample().moment.milliseconds,
                leaseDeadlineMilliseconds: fixture.clock.sample().moment.milliseconds + 1000,
                enrollments: [fixture.enrollment()], active: true, phoneRouting: true)
        }
        try await coordinator.synchronizeHost(snapshot(1), lease: lease)
        try await fixture.admit(coordinator)
        try await fixture.activate(coordinator)
        await provider.hold()
        let delivery = try fixture.delivery()
        _ = try await coordinator.enqueueWake(delivery)
        let phoneID = fixture.id(6), enrollmentEpoch = fixture.id(7)
        let send = Task { try await coordinator.deliverWakeBatch(phoneID: phoneID, enrollmentEpoch: enrollmentEpoch) }
        defer { send.cancel() }
        try await until { await provider.times.count == 1 }
        try await coordinator.synchronizeHost(snapshot(2), lease: lease)
        await provider.release()
        let result = try await send.value
        XCTAssertEqual(result.first?.status, .accepted)
        XCTAssertEqual(result.first?.attempts, 1)
        try await coordinator.shutdown()
    }

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
        CoordinatorHTTPFixture.requests.withLock { $0 = [] }
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

    private func wakePolicy(entries: Int = 32, attempts: Int = 3) throws -> GatewayWakePolicy {
        try GatewayWakePolicy(maximumEntries: entries, maximumAttempts: attempts, minimumEnrollmentIntervalMillis: 50,
            maximumLifetimeMillis: 20_000, maximumTTLSeconds: 60)
    }
    private func prepareWakes(_ fixture: Fixture, _ coordinator: GatewayDeliveryCoordinator) async throws {
        try await coordinator.replaceTrustedEnrollments([fixture.enrollment()], active: true)
        try await fixture.admit(coordinator)
        try await fixture.activate(coordinator)
        try await coordinator.setPhoneRouting(true)
    }
    private func wakeState(_ coordinator: GatewayDeliveryCoordinator, _ delivery: PhoneRequestDelivery) async throws -> GatewayWakeProgress {
        let progress = try await coordinator.wakeProgress(deliveryID: delivery.id)
        return try XCTUnwrap(progress)
    }
    private func wakeToken(_ wake: FCMWake) throws -> String? {
        let sender = try FCMWakeSender(project: "wake-fixture", packageName: "dev.remozio.android")
        let request = try sender.request(wake, accessToken: FCMAccessToken("synthetic-access"), validateOnly: false)
        let body = try XCTUnwrap(JSONSerialization.jsonObject(with: XCTUnwrap(request.httpBody)) as? [String: Any])
        return (body["message"] as? [String: Any])?["token"] as? String
    }

    func testWakeSchedulerDrainsNewArrivalsWithoutWaitingForTimer() async throws {
        let f = try Fixture(), provider = Provider([]), timer = SchedulerTimer()
        let c = try f.coordinator(provider, wakePolicy: wakePolicy(), schedulerTimer: timer)
        try await prepareWakes(f, c)
        try await c.startWakeScheduling(retryIntervalMillis: 50)
        try await until { await timer.waiting }
        let first = try f.delivery(), second = try f.delivery(2)
        try await c.enqueueWake(first)
        try await until { (try? await c.wakeProgress(deliveryID: first.id)?.status) == .accepted }
        try await c.enqueueWake(second)
        try await until { (try? await c.wakeProgress(deliveryID: second.id)?.status) == .accepted }
        let wakes = await provider.wakes
        XCTAssertEqual(wakes.count, 2)
        XCTAssertNotEqual(wakes.first?.identifier, wakes.last?.identifier)
        try await c.shutdown()
    }

    func testWakeSchedulerPresencePausesAndResumesFrozenBatchImmediately() async throws {
        let f = try Fixture(), provider = Provider([]), timer = SchedulerTimer()
        let c = try f.coordinator(provider, wakePolicy: wakePolicy(), schedulerTimer: timer)
        try await prepareWakes(f, c)
        try await c.setPhoneRouting(false)
        try await c.startWakeScheduling(retryIntervalMillis: 50)
        let delivery = try f.delivery()
        try await c.enqueueWake(delivery)
        try await until { await timer.waiting }
        let before = await provider.wakes
        XCTAssertTrue(before.isEmpty)
        await provider.hold()
        try await c.setPhoneRouting(true)
        try await until { await provider.wakes.count == 1 }
        try await c.setPhoneRouting(false)
        try await until { await c.scheduledWakeCount == 0 }
        await provider.release()
        try await c.setPhoneRouting(true)
        try await until { (try? await c.wakeProgress(deliveryID: delivery.id)?.status) == .accepted }
        let wakes = await provider.wakes
        XCTAssertEqual(wakes.count, 2); XCTAssertEqual(wakes.first?.identifier, wakes.last?.identifier)
        let progress = try await wakeState(c, delivery)
        XCTAssertEqual(progress.attempts, 2)
        try await c.shutdown()
    }

    func testWakeSchedulerRetriesPreparationFailureAtBoundedInterval() async throws {
        let f = try Fixture(), provider = Provider([]), timer = SchedulerTimer(), refreshes = Counter()
        let source = try FCMTokenSource(now: { .now }, refresh: {
            let attempt = refreshes.value.withLock { $0 += 1; return $0 }
            if attempt == 1 { throw FCMError.network }
            return FCMTokenLease(value: try FCMAccessToken("synthetic"), expiresAt: .now.advanced(by: .seconds(3600)))
        })
        let c = try f.coordinator(provider, tokenSource: source, wakePolicy: wakePolicy(), schedulerTimer: timer)
        try await prepareWakes(f, c)
        try await c.startWakeScheduling(retryIntervalMillis: 50)
        let delivery = try f.delivery()
        try await c.enqueueWake(delivery)
        try await until {
            let count = await c.scheduledWakeCount
            return refreshes.value.withLock { $0 == 1 } && count == 0
        }
        let queued = try await wakeState(c, delivery)
        XCTAssertEqual(queued.status, .queued); XCTAssertEqual(queued.attempts, 0)
        try await until { await timer.waiting }
        f.clock.advance(49); await timer.tick()
        try await until { await timer.waiting }
        XCTAssertEqual(refreshes.value.withLock { $0 }, 1)
        f.clock.advance(1); await timer.tick()
        try await until { (try? await c.wakeProgress(deliveryID: delivery.id)?.status) == .accepted }
        XCTAssertEqual(refreshes.value.withLock { $0 }, 2)
        let progress = try await wakeState(c, delivery)
        XCTAssertEqual(progress.attempts, 1)
        try await c.shutdown()
    }

    func testWakeSchedulerUnexpectedOAuthCancellationDoesNotSpin() async throws {
        let f = try Fixture(), provider = Provider([]), timer = SchedulerTimer(), refreshes = Counter()
        let source = try FCMTokenSource(now: { .now }, refresh: {
            refreshes.value.withLock { $0 += 1 }
            throw CancellationError()
        })
        let c = try f.coordinator(provider, tokenSource: source, wakePolicy: wakePolicy(), schedulerTimer: timer)
        try await prepareWakes(f, c)
        try await c.startWakeScheduling(retryIntervalMillis: 50)
        let delivery = try f.delivery(deadline: 150)
        try await c.enqueueWake(delivery)
        try await until {
            let count = await c.scheduledWakeCount
            return count == 0 && refreshes.value.withLock { $0 == 1 }
        }
        try await until { await timer.waiting }
        f.clock.advance(40); await timer.tick()
        try await until { (try? await c.wakeProgress(deliveryID: delivery.id)?.status) == .expired }
        XCTAssertEqual(refreshes.value.withLock { $0 }, 1)
        let wakes = await provider.wakes
        XCTAssertTrue(wakes.isEmpty)
        try await c.shutdown()
    }

    func testWakeSchedulerExpiresAndCancelsStalledProviderWithoutRootTraffic() async throws {
        let f = try Fixture(), provider = Provider([]), timer = SchedulerTimer()
        await provider.hold()
        let c = try f.coordinator(provider, wakePolicy: wakePolicy(), schedulerTimer: timer)
        try await prepareWakes(f, c)
        try await c.startWakeScheduling(retryIntervalMillis: 50)
        let delivery = try f.delivery(deadline: 150)
        try await c.enqueueWake(delivery)
        try await until { await provider.wakes.count == 1 }
        try await until { await timer.waiting }
        f.clock.advance(40); await timer.tick()
        try await until { await c.scheduledWakeCount == 0 }
        let expired = try await wakeState(c, delivery)
        XCTAssertEqual(expired.status, .expired)
        try await c.shutdown()
    }

    func testWakeSchedulerRoundRobinLeavesRoomForOtherPhonesBeforeNextBatch() async throws {
        let f = try Fixture(), provider = Provider([]), timer = SchedulerTimer()
        await provider.hold()
        let c = try f.coordinator(provider, wakePolicy: wakePolicy(), maximumFlights: 1, schedulerTimer: timer)
        try await c.replaceTrustedEnrollments([f.enrollment(phone: 6), f.enrollment(phone: 8), f.enrollment(phone: 10)], active: true)
        for (n, phone): (UInt8, UInt8) in [(1, 6), (3, 8), (5, 10)] {
            try await f.admit(c, n: n, phone: phone); try await f.activate(c, n: n, phone: phone)
        }
        try await c.setPhoneRouting(true)
        try await c.startWakeScheduling(retryIntervalMillis: 50)
        try await c.enqueueWake(f.delivery())
        try await until { await provider.wakes.count == 1 }
        try await c.enqueueWake(f.delivery(2, phone: 6))
        try await c.enqueueWake(f.delivery(3, phone: 8))
        try await c.enqueueWake(f.delivery(4, phone: 10))
        let count = await c.scheduledWakeCount
        XCTAssertEqual(count, 1)
        await provider.release()
        try await until { await provider.wakes.count == 4 }
        let tags = await provider.wakes.map(\.enrollmentTag)
        XCTAssertEqual(tags, [id(6, 32), id(8, 32), id(10, 32), id(6, 32)])
        try await c.shutdown()
    }

    func testWakeSchedulerUsesSlotReleasedByTokenProbeWithoutTimer() async throws {
        let f = try Fixture(), provider = Provider([]), timer = SchedulerTimer()
        await provider.hold()
        let c = try f.coordinator(provider, wakePolicy: wakePolicy(), maximumFlights: 1, schedulerTimer: timer)
        try await prepareWakes(f, c); try await f.admit(c, n: 3)
        let probe = Task { try await c.deliverProbe(operationID: id(3), phoneID: id(6)) }
        defer { probe.cancel() }
        try await until { await provider.times.count == 1 }
        try await c.startWakeScheduling(retryIntervalMillis: 50)
        let delivery = try f.delivery()
        try await c.enqueueWake(delivery)
        let count = await c.scheduledWakeCount
        XCTAssertEqual(count, 0)
        await provider.release(); _ = try await probe.value
        try await until { (try? await c.wakeProgress(deliveryID: delivery.id)?.status) == .accepted }
        let wakes = await provider.wakes
        XCTAssertEqual(wakes.count, 1)
        try await c.shutdown()
    }

    func testWakeSchedulerResumesAfterMappingRepairWithoutWaitingForTimer() async throws {
        let f = try Fixture(), provider = Provider([]), timer = SchedulerTimer()
        await provider.hold()
        let c = try f.coordinator(provider, wakePolicy: wakePolicy(), schedulerTimer: timer)
        try await prepareWakes(f, c)
        try await c.startWakeScheduling(retryIntervalMillis: 50)
        let first = try f.delivery(), second = try f.delivery(2)
        try await c.enqueueWake(first)
        try await until { await provider.wakes.count == 1 }
        try await c.enqueueWake(second)
        await provider.release(result: .registrationInvalid)
        try await until {
            let count = await c.scheduledWakeCount
            let status = try? await c.wakeProgress(deliveryID: first.id)?.status
            return count == 0 && status == .rejected
        }
        let queued = try await wakeState(c, second)
        XCTAssertEqual(queued.status, .queued); XCTAssertEqual(queued.attempts, 0)
        try await f.admit(c, n: 3, token: "repaired")
        try await f.activate(c, n: 3, token: "repaired")
        try await until { (try? await c.wakeProgress(deliveryID: second.id)?.status) == .accepted }
        let wakes = await provider.wakes
        XCTAssertEqual(wakes.count, 2)
        XCTAssertEqual(try wakeToken(XCTUnwrap(wakes.last)), "repaired")
        try await c.shutdown()
    }

    func testWakeSchedulerClockRegressionStopsAndReleasesOwnedTasks() async throws {
        let f = try Fixture(), provider = Provider([]), timer = SchedulerTimer()
        await provider.hold()
        let c = try f.coordinator(provider, wakePolicy: wakePolicy(), schedulerTimer: timer)
        try await prepareWakes(f, c)
        try await c.startWakeScheduling(retryIntervalMillis: 50)
        try await c.enqueueWake(f.delivery())
        try await until { await provider.wakes.count == 1 }
        try await until { await timer.waiting }
        f.clock.value.withLock { $0 = 100 }
        await timer.tick()
        try await until { await c.scheduledWakeCount == 0 }
        do { try await c.setPhoneRouting(true); XCTFail("Clock regression must stop owner") }
        catch { XCTAssertEqual(error as? GatewayDeliveryError, .stopped) }
        try await c.shutdown()
    }

    func testWakeSchedulerShutdownCancelsTimerAndProviderBeforeStorageRelease() async throws {
        let f = try Fixture(), provider = Provider([]), timer = SchedulerTimer()
        await provider.hold()
        let c = try f.coordinator(provider, wakePolicy: wakePolicy(), schedulerTimer: timer)
        try await prepareWakes(f, c)
        try await c.startWakeScheduling(retryIntervalMillis: 50)
        try await c.enqueueWake(f.delivery())
        try await until { await provider.wakes.count == 1 }
        try await until { await timer.waiting }
        try await c.shutdown()
        let count = await c.scheduledWakeCount, waiting = await timer.waiting
        XCTAssertEqual(count, 0); XCTAssertFalse(waiting)
        let lease = try ProtectedGatewayLease(anchor: f.root.path, relativeDirectory: "store", serviceUID: geteuid(), ancestorUID: geteuid())
        lease.close()
    }

    func testWakeSchedulerValidatesStartupConfiguration() async throws {
        let f = try Fixture(), provider = Provider([]), timer = SchedulerTimer()
        let c = try f.coordinator(provider, wakePolicy: wakePolicy(), schedulerTimer: timer)
        for interval: UInt64 in [0, 60_001] {
            do { try await c.startWakeScheduling(retryIntervalMillis: interval); XCTFail("Invalid interval") }
            catch { XCTAssertEqual(error as? GatewayDeliveryError, .invalidConfiguration) }
        }
        try await c.startWakeScheduling(retryIntervalMillis: 50)
        do { try await c.startWakeScheduling(retryIntervalMillis: 50); XCTFail("Already started") }
        catch { XCTAssertEqual(error as? GatewayDeliveryError, .alreadyRunning) }
        try await c.shutdown()
    }

    func testApprovalWakeExpiredProgressDoesNotPreventCancellation() async throws {
        let f = try Fixture(), provider = Provider([])
        await provider.hold()
        let c = try f.coordinator(provider, wakePolicy: wakePolicy())
        try await prepareWakes(f, c)
        let delivery = try f.delivery(deadline: 150)
        try await c.enqueueWake(delivery)
        let task = Task { try await c.deliverWakeBatch(phoneID: id(6), enrollmentEpoch: id(7)) }
        defer { task.cancel() }
        try await until { await provider.times.count == 1 }
        f.clock.advance(50)
        let expired = try await wakeState(c, delivery)
        XCTAssertEqual(expired.status, .expired)
        try await c.cancelWake(deliveryID: delivery.id)
        do { _ = try await task.value; XCTFail("Expired work was not cancelled") }
        catch is CancellationError {}
        let final = try await wakeState(c, delivery)
        XCTAssertEqual(final.status, .expired)
        try await c.shutdown()
    }

    func testApprovalWakeNeedsConfigurationMappingAndExplicitPhoneRouting() async throws {
        let f = try Fixture(), provider = Provider([]), c = try f.coordinator(provider, wakePolicy: wakePolicy())
        try await c.replaceTrustedEnrollments([f.enrollment()], active: true)
        let delivery = try f.delivery()
        do { try await c.enqueueWake(delivery); XCTFail("No mapping") }
        catch { XCTAssertEqual(error as? GatewayWakeError, .unavailableMapping) }
        try await f.admit(c); try await f.activate(c)
        try await c.enqueueWake(delivery)
        do { _ = try await c.deliverWakeBatch(phoneID: id(6), enrollmentEpoch: id(7)); XCTFail("Routing defaults to local") }
        catch { XCTAssertEqual(error as? GatewayWakeError, .localRouting) }
        let wakes = await provider.wakes
        XCTAssertTrue(wakes.isEmpty)
        try await c.shutdown()
        let other = try Fixture(), unconfigured = try other.coordinator(provider)
        do { try await unconfigured.enqueueWake(other.delivery()); XCTFail("No wake policy") }
        catch { XCTAssertEqual(error as? GatewayWakeError, .unavailable) }
        try await unconfigured.shutdown()
    }

    func testApprovalWakeRejectsForeignClockFutureAdmissionAndOversizedLifetime() async throws {
        let f = try Fixture(), provider = Provider([]), c = try f.coordinator(provider, wakePolicy: wakePolicy())
        try await prepareWakes(f, c)
        let base = try f.delivery()
        let foreign = PhoneRequestDelivery(id: UUID(), recipient: base.recipient, requestID: base.requestID,
            admittedAt: AuthorityMoment(epoch: UUID(), milliseconds: 100), deadlineMilliseconds: 200)
        let future = PhoneRequestDelivery(id: UUID(), recipient: base.recipient, requestID: base.requestID,
            admittedAt: AuthorityMoment(epoch: f.clock.epoch, milliseconds: 101), deadlineMilliseconds: 200)
        for delivery in [foreign, future, try f.delivery(deadline: 20_101), try f.delivery(deadline: 100)] {
            do { try await c.enqueueWake(delivery); XCTFail("Invalid delivery admitted") }
            catch { XCTAssertEqual(error as? GatewayWakeError, .invalidDelivery) }
        }
        try await c.shutdown()
    }

    func testApprovalWakeUsesRealSenderThroughInterceptedHTTPTransport() async throws {
        CoordinatorHTTPFixture.requests.withLock { $0 = [] }
        let f = try Fixture(), provider = Provider([])
        let sender = try FCMWakeSender(project: "coordinator-fixture", packageName: "dev.remozio.android",
            transport: FCMHTTPTransport(timeoutSeconds: 2, protocolClasses: [CoordinatorHTTPFixture.self]))
        let c = try f.coordinator(provider, sender: sender, wakePolicy: wakePolicy())
        try await prepareWakes(f, c)
        try await c.enqueueWake(f.delivery())
        let result = try await c.deliverWakeBatch(phoneID: id(6), enrollmentEpoch: id(7))
        XCTAssertEqual(result.first?.status, .accepted)
        let requests = CoordinatorHTTPFixture.requests.withLock { $0 }
        XCTAssertEqual(requests.count, 1)
        XCTAssertEqual(requests.first?.url?.absoluteString, "https://fcm.googleapis.com/v1/projects/coordinator-fixture/messages:send")
        XCTAssertEqual(requests.first?.value(forHTTPHeaderField: "Authorization"), "Bearer synthetic")
        try await c.shutdown()
    }

    func testApprovalWakePolicyRejectsUnboundedValues() throws {
        XCTAssertThrowsError(try GatewayWakePolicy(maximumEntries: 0, maximumAttempts: 1,
            minimumEnrollmentIntervalMillis: 1, maximumLifetimeMillis: 1, maximumTTLSeconds: 1))
        XCTAssertThrowsError(try GatewayWakePolicy(maximumEntries: 4097, maximumAttempts: 1,
            minimumEnrollmentIntervalMillis: 1, maximumLifetimeMillis: 1, maximumTTLSeconds: 1))
        XCTAssertThrowsError(try GatewayWakePolicy(maximumEntries: 1, maximumAttempts: 33,
            minimumEnrollmentIntervalMillis: 1, maximumLifetimeMillis: 1, maximumTTLSeconds: 1))
        XCTAssertThrowsError(try GatewayWakePolicy(maximumEntries: 1, maximumAttempts: 1,
            minimumEnrollmentIntervalMillis: 0, maximumLifetimeMillis: 1, maximumTTLSeconds: 1))
        XCTAssertThrowsError(try GatewayWakePolicy(maximumEntries: 1, maximumAttempts: 1,
            minimumEnrollmentIntervalMillis: 1, maximumLifetimeMillis: 86_400_001, maximumTTLSeconds: 1))
        XCTAssertThrowsError(try GatewayWakePolicy(maximumEntries: 1, maximumAttempts: 1,
            minimumEnrollmentIntervalMillis: 1, maximumLifetimeMillis: 1, maximumTTLSeconds: 86_401))
    }

    func testApprovalWakesCoalesceWithoutLosingRequestIdentityOrDeadline() async throws {
        let f = try Fixture(), provider = Provider([]), c = try f.coordinator(provider, wakePolicy: wakePolicy())
        try await prepareWakes(f, c)
        let first = try f.delivery(1, deadline: 2100), second = try f.delivery(2, deadline: 4100)
        _ = try await c.enqueueWake(first); _ = try await c.enqueueWake(second)
        let results = try await c.deliverWakeBatch(phoneID: id(6), enrollmentEpoch: id(7))
        XCTAssertEqual(Set(results.map(\.deliveryID)), [first.id, second.id])
        XCTAssertTrue(results.allSatisfy { $0.status == .accepted && $0.attempts == 1 })
        let wakes = await provider.wakes
        XCTAssertEqual(wakes.count, 1); XCTAssertEqual(wakes.first?.ttlSeconds, 1)
        XCTAssertEqual(wakes.first?.priority, .high); XCTAssertEqual(wakes.first?.enrollmentTag, id(6, 32))
        XCTAssertEqual(try wakeToken(XCTUnwrap(wakes.first)), "synthetic")
        let duplicate = try await c.enqueueWake(first)
        XCTAssertEqual(duplicate.status, .accepted)
        let again = try await c.deliverWakeBatch(phoneID: id(6), enrollmentEpoch: id(7))
        XCTAssertTrue(again.isEmpty)
        try await c.shutdown()
    }

    func testApprovalWakeArrivalAfterDispatchUsesANewBatch() async throws {
        let f = try Fixture(), provider = Provider([]), c = try f.coordinator(provider, wakePolicy: wakePolicy())
        try await prepareWakes(f, c); await provider.hold()
        let first = try f.delivery(), second = try f.delivery(2)
        _ = try await c.enqueueWake(first)
        let task = Task { try await c.deliverWakeBatch(phoneID: id(6), enrollmentEpoch: id(7)) }
        defer { task.cancel() }
        try await until { await provider.wakes.count == 1 }
        _ = try await c.enqueueWake(second)
        await provider.release()
        let initial = try await task.value
        XCTAssertEqual(initial.map(\.deliveryID), [first.id])
        let next = try await c.deliverWakeBatch(phoneID: id(6), enrollmentEpoch: id(7))
        XCTAssertEqual(next.map(\.deliveryID), [second.id])
        let wakes = await provider.wakes, times = await provider.times
        XCTAssertEqual(wakes.count, 2); XCTAssertNotEqual(wakes[0].identifier, wakes[1].identifier)
        XCTAssertGreaterThanOrEqual(times[1] - times[0], 50)
        try await c.shutdown()
    }

    func testApprovalWakeRetriesKeepIdentifierAndRespectProviderDelay() async throws {
        let f = try Fixture(), provider = Provider([.retryable(minimumDelaySeconds: 0.2001), .accepted])
        let c = try f.coordinator(provider, wakePolicy: wakePolicy())
        try await prepareWakes(f, c)
        _ = try await c.enqueueWake(f.delivery())
        let result = try await c.deliverWakeBatch(phoneID: id(6), enrollmentEpoch: id(7))
        XCTAssertEqual(result.first?.status, .accepted); XCTAssertEqual(result.first?.attempts, 2)
        let wakes = await provider.wakes, times = await provider.times
        XCTAssertEqual(wakes.count, 2); XCTAssertEqual(wakes[0].identifier, wakes[1].identifier)
        XCTAssertGreaterThanOrEqual(times[1] - times[0], 201)
        XCTAssertLessThanOrEqual(wakes[1].ttlSeconds, wakes[0].ttlSeconds)
        try await c.shutdown()
    }

    func testApprovalWakeNetworkFailuresExhaustBudgetAndExpiryCutsOffRetry() async throws {
        for expires in [false, true] {
            let f = try Fixture(), provider = Provider([.retryable(minimumDelaySeconds: 1)])
            let c = try f.coordinator(provider, wakePolicy: wakePolicy(attempts: 2))
            try await prepareWakes(f, c)
            if !expires { await provider.failNext(); await provider.failNext() }
            _ = try await c.enqueueWake(f.delivery(deadline: expires ? 150 : 10_100))
            let result = try await c.deliverWakeBatch(phoneID: id(6), enrollmentEpoch: id(7))
            XCTAssertEqual(result.first?.status, expires ? .expired : .exhausted)
            XCTAssertEqual(result.first?.attempts, expires ? 1 : 2)
            let wakes = await provider.wakes
            XCTAssertEqual(wakes.count, expires ? 1 : 2)
            if expires { XCTAssertEqual(wakes.first?.ttlSeconds, 0) }
            try await c.shutdown()
        }
    }

    func testApprovalWakePresencePauseResumesSameBatchWithoutResettingBudget() async throws {
        let f = try Fixture(), provider = Provider([]), c = try f.coordinator(provider, wakePolicy: wakePolicy())
        try await prepareWakes(f, c); await provider.hold()
        let delivery = try f.delivery()
        _ = try await c.enqueueWake(delivery)
        let task = Task { try await c.deliverWakeBatch(phoneID: id(6), enrollmentEpoch: id(7)) }
        defer { task.cancel() }
        try await until { await provider.wakes.count == 1 }
        try await c.setPhoneRouting(false)
        do { _ = try await task.value; XCTFail("Paused task succeeded") } catch {}
        let paused = try await wakeState(c, delivery)
        XCTAssertEqual(paused.status, .queued); XCTAssertEqual(paused.attempts, 1)
        do { _ = try await c.deliverWakeBatch(phoneID: id(6), enrollmentEpoch: id(7)); XCTFail("Local routing sent") }
        catch { XCTAssertEqual(error as? GatewayWakeError, .localRouting) }
        await provider.release(); try await c.setPhoneRouting(true)
        let result = try await c.deliverWakeBatch(phoneID: id(6), enrollmentEpoch: id(7))
        XCTAssertEqual(result.first?.status, .accepted); XCTAssertEqual(result.first?.attempts, 2)
        let wakes = await provider.wakes
        XCTAssertEqual(wakes.count, 2); XCTAssertEqual(wakes[0].identifier, wakes[1].identifier)
        try await c.shutdown()
    }

    func testApprovalWakeExpiryDuringOAuthPreventsProviderCall() async throws {
        let f = try Fixture(), provider = Provider([]), gate = OAuthGate()
        let source = try FCMTokenSource(now: { .now }, refresh: { try await gate.refresh() })
        let c = try f.coordinator(provider, tokenSource: source, wakePolicy: wakePolicy())
        try await prepareWakes(f, c)
        _ = try await c.enqueueWake(f.delivery(deadline: 150))
        let task = Task { try await c.deliverWakeBatch(phoneID: id(6), enrollmentEpoch: id(7)) }
        defer { task.cancel() }
        try await until { await gate.started }
        f.clock.advance(50); try await gate.release()
        let result = try await task.value
        XCTAssertEqual(result.first?.status, .expired); XCTAssertEqual(result.first?.attempts, 0)
        let wakes = await provider.wakes
        XCTAssertTrue(wakes.isEmpty)
        try await c.shutdown()
    }

    func testApprovalWakeResolutionWithdrawsOneMemberWithoutLosingOthers() async throws {
        let f = try Fixture(), provider = Provider([]), c = try f.coordinator(provider, wakePolicy: wakePolicy())
        try await prepareWakes(f, c); await provider.hold()
        let first = try f.delivery(), second = try f.delivery(2)
        _ = try await c.enqueueWake(first); _ = try await c.enqueueWake(second)
        let task = Task { try await c.deliverWakeBatch(phoneID: id(6), enrollmentEpoch: id(7)) }
        defer { task.cancel() }
        try await until { await provider.wakes.count == 1 }
        try await c.cancelWake(deliveryID: first.id)
        await provider.release()
        let result = try await task.value
        XCTAssertEqual(result.first { $0.deliveryID == first.id }?.status, .withdrawn)
        XCTAssertEqual(result.first { $0.deliveryID == second.id }?.status, .accepted)
        try await c.shutdown()
    }

    func testApprovalWakeSignedRevocationSuppressesLateAcceptance() async throws {
        let f = try Fixture(), provider = Provider([]), c = try f.coordinator(provider, wakePolicy: wakePolicy())
        try await prepareWakes(f, c); await provider.hold(honorCancellation: false)
        let delivery = try f.delivery()
        _ = try await c.enqueueWake(delivery)
        let task = Task { try await c.deliverWakeBatch(phoneID: id(6), enrollmentEpoch: id(7)) }
        defer { task.cancel() }
        try await until { await provider.wakes.count == 1 }
        try await f.revoke(c, revision: 3)
        await provider.release()
        do { _ = try await task.value; XCTFail("Revoked wake succeeded") } catch {}
        let progress = try await wakeState(c, delivery)
        XCTAssertEqual(progress.status, .withdrawn)
        do { _ = try await c.enqueueWake(f.delivery(2)); XCTFail("Revoked mapping used") }
        catch { XCTAssertEqual(error as? GatewayWakeError, .unavailableMapping) }
        try await c.shutdown()
    }

    func testApprovalWakeUsesTokenRotatedDuringOAuth() async throws {
        let f = try Fixture(), provider = Provider([]), gate = OAuthGate()
        let source = try FCMTokenSource(now: { .now }, refresh: { try await gate.refresh() })
        let c = try f.coordinator(provider, tokenSource: source, wakePolicy: wakePolicy())
        try await prepareWakes(f, c)
        _ = try await c.enqueueWake(f.delivery())
        let task = Task { try await c.deliverWakeBatch(phoneID: id(6), enrollmentEpoch: id(7)) }
        defer { task.cancel() }
        try await until { await gate.started }
        try await f.admit(c, n: 3, token: "rotated")
        try await f.activate(c, n: 3, token: "rotated")
        try await gate.release()
        _ = try await task.value
        let wakes = await provider.wakes
        XCTAssertEqual(try wakeToken(XCTUnwrap(wakes.first)), "rotated")
        try await c.shutdown()
    }

    func testApprovalWakeInvalidTokenRemovesOnlyTheRejectedMapping() async throws {
        for rotate in [false, true] {
            let f = try Fixture(), provider = Provider([]), c = try f.coordinator(provider, wakePolicy: wakePolicy())
            try await prepareWakes(f, c); await provider.hold()
            _ = try await c.enqueueWake(f.delivery())
            let task = Task { try await c.deliverWakeBatch(phoneID: id(6), enrollmentEpoch: id(7)) }
            defer { task.cancel() }
            try await until { await provider.wakes.count == 1 }
            if rotate {
                try await f.admit(c, n: 3, token: "rotated")
                try await f.activate(c, n: 3, token: "rotated")
            }
            await provider.release(result: .registrationInvalid)
            let first = try await task.value
            XCTAssertEqual(first.first?.status, .rejected)
            if rotate {
                _ = try await c.enqueueWake(f.delivery(2))
                let next = try await c.deliverWakeBatch(phoneID: id(6), enrollmentEpoch: id(7))
                XCTAssertEqual(next.first?.status, .accepted)
                let wakes = await provider.wakes
                XCTAssertEqual(try wakeToken(XCTUnwrap(wakes.last)), "rotated")
            } else {
                do { _ = try await c.enqueueWake(f.delivery(2)); XCTFail("Invalid mapping retained") }
                catch { XCTAssertEqual(error as? GatewayWakeError, .unavailableMapping) }
            }
            try await c.shutdown()
        }
    }

    func testApprovalWakeQueueBoundsConflictingReuseAndExpiredReclamation() async throws {
        let f = try Fixture(), provider = Provider([]), c = try f.coordinator(provider, wakePolicy: wakePolicy(entries: 1))
        try await prepareWakes(f, c)
        let first = try f.delivery(deadline: 150)
        _ = try await c.enqueueWake(first)
        do { _ = try await c.enqueueWake(f.delivery(2)); XCTFail("Capacity ignored") }
        catch { XCTAssertEqual(error as? GatewayDeliveryError, .capacityExceeded) }
        do { _ = try await c.enqueueWake(f.delivery(deadline: 200, identifier: first.id)); XCTFail("Deadline renewed") }
        catch { XCTAssertEqual(error as? GatewayWakeError, .conflictingDelivery) }
        f.clock.advance(50)
        let expired = try await c.enqueueWake(first)
        XCTAssertEqual(expired.status, .expired)
        let next = try await c.enqueueWake(f.delivery(2))
        XCTAssertEqual(next.status, .queued)
        try await c.shutdown()
    }

    func testApprovalWakesAndTokenProbesShareCapacityAndPacing() async throws {
        let f = try Fixture(), provider = Provider([]), c = try f.coordinator(provider, wakePolicy: wakePolicy(), maximumFlights: 1)
        try await prepareWakes(f, c); await provider.hold()
        _ = try await c.enqueueWake(f.delivery())
        let task = Task { try await c.deliverWakeBatch(phoneID: id(6), enrollmentEpoch: id(7)) }
        defer { task.cancel() }
        try await until { await provider.wakes.count == 1 }
        try await f.admit(c, n: 3)
        do { _ = try await c.deliverProbe(operationID: id(3), phoneID: id(6)); XCTFail("Shared capacity exceeded") }
        catch { XCTAssertEqual(error as? GatewayDeliveryError, .capacityExceeded) }
        await provider.release(); _ = try await task.value
        let probe = try await c.deliverProbe(operationID: id(3), phoneID: id(6))
        XCTAssertEqual(probe?.status, .accepted)
        let times = await provider.times
        XCTAssertEqual(times.count, 2); XCTAssertGreaterThanOrEqual(times[1] - times[0], 10)
        try await c.shutdown()
    }

    func testApprovalWakeAuthenticationRetryRefreshesOAuthAndKeepsBatch() async throws {
        let f = try Fixture(), provider = Provider([.authenticationRequired, .accepted]), c = try f.coordinator(provider, wakePolicy: wakePolicy())
        try await prepareWakes(f, c)
        _ = try await c.enqueueWake(f.delivery())
        let result = try await c.deliverWakeBatch(phoneID: id(6), enrollmentEpoch: id(7))
        XCTAssertEqual(result.first?.status, .accepted); XCTAssertEqual(result.first?.attempts, 2)
        XCTAssertEqual(f.refreshes.value.withLock { $0 }, 2)
        let wakes = await provider.wakes
        XCTAssertEqual(wakes[0].identifier, wakes[1].identifier)
        try await c.shutdown()
    }

    func testApprovalWakeRevocationLeavesOtherPhoneDeliveryRunning() async throws {
        let f = try Fixture(), provider = Provider([]), c = try f.coordinator(provider, wakePolicy: wakePolicy())
        try await c.replaceTrustedEnrollments([f.enrollment(), f.enrollment(phone: 8)], active: true)
        try await f.admit(c); try await f.activate(c)
        try await f.admit(c, n: 3, phone: 8); try await f.activate(c, n: 3, phone: 8)
        try await c.setPhoneRouting(true); await provider.hold()
        let first = try f.delivery(), second = try f.delivery(2, phone: 8)
        _ = try await c.enqueueWake(first); _ = try await c.enqueueWake(second)
        let a = Task { try await c.deliverWakeBatch(phoneID: id(6), enrollmentEpoch: id(7)) }
        let b = Task { try await c.deliverWakeBatch(phoneID: id(8), enrollmentEpoch: id(7)) }
        defer { a.cancel(); b.cancel() }
        try await until { await provider.wakes.count == 2 }
        try await f.revoke(c, revision: 5)
        await provider.release()
        do { _ = try await a.value; XCTFail("Revoked phone succeeded") } catch {}
        let result = try await b.value
        XCTAssertEqual(result.first?.status, .accepted)
        let state = try await wakeState(c, first)
        XCTAssertEqual(state.status, .withdrawn)
        try await c.shutdown()
    }

    func testApprovalWakeShutdownCancelsWorkAndReleasesStorage() async throws {
        let f = try Fixture(), provider = Provider([]), c = try f.coordinator(provider, wakePolicy: wakePolicy())
        try await prepareWakes(f, c); await provider.hold()
        _ = try await c.enqueueWake(f.delivery())
        let task = Task { try await c.deliverWakeBatch(phoneID: id(6), enrollmentEpoch: id(7)) }
        defer { task.cancel() }
        try await until { await provider.wakes.count == 1 }
        try await c.shutdown()
        do { _ = try await task.value; XCTFail("Shutdown wake succeeded") } catch {}
        let lease = try ProtectedGatewayLease(anchor: f.root.path, relativeDirectory: "store", serviceUID: geteuid(), ancestorUID: geteuid())
        lease.close()
        do { _ = try await c.enqueueWake(f.delivery(2)); XCTFail("Stopped owner accepted") }
        catch { XCTAssertEqual(error as? GatewayDeliveryError, .stopped) }
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
