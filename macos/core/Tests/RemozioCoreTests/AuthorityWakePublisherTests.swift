import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

final class AuthorityWakePublisherTests: XCTestCase, @unchecked Sendable {
    private final class Driver: GatewayRootDriver {
        struct State {
            var calls = 0
            var snapshots: [GatewayHostSnapshot] = []
            var registrations: [PhoneRequestDelivery] = []
            var withdrawals: [UUID] = []
            var rejectRegistrations = 0
            var holdRegistration = false
            var held: (@Sendable (GatewayRootResponse) -> Void)?
            var onRegistration: (@Sendable () throws -> Void)?
            var closed = 0
        }
        let value = Mutex(State())
        func start(closed: @escaping @Sendable () -> Void) {}
        func invoke(_ call: GatewayRootCall, reply: @escaping @Sendable (GatewayRootResponse) -> Void) {
            do {
                let response: GatewayRootResponse?
                switch call {
                case .hello:
                    value.withLock { $0.calls += 1 }; response = .version(3)
                case .synchronize(let bytes):
                    let snapshot = try GatewayHostSnapshot.decode(bytes)
                    value.withLock { $0.calls += 1; $0.snapshots.append(snapshot) }
                    response = .synchronized(true)
                case .command(let bytes):
                    switch try GatewayRootCommand.decode(bytes) {
                    case .registerWake(let delivery):
                        let hook = value.withLock { $0.onRegistration }
                        try hook?()
                        response = try value.withLock { state in
                            state.calls += 1; state.registrations.append(delivery)
                            if state.holdRegistration { state.held = reply; return nil }
                            if state.rejectRegistrations > 0 { state.rejectRegistrations -= 1; return .command(nil) }
                            return .command(try GatewayRootCommand.reply([.boolean(true)], version: 3))
                        }
                    case .withdraw(let id):
                        value.withLock { $0.calls += 1; $0.withdrawals.append(id) }
                        response = .command(try GatewayRootCommand.reply([.boolean(true)]))
                    default: return reply(.failed)
                    }
                }
                if let response { reply(response) }
            } catch { reply(.failed) }
        }
        func close() { value.withLock { $0.closed += 1 } }
    }

    private final class Fixture: @unchecked Sendable {
        struct State { var time: UInt64 = 110; var mode = RoutingMode.away }
        let state = Mutex(State())
        let root: URL
        let journal: AuthorityJournal
        let epoch = UUID()
        let writer: AuditEpochWriter
        let registration: GatewayRegistrationIdentity
        let request: IssuedRequestPayload
        init(deadline: UInt64 = 200) throws {
            let key = P256.Signing.PrivateKey()
            let limits = try CBORLimits(maxBytes: 4096, maxDepth: 12, maxItems: 256)
            let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1)
            let capabilities = ContractCapabilities(contracts: [contract: []])
            registration = try GatewayRegistrationIdentity(ownerID: Self.id(3), macID: Self.id(1), accountID: Self.id(2),
                gatewayID: Self.id(4), lifecycleEpoch: Self.id(8), rootPublicKey: key.publicKey.x963Representation)
            guard let canonical = realpath(FileManager.default.temporaryDirectory.path, nil) else { throw CocoaError(.fileReadUnknown) }
            defer { free(canonical) }
            root = URL(fileURLWithPath: String(cString: canonical)).appendingPathComponent(UUID().uuidString)
            let directory = root.appendingPathComponent("store").path
            try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            for name in ["writer.lock", "journal.sqlite"] {
                let fd = Darwin.open(directory + "/" + name, O_CREAT | O_EXCL | O_WRONLY, 0o600)
                guard fd >= 0 else { throw CocoaError(.fileWriteUnknown) }; Darwin.close(fd)
            }
            let db = try JournalDatabase(lease: ProtectedJournalLease(anchor: root.path, relativeDirectory: "store", owner: getuid()),
                macID: Self.id(1), accountID: Self.id(2), recordLimits: limits, descriptorLimits: limits, decisionLimits: limits,
                maximumConsumptions: 30, busyMilliseconds: 100, initialize: true)
            let revision = try db.write { try $0.configureApprovalAuthority(capabilities: capabilities, allowedContracts: [contract]) }
            let descriptor = try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
                0: .unsigned(1), 1: .bytes(Self.id(1)), 2: .bytes(Self.id(2)), 3: .bytes(Self.id(3)),
                4: .unsigned(3), 5: .unsigned(1), 6: .null, 7: .null, 8: .null]), limits: limits), limits: limits)
            let writer = try db.write { try $0.createEpoch(descriptor) }
            self.writer = writer
            let enrollment = try StoredApprovalEnrollment(epoch: Self.id(9), notificationTag: Self.id(10, count: 32),
                identityPublicKey: key.publicKey.x963Representation,
                approval: ApprovalEnrollment(phoneID: Self.id(5), active: true, capabilities: capabilities,
                    keys: [EnrolledApprovalKey(id: Self.id(6), keyClass: .biometric, publicKey: key.publicKey.x963Representation),
                        EnrolledApprovalKey(id: Self.id(7), keyClass: .decision,
                            publicKey: P256.Signing.PrivateKey().publicKey.x963Representation)]))
            _ = try db.write { try $0.addApprovalEnrollment(enrollment, expectedTrustRevision: revision,
                eventID: Self.id(30), receiptTimeMs: nil, writer: writer, expectedAuditHead: 0) }
            let owner = try ApprovalRequestCoordinator(database: db, writer: writer, clockEpoch: epoch, maximumRequests: 8,
                maximumRetainedBytes: 32768, requestLimits: limits, captureLimits: limits, decisionLimits: limits,
                signingLimits: limits, auditLimits: limits)
            request = try owner.admitFixture(ApprovalRequestDraft(contract: contract, requiredFeatures: [], capture: Data([0xa0]),
                actions: [.init(choice: .execute, scope: .currentRequest), .init(choice: .decline, scope: .currentRequest)],
                firstObservedAt: AuthorityMoment(epoch: epoch, milliseconds: 100), deadlineMilliseconds: deadline,
                createdUnixMilliseconds: 1000, expiresUnixMilliseconds: 1000 + deadline - 100),
                now: AuthorityMoment(epoch: epoch, milliseconds: 110), receiptTimeMs: nil)
            journal = AuthorityJournal(requests: owner)
        }
        deinit { try? journal.close(); try? FileManager.default.removeItem(at: root) }
        static func id(_ n: UInt8, count: Int = 16) -> Data { Data(repeating: n, count: count) }
        func now() -> AuthorityMoment { .init(epoch: epoch, milliseconds: state.withLock { $0.time }) }
        func routing() throws -> PresenceRouting {
            var router = PresenceRouter(configuration: try PresenceConfiguration(observationLifetimeMilliseconds: 100, unavailableGraceMilliseconds: 100))
            return router.evaluate(mode: state.withLock { $0.mode }, snapshot: PresenceSnapshot(),
                now: PresenceMoment(epoch: epoch, milliseconds: state.withLock { $0.time }))
        }
        func publisher(_ driver: Driver, lease: UInt64 = 1000) throws -> AuthorityWakePublisher {
            try .init(journal: journal, channel: GatewayRootChannel(driver: driver), registration: registration,
                leaseMilliseconds: lease, clock: { self.now() }, routing: { try self.routing() })
        }
        func cancelAndForget() throws {
            try journal.withRequests { owner in
                _ = try owner.retirePending(requestID: self.request.requestID, reason: .cancelled, now: self.now(), receiptTimeMs: nil)
                try owner.forgetTerminal(requestID: self.request.requestID)
            }
        }
        func revoke() throws {
            try journal.withRequests { owner in
                let revision = try owner.database.read { try $0.approvalTrustSnapshot().revision }
                _ = try owner.database.write { try $0.revokeApprovalEnrollment(phoneID: Self.id(5), epoch: Self.id(9),
                    expectedTrustRevision: revision, eventID: Self.id(31), receiptTimeMs: nil, writer: self.writer, expectedAuditHead: 2) }
            }
        }
    }

    func testRegisteredGrantUsesCurrentJournalLeaseAndIsNotRegisteredAgain() async throws {
        let fixture = try Fixture(), driver = Driver(), publisher = try fixture.publisher(driver)
        try await publisher.start(); try await publisher.reconcile()
        let grant = try XCTUnwrap(driver.value.withLock { $0.registrations.first })
        let hints = try await publisher.readyDeliveryIDs()
        XCTAssertEqual(hints, [grant.id]); XCTAssertEqual(grant.requestID, fixture.request.requestID)
        XCTAssertEqual(grant.deadlineMilliseconds, 200)
        XCTAssertEqual(grant.admittedAt.epoch, fixture.epoch)
        try await publisher.reconcile()
        XCTAssertEqual(driver.value.withLock { $0.registrations }, [grant])
        let snapshots = driver.value.withLock { $0.snapshots }
        XCTAssertEqual(snapshots.map(\.sequence), [1, 2, 3, 4])
        XCTAssertTrue(snapshots.allSatisfy { $0.phoneRouting && $0.registration == fixture.registration })
        XCTAssertEqual(snapshots.last?.enrollments.first?.phoneID, Fixture.id(5))
        await publisher.close()
    }
    func testRejectedRegistrationRetriesOriginalGrantWithoutRenewingRequest() async throws {
        let fixture = try Fixture(), driver = Driver(), publisher = try fixture.publisher(driver)
        driver.value.withLock { $0.rejectRegistrations = 1 }
        try await publisher.start(); try await publisher.reconcile()
        let before = try await publisher.readyDeliveryIDs(); XCTAssertTrue(before.isEmpty)
        fixture.state.withLock { $0.time = 150 }
        try await publisher.reconcile()
        let registrations = driver.value.withLock { $0.registrations }
        XCTAssertEqual(registrations.count, 2); XCTAssertEqual(registrations[0], registrations[1])
        XCTAssertEqual(registrations[1].deadlineMilliseconds, 200)
        let after = try await publisher.readyDeliveryIDs(); XCTAssertEqual(after, [registrations[0].id])
        await publisher.close()
    }
    func testCancellationOrUnenrollmentDuringAcknowledgmentWithdrawsBeforeHint() async throws {
        for revoke in [false, true] {
            let fixture = try Fixture(), driver = Driver(), publisher = try fixture.publisher(driver)
            driver.value.withLock { $0.onRegistration = { if revoke { try fixture.revoke() } else { try fixture.cancelAndForget() } } }
            try await publisher.start(); try await publisher.reconcile()
            let grant = try XCTUnwrap(driver.value.withLock { $0.registrations.first })
            XCTAssertEqual(driver.value.withLock { $0.withdrawals }, [grant.id])
            let hints = try await publisher.readyDeliveryIDs(); XCTAssertTrue(hints.isEmpty)
            XCTAssertTrue(try fixture.journal.withRequests {
                try $0.reconcileWakePublications(routing: fixture.routing(), now: fixture.now(), receiptTimeMs: nil).withdrawals.isEmpty
            })
            await publisher.close()
        }
    }
    func testExpiryDuringAcknowledgmentWithdrawsOriginalGrant() async throws {
        let fixture = try Fixture(), driver = Driver(), publisher = try fixture.publisher(driver)
        driver.value.withLock { $0.onRegistration = { fixture.state.withLock { $0.time = 200 } } }
        try await publisher.start(); try await publisher.reconcile()
        let grant = try XCTUnwrap(driver.value.withLock { $0.registrations.first })
        XCTAssertEqual(driver.value.withLock { $0.withdrawals }, [grant.id])
        let hints = try await publisher.readyDeliveryIDs(); XCTAssertTrue(hints.isEmpty)
        XCTAssertEqual(try fixture.journal.withRequests { try $0.state(requestID: fixture.request.requestID).phase }, .expired)
        await publisher.close()
    }
    func testPresenceDuringAcknowledgmentSuppressesHintsAndSynchronizesGateway() async throws {
        let fixture = try Fixture(), driver = Driver(), publisher = try fixture.publisher(driver)
        driver.value.withLock { $0.onRegistration = { fixture.state.withLock { $0.mode = .present } } }
        try await publisher.start(); try await publisher.reconcile()
        let hints = try await publisher.readyDeliveryIDs(); XCTAssertTrue(hints.isEmpty)
        XCTAssertEqual(driver.value.withLock { $0.snapshots.last?.phoneRouting }, false)
        driver.value.withLock { $0.onRegistration = nil }
        fixture.state.withLock { $0.mode = .away; $0.time = 150 }
        // The changed route is not advertised until the gateway acknowledges it.
        let before = try await publisher.readyDeliveryIDs(); XCTAssertTrue(before.isEmpty)
        try await publisher.reconcile()
        let grant = try XCTUnwrap(driver.value.withLock { $0.registrations.first })
        let after = try await publisher.readyDeliveryIDs(); XCTAssertEqual(after, [grant.id])
        XCTAssertEqual(driver.value.withLock { $0.registrations.count }, 1)
        await publisher.close()
    }
    func testLeaseExpiryDuringAcknowledgmentRetiresWakeOnly() async throws {
        let fixture = try Fixture(deadline: 5000), driver = Driver(), publisher = try fixture.publisher(driver)
        driver.value.withLock { $0.onRegistration = { fixture.state.withLock { $0.time = 1110 } } }
        try await publisher.start()
        do { try await publisher.reconcile(); XCTFail("An expired lease published a hint") }
        catch { XCTAssertEqual(error as? AuthorityWakePublisherError, .expiredLease) }
        do { _ = try await publisher.readyDeliveryIDs(); XCTFail("A closed publisher exposed a hint") }
        catch { XCTAssertEqual(error as? AuthorityWakePublisherError, .closed) }
        XCTAssertEqual(driver.value.withLock { $0.closed }, 1)
        XCTAssertEqual(try fixture.journal.withRequests { try $0.state(requestID: fixture.request.requestID).phase }, .queued)
        XCTAssertThrowsError(try fixture.journal.withRequests {
            try $0.reconcileWakePublications(routing: fixture.routing(), now: fixture.now(), receiptTimeMs: nil)
        })
    }
    func testClosingDuringRegistrationRejectsLateAcknowledgmentAndConcurrentDrain() async throws {
        let fixture = try Fixture(), driver = Driver(), publisher = try fixture.publisher(driver)
        driver.value.withLock { $0.holdRegistration = true }
        try await publisher.start()
        let drain = Task { try await publisher.reconcile() }
        let deadline = ContinuousClock.now.advanced(by: .seconds(2))
        while driver.value.withLock({ $0.held == nil }) && ContinuousClock.now < deadline { await Task.yield() }
        let reply = try XCTUnwrap(driver.value.withLock { $0.held })
        do { try await publisher.reconcile(); XCTFail("Concurrent drain") }
        catch { XCTAssertEqual(error as? AuthorityWakePublisherError, .busy) }
        await publisher.close()
        reply(.command(try GatewayRootCommand.reply([.boolean(true)], version: 3)))
        do { try await drain.value; XCTFail("Closed drain resumed") } catch {}
        do { _ = try await publisher.readyDeliveryIDs(); XCTFail("Late hint") } catch {}
        XCTAssertEqual(driver.value.withLock { $0.registrations.count }, 1)
        XCTAssertEqual(driver.value.withLock { $0.snapshots.count }, 1)
        XCTAssertEqual(driver.value.withLock { $0.closed }, 1)
    }
    func testClosedJournalCannotExposePreviouslyRegisteredHint() async throws {
        let fixture = try Fixture(), driver = Driver(), publisher = try fixture.publisher(driver)
        try await publisher.start(); try await publisher.reconcile()
        try fixture.journal.close()
        do { _ = try await publisher.readyDeliveryIDs(); XCTFail("Closed journal returned a grant") } catch {}
        await publisher.close()
    }
    func testPublisherFeedComposesWithNegotiatedRootEndpointAndReflectsTerminalForget() async throws {
        let fixture = try Fixture(), driver = Driver(), publisher = try fixture.publisher(driver)
        try await publisher.start(); try await publisher.reconcile()
        let feed = publisher.hintFeed, binding = feed.binding
        let trust = DirectApprovalTrust(macID: binding.macID, accountID: binding.accountID, revision: UUID(), peers: [])
        let endpoint = try AuthorityXPCEndpoint(macID: binding.macID, accountID: binding.accountID, budget: AuthorityXPCWorkBudget(),
            verify: {}, invalidate: {}, snapshot: { trust }, validate: { _ in false }, wakeHints: { try feed.current() })
        endpoint.hello { XCTAssertEqual($0, 1) }
        endpoint.requestWakeVersion { XCTAssertEqual($0, 1) }
        let response = Mutex<Data?>(nil)
        endpoint.wakeDeliveryHints { bytes in response.withLock { $0 = bytes } }
        let bytes = try XCTUnwrap(response.withLock { $0 })
        let hint = try AuthorityWakeHints.decode(bytes, expectedBinding: binding)
        XCTAssertEqual(hint.deliveryIDs, driver.value.withLock { $0.registrations.map(\.id) })
        try fixture.cancelAndForget()
        endpoint.wakeDeliveryHints { bytes in response.withLock { $0 = bytes } }
        let terminal = try AuthorityWakeHints.decode(XCTUnwrap(response.withLock { $0 }), expectedBinding: binding)
        XCTAssertTrue(terminal.deliveryIDs.isEmpty)
        try await publisher.reconcile()
        XCTAssertEqual(driver.value.withLock { $0.withdrawals }, hint.deliveryIDs)
        await publisher.close()
        endpoint.wakeDeliveryHints { XCTAssertNil($0) }
    }
    func testServiceShutdownCancelsRunningRegistrationBeforeClosingRequestJournal() async throws {
        let fixture = try Fixture(), driver = Driver(), publisher = try fixture.publisher(driver)
        driver.value.withLock { $0.holdRegistration = true }
        let starts = Mutex(0), closes = Mutex(0), feed = publisher.hintFeed
        let service = AuthorityWakeService(publisher: publisher, interval: 100, startRequests: { starts.withLock { $0 += 1 } }, closeRequests: {
            XCTAssertThrowsError(try feed.current())
            closes.withLock { $0 += 1 }
            try fixture.journal.close()
        })
        try await service.start()
        let deadline = ContinuousClock.now.advanced(by: .seconds(2))
        while driver.value.withLock({ $0.held == nil }), ContinuousClock.now < deadline { await Task.yield() }
        XCTAssertNotNil(driver.value.withLock { $0.held })
        try await service.close(); try await service.close()
        XCTAssertEqual(starts.withLock { $0 }, 1); XCTAssertEqual(closes.withLock { $0 }, 1)
        XCTAssertEqual(driver.value.withLock { $0.closed }, 1)
    }
}
