import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class AuthorityPresenceXPCTests: XCTestCase, @unchecked Sendable {
    private enum Failure: Error { case fixture, denied }
    private final class Box<T>: @unchecked Sendable {
        private let lock = NSLock()
        private var stored: T
        init(_ value: T) { stored = value }
        var value: T { get { lock.withLock { stored } } set { lock.withLock { stored = newValue } } }
    }
    private final class Environment: @unchecked Sendable {
        let epoch = UUID()
        let time = Box<UInt64>(100)
        let denied = Box(false)
        let selfDenied = Box(false)
        let verified = Box(0)
        let invalidated = Box(0)
        func now() -> AuthorityMoment { .init(epoch: epoch, milliseconds: time.value) }
        func verify() throws { verified.value += 1; if denied.value { throw Failure.denied } }
    }
    private final class EndpointDriver: PresenceClientDriver, Sendable {
        let endpoint: AuthorityPresenceXPCEndpoint
        let loseModeReply: Bool
        init(endpoint: AuthorityPresenceXPCEndpoint, loseModeReply: Bool = false) { self.endpoint = endpoint; self.loseModeReply = loseModeReply }
        func start(closed: @escaping @Sendable () -> Void) {}
        func invoke(_ call: PresenceClientCall, reply: @escaping @Sendable (PresenceClientReply) -> Void) {
            switch call {
            case .hello: endpoint.hello { reply(.version($0)) }
            case .current: endpoint.current { reply(.status($0)) }
            case .publish(let bytes): endpoint.publish(bytes) { reply(.status($0)) }
            case .setMode(let bytes): endpoint.setMode(bytes) { [loseModeReply] in if !loseModeReply { reply(.status($0)) } }
            }
        }
        func close() { endpoint.close() }
    }
    private final class Fixture {
        let root: URL
        let environment = Environment()
        let journal: AuthorityJournal
        let presence: AuthorityPresenceRuntime
        let access: AuthorityPresenceAccess
        let policy: XPCPeerPolicy
        let binding: AuthorityPresenceBinding
        let limits: CBORLimits
        var mac: Data { Data(repeating: 1, count: 16) }
        var account: Data { Data(repeating: 2, count: 16) }
        init() throws {
            let mac = Data(repeating: 1, count: 16), account = Data(repeating: 2, count: 16), environment = self.environment
            guard let canonical = realpath(FileManager.default.temporaryDirectory.path, nil) else { throw Failure.fixture }
            defer { free(canonical) }
            root = URL(fileURLWithPath: String(cString: canonical)).appendingPathComponent(UUID().uuidString)
            let directory = root.appendingPathComponent("store").path
            try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            for name in ["writer.lock", "journal.sqlite"] {
                let fd = Darwin.open(directory + "/" + name, O_CREAT | O_EXCL | O_WRONLY, 0o600)
                guard fd >= 0 else { throw Failure.fixture }; Darwin.close(fd)
            }
            limits = try .init(maxBytes: 16384, maxDepth: 12, maxItems: 1024)
            let db = try JournalDatabase(lease: .init(anchor: root.path, relativeDirectory: "store", owner: getuid()),
                macID: mac, accountID: account, recordLimits: limits, descriptorLimits: limits, decisionLimits: limits,
                maximumConsumptions: 20, busyMilliseconds: 100, initialize: true,
                routingPolicy: .init(clockEpoch: environment.epoch, challengeLifetimeMillis: 1000, maximumOperations: 20,
                    payloadLimits: limits, signingLimits: limits))
            let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1)
            _ = try db.write { try $0.configureApprovalAuthority(capabilities: .init(contracts: [contract: []]), allowedContracts: [contract]) }
            let descriptor = try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(mac),
                2: .bytes(account), 3: .bytes(Data(repeating: 3, count: 16)), 4: .unsigned(1), 5: .unsigned(1),
                6: .null, 7: .null, 8: .null]), limits: limits), limits: limits)
            let writer = try db.write { try $0.createEpoch(descriptor) }
            let app = try Self.appEntry()
            _ = try db.write { try $0.installCodePolicy(.init(entries: [app]), expectedRevision: nil) }
            let owner = try ApprovalRequestCoordinator(database: db, writer: writer, clockEpoch: environment.epoch,
                maximumRequests: 4, maximumRetainedBytes: 16384, requestLimits: limits, captureLimits: limits,
                decisionLimits: limits, signingLimits: limits, auditLimits: limits)
            journal = AuthorityJournal(requests: owner)
            presence = AuthorityPresenceRuntime(configuration: try .init(macID: mac, accountID: account, ownerUID: 501,
                policy: .init(observationLifetimeMilliseconds: 1000, unavailableGraceMilliseconds: 0)), clockEpoch: environment.epoch)
            policy = try .init(teamID: app.teamID, componentIdentifier: app.identifier, approvedCodeDirectoryHashes: [app.codeDirectoryHash], expectedUserID: 501)
            access = try AuthorityPresenceAccess(journal: journal, presence: presence, appPolicy: policy, now: { environment.now() },
                validateSelf: { _ in if environment.selfDenied.value { throw Failure.denied } })
            binding = try .init(macID: mac, accountID: account, clockEpoch: environment.epoch, connectionID: UUID())
        }
        deinit { presence.close(); try? journal.close(); try? FileManager.default.removeItem(at: root) }
        static func appEntry(generation: UInt64 = 1, active: Bool = true) throws -> AuthorityCodeEntry {
            try .init(role: .app, teamID: "ABCDEFGHIJ", identifier: "dev.remozio.app", installedGeneration: generation,
                minimumGeneration: generation, codeDirectoryHash: Data(repeating: UInt8(generation), count: 20), active: active)
        }
        func endpoint(binding received: AuthorityPresenceBinding? = nil) throws -> AuthorityPresenceXPCEndpoint {
            let binding = received ?? self.binding, environment = self.environment, access = self.access
            return try AuthorityPresenceXPCEndpoint(binding: binding, budget: .init(maximum: 1), verify: { try environment.verify() },
                verifyCurrent: { try access.verifyCurrent() }, invalidate: { environment.invalidated.value += 1 },
                withdraw: { access.withdraw(observer: binding.connectionID) }, status: { try access.status(binding: binding) },
                publish: { try access.publish($0) }, setMode: { try access.setMode($0) })
        }
        func current(_ endpoint: AuthorityPresenceXPCEndpoint) throws -> AuthorityPresenceStatus {
            let result = Box<Data?>(nil)
            endpoint.current { result.value = $0 }
            return try AuthorityPresenceCodec.decodeStatus(XCTUnwrap(result.value), expectedMacID: mac, expectedAccountID: account)
        }
        func mode(_ mode: RoutingMode, sequence: UInt64 = 1, revision: UInt64 = 0, binding received: AuthorityPresenceBinding? = nil) throws -> Data {
            try AuthorityPresenceCodec.encodeModeChange(binding: received ?? binding, sequence: sequence, mode: mode, expectedRevision: revision)
        }
        func publication(sequence: UInt64 = 1, sampledAt: UInt64? = nil, binding received: AuthorityPresenceBinding? = nil) throws -> Data {
            let binding = received ?? self.binding, time = sampledAt ?? environment.time.value
            return try AuthorityPresenceCodec.encodePublication(binding: binding, sequence: sequence,
                sampledAt: .init(epoch: binding.clockEpoch, milliseconds: time),
                snapshot: .init(remoteWorkspace: .init(.usable, observedAt: .init(epoch: binding.clockEpoch, milliseconds: time))))
        }
        func records() throws -> [AuditEventMetadata] {
            let limits = self.limits
            return try journal.read { try $0.page(epoch: Data(repeating: 3, count: 16), after: 0,
                maximumRecords: 10, maximumBytes: 16384).canonicalRecords.map { try AuditEventMetadata.decode($0, limits: limits) } }
        }
    }

    func testClientControlsCommitThroughRealJournalAndRecoverALostReplyWithoutReplay() async throws {
        let f = try Fixture(), endpoint = try f.endpoint(), environment = f.environment
        let channel = AuthorityPresenceChannel(driver: EndpointDriver(endpoint: endpoint), macID: f.mac, accountID: f.account,
            sample: { _ in environment.now() })
        let initial = try await channel.start()
        let present = try await channel.setMode(.present, expectedRevision: initial.state.revision)
        XCTAssertEqual(present.state, .init(mode: .present, revision: 1)); XCTAssertEqual(present.routing.destination, .localMac)
        await channel.close()
        let secondBinding = try AuthorityPresenceBinding(macID: f.mac, accountID: f.account, clockEpoch: environment.epoch, connectionID: UUID())
        let second = try f.endpoint(binding: secondBinding)
        let interrupted = AuthorityPresenceChannel(driver: EndpointDriver(endpoint: second, loseModeReply: true), macID: f.mac,
            accountID: f.account, timeoutMilliseconds: 100, sample: { _ in environment.now() })
        _ = try await interrupted.start()
        do { _ = try await interrupted.setMode(.away, expectedRevision: 1); XCTFail() }
        catch { XCTAssertEqual(error as? AuthorityPresenceChannelError, .timedOut) }
        let freshBinding = try AuthorityPresenceBinding(macID: f.mac, accountID: f.account, clockEpoch: environment.epoch, connectionID: UUID())
        let fresh = try f.endpoint(binding: freshBinding)
        let recovered = AuthorityPresenceChannel(driver: EndpointDriver(endpoint: fresh), macID: f.mac, accountID: f.account,
            sample: { _ in environment.now() })
        let current = try await recovered.start()
        XCTAssertEqual(current.state, .init(mode: .away, revision: 2)); XCTAssertEqual(current.routing.destination, .phones)
        XCTAssertEqual(try f.records().count, 2)
        await recovered.close()
    }

    func testVerifiedHandshakeAndEverySelectorUseTheRealOwner() throws {
        let f = try Fixture(), endpoint = try f.endpoint()
        endpoint.hello { XCTAssertEqual($0, 1) }
        let initial = try f.current(endpoint)
        XCTAssertEqual(initial.binding, f.binding); XCTAssertEqual(initial.state, .init(mode: .automatic, revision: 0))
        XCTAssertEqual(initial.routing.reason, .detectorUnavailable)
        endpoint.publish(try f.publication()) { XCTAssertNotNil($0) }
        let result = Box<Data?>(nil)
        endpoint.setMode(try f.mode(.away, sequence: 2)) { result.value = $0 }
        let away = try AuthorityPresenceCodec.decodeStatus(XCTUnwrap(result.value), expectedMacID: f.mac, expectedAccountID: f.account)
        XCTAssertEqual(away.state, .init(mode: .away, revision: 1)); XCTAssertEqual(away.routing.reason, .manualAway)
        XCTAssertEqual(f.environment.verified.value, 4)
        XCTAssertEqual(try f.records().map(\.authentication), [.localUser])
        XCTAssertEqual(try f.records().map(\.kind), [.routingChanged])
        endpoint.close(); endpoint.close(); XCTAssertEqual(f.environment.invalidated.value, 1)
    }
    func testMissingHandshakeOrFailedInvocationCannotReadOrMutate() throws {
        for selector in 0..<4 {
            let f = try Fixture(), endpoint = try f.endpoint()
            if selector == 0 { f.environment.denied.value = true; endpoint.hello { XCTAssertEqual($0, 0) } }
            else if selector == 1 { endpoint.current { XCTAssertNil($0) } }
            else if selector == 2 { endpoint.publish(try f.publication()) { XCTAssertNil($0) } }
            else { endpoint.setMode(try f.mode(.present)) { XCTAssertNil($0) } }
            XCTAssertTrue(try f.records().isEmpty)
            XCTAssertEqual(try f.journal.withRequests { try $0.localRoutingState().revision }, 0)
            XCTAssertEqual(f.environment.invalidated.value, 1)
        }
        let f = try Fixture(), endpoint = try f.endpoint()
        endpoint.hello { XCTAssertEqual($0, 1) }
        f.environment.denied.value = true
        endpoint.setMode(try f.mode(.present)) { XCTAssertNil($0) }
        XCTAssertTrue(try f.records().isEmpty)
    }
    func testStaleRevisionReturnsCurrentStatusWithoutSilentlyOverwriting() throws {
        let f = try Fixture(), endpoint = try f.endpoint(), result = Box<Data?>(nil)
        endpoint.hello { XCTAssertEqual($0, 1) }
        let moment = f.environment.now()
        _ = try f.journal.withRequests { try $0.setLocalRoutingMode(.present, expectedRevision: 0, now: moment, receiptTimeMs: nil) }
        endpoint.setMode(try f.mode(.away)) { result.value = $0 }
        let conflict = try AuthorityPresenceCodec.decodeStatus(XCTUnwrap(result.value), expectedMacID: f.mac, expectedAccountID: f.account)
        XCTAssertTrue(conflict.conflict); XCTAssertEqual(conflict.state, .init(mode: .present, revision: 1))
        XCTAssertEqual(conflict.routing.destination, .localMac)
        endpoint.setMode(try f.mode(.away, sequence: 2, revision: 1)) { XCTAssertNotNil($0) }
        XCTAssertEqual(try f.current(endpoint).state, .init(mode: .away, revision: 2))
        XCTAssertEqual(try f.records().count, 2); XCTAssertEqual(f.environment.invalidated.value, 0)
    }
    func testWrongScopeEpochConnectionAndSequenceCannotChangeMode() throws {
        for change in 0..<6 {
            let f = try Fixture(), endpoint = try f.endpoint()
            endpoint.hello { XCTAssertEqual($0, 1) }
            let binding = try AuthorityPresenceBinding(macID: change == 0 ? Data(repeating: 9, count: 16) : f.mac,
                accountID: change == 1 ? Data(repeating: 9, count: 16) : f.account,
                clockEpoch: change == 2 ? UUID() : f.binding.clockEpoch, connectionID: change == 3 ? UUID() : f.binding.connectionID)
            endpoint.setMode(try f.mode(.present, sequence: change == 4 ? 2 : change == 5 ? UInt64.max : 1, binding: binding)) { XCTAssertNil($0) }
            XCTAssertTrue(try f.records().isEmpty); XCTAssertEqual(f.environment.invalidated.value, 1)
        }
    }
    func testPublicationReplayClosesAndWithdrawsItsObservation() throws {
        let f = try Fixture(), endpoint = try f.endpoint(), payload = try f.publication()
        endpoint.hello { XCTAssertEqual($0, 1) }
        endpoint.publish(payload) { XCTAssertNotNil($0) }
        XCTAssertEqual(try f.current(endpoint).routing.reason, .remoteDesktop)
        endpoint.publish(payload) { XCTAssertNil($0) }
        XCTAssertEqual(try f.access.status(binding: f.binding).routing.reason, .detectorUnavailable)
        XCTAssertTrue(try f.records().isEmpty)
    }
    func testOldConnectionClosureCannotRemoveNewerObservation() throws {
        let f = try Fixture(), first = try f.endpoint()
        let next = try AuthorityPresenceBinding(macID: f.mac, accountID: f.account, clockEpoch: f.binding.clockEpoch, connectionID: UUID())
        let second = try f.endpoint(binding: next)
        first.hello { XCTAssertEqual($0, 1) }; second.hello { XCTAssertEqual($0, 1) }
        first.publish(try f.publication()) { XCTAssertNotNil($0) }
        f.environment.time.value = 110
        second.publish(try f.publication(binding: next)) { XCTAssertNotNil($0) }
        first.close()
        XCTAssertEqual(try f.current(second).routing.reason, .remoteDesktop)
        second.close()
        XCTAssertEqual(try f.access.status(binding: next).routing.reason, .detectorUnavailable)
    }
    func testChangedAppPolicyAndInvalidRootCodePreventAllAccess() throws {
        for selector in 0..<3 {
            let f = try Fixture(), endpoint = try f.endpoint()
            endpoint.hello { XCTAssertEqual($0, 1) }
            let snapshot = try XCTUnwrap(f.journal.read { try $0.codePolicy() })
            let replacement = try Fixture.appEntry(generation: 2)
            _ = try f.journal.write { try $0.installCodePolicy(.init(entries: [replacement]), expectedRevision: snapshot.revision) }
            if selector == 0 { endpoint.current { XCTAssertNil($0) } }
            else if selector == 1 { endpoint.publish(try f.publication()) { XCTAssertNil($0) } }
            else { endpoint.setMode(try f.mode(.present)) { XCTAssertNil($0) } }
            XCTAssertTrue(try f.records().isEmpty)
        }
        let f = try Fixture(), endpoint = try f.endpoint()
        endpoint.hello { XCTAssertEqual($0, 1) }; f.environment.selfDenied.value = true
        endpoint.setMode(try f.mode(.present)) { XCTAssertNil($0) }
        XCTAssertTrue(try f.records().isEmpty)
    }
    func testFutureAndExpiredSamplesCannotReplacePresence() throws {
        for time: UInt64 in [101, 1100] {
            let f = try Fixture(), endpoint = try f.endpoint()
            endpoint.hello { XCTAssertEqual($0, 1) }
            if time == 1100 { f.environment.time.value = time }
            endpoint.publish(try f.publication(sampledAt: time == 101 ? 101 : 100)) { XCTAssertNil($0) }
            XCTAssertEqual(try f.access.status(binding: f.binding).routing.reason, .detectorUnavailable)
            XCTAssertTrue(try f.records().isEmpty)
        }
    }
    func testCodecPreservesUnknownSignalsAndRejectsUnknownFieldsVersionsAndValues() throws {
        let f = try Fixture(), at = PresenceMoment(epoch: f.binding.clockEpoch, milliseconds: 100)
        let snapshot = PresenceSnapshot(remoteWorkspace: .init(.unsupported, observedAt: at), locked: .init(false, observedAt: at),
            displays: .init([.asleep, .awake(.readable), .awake(.dark), .awake(.unknown), .unknown], observedAt: at),
            lastQualifyingInputMilliseconds: .init(50, observedAt: at))
        let bytes = try AuthorityPresenceCodec.encodePublication(binding: f.binding, sequence: 1, sampledAt: f.environment.now(), snapshot: snapshot)
        let decoded = try AuthorityPresenceCodec.decodePublication(bytes)
        XCTAssertEqual(decoded.snapshot.displays?.value.count, 5); XCTAssertEqual(decoded.snapshot.locked?.value, false)
        XCTAssertEqual(decoded.snapshot.lastQualifyingInputMilliseconds?.value, 50)
        let empty = try AuthorityPresenceCodec.decodePublication(AuthorityPresenceCodec.encodePublication(binding: f.binding,
            sequence: 1, sampledAt: f.environment.now(), snapshot: .init()))
        XCTAssertNil(empty.snapshot.locked); XCTAssertNil(empty.snapshot.remoteWorkspace); XCTAssertNil(empty.snapshot.displays)
        guard case .map(let original) = try DeterministicCBOR.decode(bytes, limits: f.limits) else { return XCTFail() }
        for (field, value): (UInt64, CBORValue) in [(0, .unsigned(2)), (8, .unsigned(2)), (7, .unsigned(3)),
            (9, .array(Array(repeating: .unsigned(0), count: 33))), (10, .unsigned(101)), (11, .null)] {
            var fields = original; fields[field] = value
            XCTAssertThrowsError(try AuthorityPresenceCodec.decodePublication(DeterministicCBOR.encode(.map(fields), limits: f.limits)))
        }
        XCTAssertThrowsError(try AuthorityPresenceCodec.decodePublication(Data(repeating: 0, count: 4097)))
        XCTAssertThrowsError(try AuthorityPresenceCodec.decodeModeChange(bytes))
    }
    func testReplyCanStartNextOperationAtCapacityOne() throws {
        let f = try Fixture(), endpoint = try f.endpoint(), payload = try f.mode(.present)
        endpoint.hello { version in
            XCTAssertEqual(version, 1)
            endpoint.current { current in
                XCTAssertNotNil(current)
                endpoint.setMode(payload) { XCTAssertNotNil($0) }
            }
        }
        XCTAssertEqual(try f.current(endpoint).state.mode, .present); XCTAssertEqual(f.environment.invalidated.value, 0)
    }
}
