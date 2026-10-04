import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

@MainActor
final class DirectApprovalHostTests: XCTestCase {
    private enum Failure: Error { case injected }
    nonisolated private static func id(_ n: UInt8) -> Data { Data(repeating: n, count: 16) }
    nonisolated private static func capabilities() throws -> ContractCapabilities {
        try ContractCapabilities(contracts: [RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1): []])
    }
    private final class FakeListener: OwnedDirectListener, @unchecked Sendable {
        let generation: UUID
        let peers: [DirectApprovalPeer]
        let event: @Sendable (DirectListenerEvent) -> Void
        private let lock = NSLock()
        private var closed = false
        var isClosed: Bool { lock.withLock { closed } }
        init(_ generation: UUID, _ peers: [DirectApprovalPeer], _ event: @escaping @Sendable (DirectListenerEvent) -> Void) {
            self.generation = generation; self.peers = peers; self.event = event
        }
        func start() throws { }
        func close() { lock.withLock { closed = true } }
    }
    private final class Factory: @unchecked Sendable {
        private let lock = NSLock()
        private var values: [FakeListener] = []
        private var fail = false
        var listeners: [FakeListener] { lock.withLock { values } }
        func failNext() { lock.withLock { fail = true } }
        func make(_ generation: UUID, _ peers: [DirectApprovalPeer], _ event: @escaping @Sendable (DirectListenerEvent) -> Void) throws -> FakeListener {
            try lock.withLock {
                if fail { fail = false; throw Failure.injected }
                if let previous = values.last { XCTAssertTrue(previous.isClosed) }
                let value = FakeListener(generation, peers, event); values.append(value); return value
            }
        }
    }
    private final class Fixture {
        let root: URL
        let writer: AuditEpochWriter
        let host: DirectApprovalHost
        let factory = Factory()
        init() throws {
            guard let canonical = realpath(FileManager.default.temporaryDirectory.path, nil) else { throw Failure.injected }
            defer { free(canonical) }
            root = URL(fileURLWithPath: String(cString: canonical)).appendingPathComponent(UUID().uuidString)
            let directory = root.appendingPathComponent("store").path
            try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            for name in ["writer.lock", "journal.sqlite"] {
                let fd = Darwin.open(directory + "/" + name, O_CREAT | O_EXCL | O_WRONLY, 0o600)
                guard fd >= 0 else { throw Failure.injected }; Darwin.close(fd)
            }
            let limits = try CBORLimits(maxBytes: 16384, maxDepth: 12, maxItems: 1024)
            let lease = try ProtectedJournalLease(anchor: root.path, relativeDirectory: "store", owner: getuid())
            let database = try JournalDatabase(lease: lease, macID: id(1), accountID: id(2), recordLimits: limits,
                descriptorLimits: limits, decisionLimits: limits, maximumConsumptions: 20, busyMilliseconds: 100, initialize: true)
            let capabilities = try capabilities()
            _ = try database.write { try $0.configureApprovalAuthority(capabilities: capabilities, allowedContracts: Set(capabilities.contracts.keys)) }
            let descriptor = try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
                0: .unsigned(1), 1: .bytes(id(1)), 2: .bytes(id(2)), 3: .bytes(id(3)), 4: .unsigned(7),
                5: .unsigned(1), 6: .null, 7: .null, 8: .null,
            ]), limits: limits), limits: limits)
            writer = try database.write { try $0.createEpoch(descriptor) }
            let factory = factory
            host = DirectApprovalHost(database: database, policy: try DirectHostPolicy(maximumPayloadBytes: 1024),
                factory: { generation, peers, event, _ in try factory.make(generation, peers, event) })
        }
        deinit { try? FileManager.default.removeItem(at: root) }
        func add() async throws {
            let row = try StoredApprovalEnrollment(epoch: id(9), notificationTag: Data(repeating: 5, count: 32),
                identityPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
                approval: ApprovalEnrollment(phoneID: id(5), active: true, capabilities: capabilities(), keys: [
                    EnrolledApprovalKey(id: id(10), keyClass: .biometric, publicKey: P256.Signing.PrivateKey().publicKey.x963Representation),
                    EnrolledApprovalKey(id: id(11), keyClass: .decision, publicKey: P256.Signing.PrivateKey().publicKey.x963Representation),
                ]))
            let writer = writer
            _ = try await host.write { tx in try tx.addApprovalEnrollment(row, expectedTrustRevision: tx.approvalTrustSnapshot().revision,
                eventID: id(40), receiptTimeMs: 1000, writer: writer, expectedAuditHead: 0) }
        }
    }

    func testTrustMutationClosesListenerAndRejectsOldSession() async throws {
        let f = try Fixture()
        try await f.host.start()
        let empty = await f.host.state
        XCTAssertEqual(empty, .noEligiblePhones)
        XCTAssertTrue(f.factory.listeners.isEmpty)
        try await f.add()
        let listener = try XCTUnwrap(f.factory.listeners.last)
        let session = try await f.host.admit(listener.peers[0], generation: listener.generation)
        let count = try await f.host.transaction(session: session) { try $0.approvalEnrollments().count }
        XCTAssertEqual(count, 1)
        let writer = f.writer
        _ = try await f.host.write { tx in try tx.revokeApprovalEnrollment(phoneID: Self.id(5), epoch: Self.id(9),
            expectedTrustRevision: tx.approvalTrustSnapshot().revision, eventID: Self.id(41), receiptTimeMs: 1001,
            writer: writer, expectedAuditHead: 1) }
        XCTAssertTrue(listener.isClosed)
        do { _ = try await f.host.transaction(session: session) { _ in true }; XCTFail("Old session accepted") }
        catch { XCTAssertTrue(error is DirectHostError) }
        let state = await f.host.state
        XCTAssertEqual(state, .noEligiblePhones)
        try await f.host.close()
    }

    func testPolicyReplacementAndRestartRejectStaleEventsAndSessions() async throws {
        let f = try Fixture(); try await f.add(); try await f.host.start()
        let first = try XCTUnwrap(f.factory.listeners.last)
        let old = try await f.host.admit(first.peers[0], generation: first.generation)
        try await f.host.updatePolicy(DirectHostPolicy(maximumPayloadBytes: 2048, minimumEnvelopeVersion: 2))
        let second = try XCTUnwrap(f.factory.listeners.last)
        XCTAssertEqual(second.peers[0].maximumPayloadBytes, 2048)
        XCTAssertEqual(second.peers[0].minimumEnvelopeVersion, 2)
        XCTAssertNotEqual(first.generation, second.generation)
        first.event(.failed); first.event(.ready(port: 999))
        for _ in 0..<20 { await Task.yield() }
        let state = await f.host.state
        XCTAssertEqual(state, .starting)
        XCTAssertFalse(second.isClosed)
        do { _ = try await f.host.transaction(session: old) { _ in true }; XCTFail("Old policy session accepted") } catch { }
        await f.host.stop()
        XCTAssertTrue(second.isClosed)
        try await f.host.start()
        XCTAssertEqual(f.factory.listeners.count, 3)
        try await f.host.close()
        do { try await f.host.start(); XCTFail("Closed host restarted") } catch { }
    }

    func testCommittedWriteSurvivesListenerFailureAndCanRetry() async throws {
        let f = try Fixture(); try await f.host.start(); f.factory.failNext()
        try await f.add()
        let state = await f.host.state
        XCTAssertEqual(state, .failed)
        let count = try await f.host.read { try $0.approvalEnrollments().count }
        XCTAssertEqual(count, 1)
        try await f.host.start()
        XCTAssertEqual(f.factory.listeners.count, 1)
        try await f.host.close()
    }

    func testUnchangedTrustAndRolledBackWriteKeepTheListener() async throws {
        let f = try Fixture(); try await f.add(); try await f.host.start()
        let first = try XCTUnwrap(f.factory.listeners.last)
        try await f.host.write { _ in }
        do { try await f.host.write { _ in throw Failure.injected }; XCTFail("Expected failure") } catch { }
        try await f.host.start()
        XCTAssertEqual(f.factory.listeners.count, 1)
        XCTAssertFalse(first.isClosed)
        try await f.host.close()
    }
}
