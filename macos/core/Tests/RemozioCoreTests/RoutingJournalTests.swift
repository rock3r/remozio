import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import SQLite3
import XCTest
@testable import RemozioCore

final class RoutingJournalTests: XCTestCase {
    private enum Failure: Error { case injected }
    private let key = P256.Signing.PrivateKey()
    private let clock = UUID()
    private func id(_ n: UInt8) -> Data { Data(repeating: n, count: 16) }
    private var limits: CBORLimits { get throws { try .init(maxBytes: 16384, maxDepth: 12, maxItems: 1024) } }
    private func now(_ n: UInt64 = 100) -> AuthorityMoment { .init(epoch: clock, milliseconds: n) }
    private func open(_ f: Fixture, initialize: Bool = false, migrate: Int64? = nil, maximum: Int = 20) throws -> JournalDatabase {
        try JournalDatabase(lease: f.lease(), macID: id(1), accountID: id(2), recordLimits: limits, descriptorLimits: limits,
            decisionLimits: limits, maximumConsumptions: 20, busyMilliseconds: 100, initialize: initialize, migrateFromVersion: migrate,
            routingPolicy: RoutingJournalPolicy(clockEpoch: clock, challengeLifetimeMillis: 1000, maximumOperations: maximum,
                payloadLimits: limits, signingLimits: limits))
    }
    private func setup(_ f: Fixture, maximum: Int = 20) throws -> (JournalDatabase, AuditEpochWriter, UUID) {
        let db = try open(f, initialize: true, maximum: maximum)
        let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1)
        let capabilities = ContractCapabilities(contracts: [contract: []])
        let empty = try db.write { try $0.configureApprovalAuthority(capabilities: capabilities, allowedContracts: [contract]) }
        let descriptor = try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(id(1)), 2: .bytes(id(2)), 3: .bytes(id(3)),
            4: .unsigned(7), 5: .unsigned(1), 6: .null, 7: .null, 8: .null,
        ]), limits: limits), limits: limits)
        let writer = try db.write { try $0.createEpoch(descriptor) }
        let enrolled = try StoredApprovalEnrollment(epoch: id(4), notificationTag: Data(repeating: 5, count: 32),
            identityPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
            approval: ApprovalEnrollment(phoneID: id(5), active: true, capabilities: capabilities, keys: [
                EnrolledApprovalKey(id: id(6), keyClass: .decision, publicKey: key.publicKey.x963Representation),
                EnrolledApprovalKey(id: id(7), keyClass: .biometric, publicKey: P256.Signing.PrivateKey().publicKey.x963Representation),
            ]))
        let revision = try db.write { try $0.addApprovalEnrollment(enrolled, expectedTrustRevision: empty, eventID: id(8),
            receiptTimeMs: 1000, writer: writer, expectedAuditHead: 0) }
        return (db, writer, revision)
    }
    private func issue(_ db: JournalDatabase, trust: UUID, revision: UInt64 = 0, moment: UInt64 = 100) throws -> RoutingAwayControl {
        try db.write { try $0.issueRoutingChallenge(authenticatedPhoneID: id(5), authenticatedEnrollmentEpoch: id(4), expectedTrustRevision: trust,
            expectedRoutingRevision: revision, nowUnixMillis: 1000, now: now(moment)) }
    }
    private func apply(_ tx: JournalTransaction, _ control: RoutingAwayControl, trust: UUID, writer: AuditEpochWriter,
                       head: UInt64 = 1, wall: UInt64 = 1100, moment: UInt64 = 200, signingKey: P256.Signing.PrivateKey? = nil) throws -> RoutingChange {
        let payload = try control.encode(limits: limits)
        let signature = try (signingKey ?? key).signature(for: RoutingAwaySigningInput.make(wireVersion: 1, canonicalPayload: payload,
            payloadLimits: limits, inputLimits: limits)).rawRepresentation
        return try tx.applyRoutingAway(canonicalPayload: payload, signature: signature, authenticatedPhoneID: id(5),
            authenticatedEnrollmentEpoch: id(4), expectedTrustRevision: trust, nowUnixMillis: wall, now: now(moment),
            eventID: id(9), writer: writer, expectedAuditHead: head)
    }
    private func local(_ db: JournalDatabase, _ mode: RoutingMode, writer: AuditEpochWriter, revision: UInt64, head: UInt64) throws -> RoutingState {
        try db.write { try $0.setLocalRoutingMode(mode, expectedRevision: revision, eventID: id(UInt8(20 + head)), receiptTimeMs: 1200,
            writer: writer, expectedAuditHead: head) }
    }
    private func fails(_ error: RoutingJournalError, _ body: () throws -> Any, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try body(), file: file, line: line) { XCTAssertEqual($0 as? RoutingJournalError, error, file: file, line: line) }
    }

    func testModesPersistAndPhoneRetryNeverOverridesLaterLocalChoice() throws {
        let f = try Fixture(), (db, writer, trust) = try setup(f)
        XCTAssertEqual(try db.read { try $0.routingState() }, RoutingState(mode: .automatic, revision: 0))
        let control = try issue(db, trust: trust)
        let result = try db.write { try apply($0, control, trust: trust, writer: writer) }
        XCTAssertTrue(result.inserted); XCTAssertEqual(result.state, RoutingState(mode: .away, revision: 1))
        _ = try local(db, .present, writer: writer, revision: 1, head: 2)
        let retry = try db.write { try apply($0, control, trust: trust, writer: writer, head: 999, wall: 9999, moment: 2000) }
        XCTAssertFalse(retry.inserted); XCTAssertEqual(retry.state, result.state)
        XCTAssertEqual(try db.read { try $0.routingState() }, RoutingState(mode: .present, revision: 2))
        let records = try db.read { try $0.page(epoch: id(3), after: 1, maximumRecords: 10, maximumBytes: 16384).canonicalRecords }
        let events = try records.map { try AuditEventMetadata.decode($0, limits: limits) }
        XCTAssertEqual(events.map(\.kind), [.routingChanged, .routingChanged])
        XCTAssertEqual(events.map(\.authentication), [.decisionKey, .localUser])
        XCTAssertEqual(events.first?.decisionPhoneID, id(5))
        XCTAssertTrue(events.allSatisfy { $0.action == nil && $0.requestID == nil })
        try db.close()
        let reopened = try open(f)
        XCTAssertEqual(try reopened.read { try $0.routingState() }, RoutingState(mode: .present, revision: 2))
        XCTAssertFalse(try reopened.write { try apply($0, control, trust: trust, writer: writer) }.inserted)
    }

    func testConcurrentPhoneAndLocalChoicesUseRevisionCompareAndSwap() throws {
        let f = try Fixture(), (db, writer, trust) = try setup(f)
        let first = try issue(db, trust: trust), second = try issue(db, trust: trust)
        XCTAssertNotEqual(first.challenge, second.challenge); XCTAssertNotEqual(first.operationID, second.operationID)
        _ = try db.write { try apply($0, first, trust: trust, writer: writer) }
        fails(.conflict) { try db.write { try apply($0, second, trust: trust, writer: writer) } }
        fails(.conflict) { try local(db, .present, writer: writer, revision: 0, head: 2) }
        _ = try local(db, .automatic, writer: writer, revision: 1, head: 2)
        let pending = try issue(db, trust: trust, revision: 2, moment: 200)
        _ = try local(db, .present, writer: writer, revision: 2, head: 3)
        fails(.conflict) { try db.write { try apply($0, pending, trust: trust, writer: writer, head: 4) } }
        XCTAssertEqual(try db.read { try $0.routingState() }, RoutingState(mode: .present, revision: 3))
    }

    func testExpiryAndRestartInvalidateUnconsumedChallenges() throws {
        for (wall, moment) in [(UInt64(2000), UInt64(200)), (UInt64(1100), UInt64(1100)), (UInt64(999), UInt64(200))] {
            let f = try Fixture(), (db, writer, trust) = try setup(f), control = try issue(db, trust: trust)
            fails(.expired) { try db.write { try apply($0, control, trust: trust, writer: writer, wall: wall, moment: moment) } }
            XCTAssertEqual(try db.read { try $0.routingState().revision }, 0)
        }
        let f = try Fixture(), (db, writer, trust) = try setup(f), control = try issue(db, trust: trust)
        try db.close()
        let reopened = try open(f)
        fails(.unavailableChallenge) { try reopened.write { try apply($0, control, trust: trust, writer: writer) } }
        let fresh = try issue(reopened, trust: trust, moment: 200)
        let descriptor = try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(id(1)), 2: .bytes(id(2)), 3: .bytes(id(12)),
            4: .unsigned(7), 5: .unsigned(1), 6: .null, 7: .null, 8: .null,
        ]), limits: limits), limits: limits)
        let nextWriter = try reopened.write { try $0.createEpoch(descriptor) }
        XCTAssertTrue(try reopened.write { try apply($0, fresh, trust: trust, writer: nextWriter, head: 0) }.inserted)
    }

    func testRevocationAndWrongSignaturesCannotChangeRouting() throws {
        let f = try Fixture(), (db, writer, trust) = try setup(f), control = try issue(db, trust: trust)
        fails(.invalidSignature) { try db.write { try apply($0, control, trust: trust, writer: writer, signingKey: P256.Signing.PrivateKey()) } }
        let removed = try db.write { try $0.revokeApprovalEnrollment(phoneID: id(5), epoch: id(4), expectedTrustRevision: trust,
            eventID: id(10), receiptTimeMs: 1200, writer: writer, expectedAuditHead: 1).revision }
        XCTAssertThrowsError(try db.write { try apply($0, control, trust: trust, writer: writer, head: 2) }) {
            XCTAssertEqual($0 as? EnrollmentJournalError, .staleRevision)
        }
        XCTAssertThrowsError(try db.write { try apply($0, control, trust: removed, writer: writer, head: 2) }) {
            XCTAssertEqual($0 as? EnrollmentJournalError, .unavailableEnrollment)
        }
        XCTAssertEqual(try db.read { try $0.routingState().revision }, 0)
    }

    func testFailedAuditOrConsumptionWriteRollsBackAllRoutingEffects() throws {
        for table in ["routing_state_v1", "routing_operations_v1", "audit_records_v1"] {
            let f = try Fixture(), (db, writer, trust) = try setup(f), control = try issue(db, trust: trust)
            let action = table == "audit_records_v1" ? "INSERT" : "UPDATE"
            try f.sql("CREATE TRIGGER reject_write BEFORE \(action) ON \(table) BEGIN SELECT RAISE(ABORT,'fixture'); END")
            XCTAssertThrowsError(try db.write { try apply($0, control, trust: trust, writer: writer) })
            XCTAssertEqual(try db.read { try $0.routingState().revision }, 0)
            XCTAssertEqual(try db.read { try $0.page(epoch: id(3), after: 0, maximumRecords: 10, maximumBytes: 16384).canonicalRecords.count }, 1)
            try f.sql("DROP TRIGGER reject_write")
            XCTAssertTrue(try db.write { try apply($0, control, trust: trust, writer: writer) }.inserted)
        }
    }

    func testReadOnlyEscapedAndSwallowedFailureCannotMutate() throws {
        let f = try Fixture(), (db, writer, trust) = try setup(f), control = try issue(db, trust: trust)
        XCTAssertThrowsError(try db.read { try apply($0, control, trust: trust, writer: writer) })
        var escaped: JournalTransaction?
        _ = try db.read { escaped = $0; return try $0.routingState() }
        XCTAssertThrowsError(try escaped?.routingState())
        XCTAssertThrowsError(try db.write { tx in
            _ = try? tx.setLocalRoutingMode(.present, expectedRevision: 99, eventID: id(11), receiptTimeMs: 1000, writer: writer, expectedAuditHead: 1)
            return try apply(tx, control, trust: trust, writer: writer)
        })
        XCTAssertEqual(try db.read { try $0.routingState().revision }, 0)
    }

    func testStorageCapacityClockAndCorruptionFailuresDoNotResetState() throws {
        let f = try Fixture(), (db, _, trust) = try setup(f, maximum: 1)
        _ = try issue(db, trust: trust)
        fails(.capacityExceeded) { try issue(db, trust: trust) }
        fails(.invalidClock) { try issue(db, trust: trust, moment: 99) }
        XCTAssertThrowsError(try db.read { try $0.routingState() }) { XCTAssertEqual($0 as? JournalDatabaseError, .unavailable) }
        try db.close()
        let reopened = try open(f)
        try f.sql("PRAGMA ignore_check_constraints=ON; UPDATE routing_state_v1 SET revision=x'00'")
        fails(.corruptData) { try reopened.read { try $0.routingState() } }
    }

    func testSignedChangesToRetainedFieldsCannotExtendOrRedirectAChallenge() throws {
        let f = try Fixture(), (db, writer, trust) = try setup(f), control = try issue(db, trust: trust)
        guard case let .map(original) = try DeterministicCBOR.decode(control.encode(limits: limits), limits: limits) else { return XCTFail() }
        for field in UInt64(1)...10 {
            var changed = original
            switch changed[field] {
            case var .bytes(value): value[0] ^= 1; changed[field] = .bytes(value)
            case let .unsigned(value): changed[field] = .unsigned(value + 1)
            default: return XCTFail()
            }
            let altered = try RoutingAwayControl.decode(DeterministicCBOR.encode(.map(changed), limits: limits), limits: limits)
            XCTAssertThrowsError(try db.write { try apply($0, altered, trust: trust, writer: writer) })
        }
        var wrongKey = original; wrongKey[7] = .bytes(id(7))
        let biometric = try RoutingAwayControl.decode(DeterministicCBOR.encode(.map(wrongKey), limits: limits), limits: limits)
        fails(.wrongKey) { try db.write { try apply($0, biometric, trust: trust, writer: writer) } }
        XCTAssertTrue(try db.write { try apply($0, control, trust: trust, writer: writer) }.inserted)
    }

    func testFailedMigrationPreservesExistingModeAndVersion() throws {
        let f = try Fixture(), (db, writer, _) = try setup(f)
        _ = try local(db, .present, writer: writer, revision: 0, head: 1)
        try db.close()
        try f.sql("PRAGMA user_version=6")
        XCTAssertThrowsError(try open(f, migrate: 6))
        try f.sql("PRAGMA user_version=7")
        let reopened = try open(f)
        XCTAssertEqual(try reopened.read { try $0.routingState() }, RoutingState(mode: .present, revision: 1))
    }

    func testSchemaSixMigrationPreservesEnrollmentAndInitializesAutomatic() throws {
        let f = try Fixture(), (db, _, trust) = try setup(f)
        try db.close()
        try f.sql("DROP TABLE routing_operations_v1; DROP TABLE routing_state_v1; PRAGMA user_version=6")
        XCTAssertThrowsError(try open(f))
        let migrated = try open(f, migrate: 6)
        XCTAssertEqual(try migrated.read { try $0.approvalTrustSnapshot().revision }, trust)
        XCTAssertEqual(try migrated.read { try $0.routingState() }, RoutingState(mode: .automatic, revision: 0))
    }

    private final class Fixture {
        let root: URL
        var directory: String { root.appendingPathComponent("store").path }
        var path: String { directory + "/journal.sqlite" }
        init() throws {
            guard let canonical = realpath(FileManager.default.temporaryDirectory.path, nil) else { throw Failure.injected }
            defer { free(canonical) }
            root = URL(fileURLWithPath: String(cString: canonical)).appendingPathComponent(UUID().uuidString)
            try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            for name in ["writer.lock", "journal.sqlite"] {
                let fd = Darwin.open(directory + "/" + name, O_CREAT | O_EXCL | O_WRONLY, 0o600)
                guard fd >= 0 else { throw Failure.injected }; Darwin.close(fd)
            }
        }
        deinit { try? FileManager.default.removeItem(at: root) }
        func lease() throws -> ProtectedJournalLease { try .init(anchor: root.path, relativeDirectory: "store", owner: getuid()) }
        func sql(_ sql: String) throws {
            var db: OpaquePointer?
            guard sqlite3_open(path, &db) == SQLITE_OK, let db else { throw Failure.injected }
            defer { sqlite3_close(db) }
            guard sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else { throw Failure.injected }
        }
    }
}
