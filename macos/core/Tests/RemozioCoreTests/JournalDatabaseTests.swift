import Darwin
import Foundation
@testable import RemozioCore
import RemozioProtocol
import SQLite3
import XCTest

final class JournalDatabaseTests: XCTestCase {
    private enum Failure: Error { case injected }
    private var bounds: CBORLimits { get throws { try CBORLimits(maxBytes: 16384, maxDepth: 8, maxItems: 512) } }
    private func id(_ n: UInt8) -> Data { Data(repeating: n, count: 16) }
    private func descriptor(_ epoch: UInt8 = 3) throws -> AuditEpochDescriptor {
        try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(id(1)), 2: .bytes(id(2)), 3: .bytes(id(epoch)),
            4: .unsigned(7), 5: .unsigned(1), 6: .null, 7: .null, 8: .null,
        ]), limits: bounds), limits: bounds)
    }
    private func record(_ sequence: UInt64, epoch: UInt8 = 3) throws -> Data {
        try AuditEventMetadata(eventID: id(UInt8(sequence)), macID: id(1), accountID: id(2), journalEpoch: id(epoch),
            sequence: sequence, requestID: id(8), eventTimeMs: nil, authorityReceiptTimeMs: nil, kind: .consumed,
            category: .command, action: nil, decisionPhoneID: nil, authentication: .system, outcome: .accepted,
            reason: .none, droppedEventCount: nil, peerDeviceID: nil).encode(limits: bounds)
    }
    private func open(_ fixture: Fixture, initialize: Bool = false, mac: UInt8 = 1, account: UInt8 = 2,
                      busy: UInt32 = 100) throws -> JournalDatabase {
        try JournalDatabase(lease: fixture.lease(), macID: id(mac), accountID: id(account),
                            recordLimits: bounds, descriptorLimits: bounds, decisionLimits: bounds, maximumConsumptions: 10, busyMilliseconds: busy, initialize: initialize)
    }

    func testExplicitSetupPersistenceAndWriterRetirementAcrossReopen() throws {
        let fixture = try Fixture()
        XCTAssertThrowsError(try open(fixture))
        let database = try open(fixture, initialize: true)
        let writer = try database.write { try $0.createEpoch(descriptor()) }
        try database.write { try $0.append(record(1), writer: writer, expectedHead: 0) }
        try database.close()
        let reopened = try open(fixture)
        XCTAssertEqual(try reopened.read { try $0.page(epoch: id(3), after: 0, maximumRecords: 10, maximumBytes: 16384).canonicalRecords }, try [record(1)])
        XCTAssertThrowsError(try reopened.write { try $0.append(record(2), writer: writer, expectedHead: 1) })
        XCTAssertThrowsError(try reopened.read { _ in }) { XCTAssertEqual($0 as? JournalDatabaseError, .unavailable) }
        try reopened.close()
        let recovered = try open(fixture)
        let fresh = try recovered.write { try $0.createEpoch(descriptor(4)) }
        try recovered.write { try $0.append(record(1, epoch: 4), writer: fresh, expectedHead: 0) }
        XCTAssertEqual(try recovered.read { try $0.epoch(id(4))?.head }, 1)
    }

    func testWrongScopeVersionAndReinitializeDoNotReplaceExistingData() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        _ = try database.write { try $0.createEpoch(descriptor()) }
        try database.close()
        for operation in [{ try self.open(fixture, mac: 9) }, { try self.open(fixture, account: 9) },
                          { try self.open(fixture, initialize: true) }] {
            XCTAssertThrowsError(try operation())
        }
        try fixture.sql("PRAGMA user_version=99")
        XCTAssertThrowsError(try open(fixture))
        try fixture.sql("PRAGMA user_version=5")
        let reopened = try open(fixture)
        XCTAssertNotNil(try reopened.read { try $0.epoch(id(3)) })
        try reopened.close()
        try fixture.sql("PRAGMA journal_mode=WAL")
        XCTAssertThrowsError(try open(fixture, mac: 9))
        XCTAssertEqual(try fixture.scalar("PRAGMA journal_mode"), "wal")
    }

    func testMalformedStoreAndMissingTableFailWithoutReset() throws {
        let malformed = try Fixture(), data = Data("not a SQLite database".utf8)
        try data.write(to: URL(fileURLWithPath: malformed.path))
        XCTAssertEqual(chmod(malformed.path, 0o600), 0)
        XCTAssertThrowsError(try open(malformed, initialize: true))
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: malformed.path)), data)
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        try database.close()
        try fixture.sql("DROP TABLE audit_records_v1")
        XCTAssertThrowsError(try open(fixture))
        XCTAssertThrowsError(try open(fixture, initialize: true))
    }

    func testEscapedTransactionCannotAccessLaterTransactionOrClosedOwner() throws {
        let fixture = try Fixture()
        var database: JournalDatabase? = try open(fixture, initialize: true)
        let escaped = try database!.read { $0 }
        XCTAssertThrowsError(try escaped.epoch(id(3)))
        try database!.read { current in
            XCTAssertThrowsError(try escaped.epoch(id(3)))
            XCTAssertNil(try current.epoch(id(3)))
        }
        try database!.close()
        XCTAssertThrowsError(try escaped.epoch(id(3)))
        database = nil
        XCTAssertThrowsError(try escaped.epoch(id(3)))
    }

    func testReadOnlyAndNestedOperationsCannotAlterOuterTransaction() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        XCTAssertThrowsError(try database.read { try $0.createEpoch(descriptor()) }) {
            XCTAssertEqual($0 as? JournalDatabaseError, .readOnly)
        }
        try database.write { transaction in
            XCTAssertThrowsError(try database.read { _ in }) { XCTAssertEqual($0 as? JournalDatabaseError, .transactionActive) }
            XCTAssertThrowsError(try database.write { _ in })
            XCTAssertThrowsError(try database.close())
            _ = try transaction.createEpoch(descriptor())
        }
        XCTAssertEqual(try database.read { try $0.epoch(id(3))?.head }, 0)
    }

    func testCallbackFailureRollsBackAndSwallowedMutationErrorCannotCommit() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        let writer = try database.write { try $0.createEpoch(descriptor()) }
        XCTAssertThrowsError(try database.write {
            try $0.append(record(1), writer: writer, expectedHead: 0)
            throw Failure.injected
        })
        XCTAssertEqual(try database.read { try $0.epoch(id(3))?.head }, 0)
        XCTAssertThrowsError(try database.write {
            try $0.append(record(1), writer: writer, expectedHead: 0)
            XCTAssertThrowsError(try $0.append(record(1), writer: writer, expectedHead: 1))
        }) { XCTAssertEqual($0 as? JournalDatabaseError, .transactionFailed) }
        XCTAssertEqual(try database.read { try $0.epoch(id(3))?.head }, 0)
        try database.write { try $0.append(record(1), writer: writer, expectedHead: 0) }
    }

    func testCaughtHeadMismatchRollsBackAndRetiresOwner() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        let writer = try database.write { try $0.createEpoch(descriptor()) }
        XCTAssertThrowsError(try database.write {
            try $0.append(record(1), writer: writer, expectedHead: 0)
            XCTAssertThrowsError(try $0.append(record(1), writer: writer, expectedHead: 0)) { XCTAssertEqual($0 as? AuditJournalError, .headMismatch) }
        })
        XCTAssertThrowsError(try database.read { _ in }) { XCTAssertEqual($0 as? JournalDatabaseError, .unavailable) }
        try database.close()
        let reopened = try open(fixture)
        XCTAssertEqual(try reopened.read { try $0.epoch(id(3))?.head }, 0)
    }

    func testEpochCreationRollbackRetiresOwnerAndUncommittedWriter() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        var escaped: AuditEpochWriter?
        XCTAssertThrowsError(try database.write {
            escaped = try $0.createEpoch(descriptor())
            throw Failure.injected
        })
        XCTAssertThrowsError(try database.read { _ in }) { XCTAssertEqual($0 as? JournalDatabaseError, .unavailable) }
        try database.close()
        let reopened = try open(fixture)
        XCTAssertNil(try reopened.read { try $0.epoch(id(3)) })
        _ = try reopened.write { try $0.createEpoch(descriptor()) }
        XCTAssertThrowsError(try reopened.write { try $0.append(record(1), writer: XCTUnwrap(escaped), expectedHead: 0) })
    }

    func testSQLiteAutomaticRollbackRetiresOwnerButStatementAbortAllowsRetry() throws {
        for action in ["ABORT", "ROLLBACK"] {
            let fixture = try Fixture(), database = try open(fixture, initialize: true)
            let writer = try database.write { try $0.createEpoch(descriptor()) }
            try fixture.sql("CREATE TRIGGER fail_insert BEFORE INSERT ON audit_records_v1 BEGIN SELECT RAISE(\(action),'injected'); END")
            XCTAssertThrowsError(try database.write { try $0.append(record(1), writer: writer, expectedHead: 0) })
            if action == "ABORT" { XCTAssertEqual(try database.read { try $0.epoch(id(3))?.head }, 0) }
            else { XCTAssertThrowsError(try database.read { _ in }) { XCTAssertEqual($0 as? JournalDatabaseError, .unavailable) } }
            try database.close()
            try fixture.sql("DROP TRIGGER fail_insert")
            let reopened = try open(fixture)
            XCTAssertEqual(try reopened.read { try $0.epoch(id(3))?.head }, 0)
        }
    }

    func testLeaseFailureBeforeCommitRetiresOwnerEvenAfterPermissionsRestored() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        let writer = try database.write { try $0.createEpoch(descriptor()) }
        XCTAssertThrowsError(try database.write {
            try $0.append(record(1), writer: writer, expectedHead: 0)
            XCTAssertEqual(chmod(fixture.path, 0o644), 0)
        })
        XCTAssertEqual(chmod(fixture.path, 0o600), 0)
        XCTAssertThrowsError(try database.read { _ in }) { XCTAssertEqual($0 as? JournalDatabaseError, .unavailable) }
        try database.close()
        let reopened = try open(fixture)
        XCTAssertEqual(try reopened.read { try $0.epoch(id(3))?.head }, 0)
    }

    func testFailedOpenAndCloseReleaseLeaseAndProductionRequiresRoot() throws {
        let fixture = try Fixture()
        XCTAssertThrowsError(try open(fixture, initialize: true, busy: 60_001))
        let database = try open(fixture, initialize: true)
        XCTAssertThrowsError(try open(fixture)) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
        try database.close(); try database.close()
        XCTAssertThrowsError(try database.read { _ in }) { XCTAssertEqual($0 as? JournalDatabaseError, .closed) }
        let next = try open(fixture)
        try next.close()
        if geteuid() != 0 {
            XCTAssertThrowsError(try JournalDatabase.open(directoryPath: fixture.directory, macID: id(1), accountID: id(2),
                recordLimits: bounds, descriptorLimits: bounds, decisionLimits: bounds, maximumConsumptions: 10, busyMilliseconds: 100)) {
                XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
            }
        }
    }

    private final class Fixture {
        let root: URL
        var directory: String { root.appendingPathComponent("store").path }
        var path: String { directory + "/journal.sqlite" }
        init() throws {
            guard let canonical = realpath(FileManager.default.temporaryDirectory.path, nil) else { throw Failure.injected }
            defer { free(canonical) }
            root = URL(fileURLWithPath: String(cString: canonical)).appendingPathComponent(UUID().uuidString)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            for name in ["writer.lock", "journal.sqlite"] {
                let fd = Darwin.open(directory + "/" + name, O_CREAT | O_EXCL | O_WRONLY, 0o600)
                guard fd >= 0 else { throw JournalLeaseError.system(errno) }
                Darwin.close(fd)
            }
        }
        deinit { try? FileManager.default.removeItem(at: root) }
        func lease() throws -> ProtectedJournalLease { try ProtectedJournalLease(anchor: root.path, relativeDirectory: "store", owner: getuid()) }
        func sql(_ query: String) throws { _ = try scalar(query) }
        func scalar(_ query: String) throws -> String? {
            var db: OpaquePointer?
            guard sqlite3_open(path, &db) == SQLITE_OK, let db else { throw Failure.injected }
            defer { sqlite3_close(db) }
            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(db, query, -1, &stmt, nil) == SQLITE_OK, let stmt else { throw Failure.injected }
            defer { sqlite3_finalize(stmt) }
            let rc = sqlite3_step(stmt)
            guard rc == SQLITE_DONE || rc == SQLITE_ROW else { throw Failure.injected }
            return rc == SQLITE_ROW ? sqlite3_column_text(stmt, 0).map { String(cString: $0) } : nil
        }
    }
}
