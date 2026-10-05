import Darwin
import Foundation
import SQLite3
import XCTest
import RemozioProtocol
@testable import RemozioCore

final class CheckpointedJournalTests: XCTestCase {
    private enum Fault: Error { case injected }

    func testResultReturnsAfterBothStoresCommitAndSurvivesReopen() throws {
        let fixture = try Fixture()
        let coordinator = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
        let result = try coordinator.write(epoch: fixture.epoch) { transaction in
            try fixture.append(transaction)
            return "committed"
        }
        XCTAssertEqual(result, "committed")
        let state = try fixture.store.read()
        XCTAssertNil(state.pending)
        XCTAssertEqual(state.committed.generation, 2)
        XCTAssertEqual(state.committed.journalHead, 1)
        XCTAssertEqual(state.committed, try fixture.observed(generation: 2))
        try fixture.reopen()
        XCTAssertEqual(try fixture.store.read(), state)
        XCTAssertEqual(state.committed, try fixture.observed(generation: 2))
    }

    func testPreparationFailureRollsBackJournalAndRetiresCoordinator() throws {
        let fixture = try Fixture(), before = try fixture.store.read()
        try fixture.sql("CREATE TRIGGER fail_prepare BEFORE UPDATE ON continuity_v1 WHEN NEW.pending IS NOT NULL BEGIN SELECT RAISE(ABORT,'injected'); END")
        let coordinator = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
        XCTAssertThrowsError(try coordinator.write(epoch: fixture.epoch) { try fixture.append($0); return "must not escape" })
        XCTAssertEqual(try fixture.store.read(), before)
        XCTAssertEqual(try fixture.observed(generation: 1), before.committed)
        XCTAssertThrowsError(try coordinator.write(epoch: fixture.epoch) { _ in XCTFail("retired callback ran") }) {
            XCTAssertEqual($0 as? CheckpointedJournal.Failure, .retired)
        }
        try fixture.reopen()
        XCTAssertEqual(try fixture.store.read(), before)
        XCTAssertEqual(try fixture.observed(generation: 1), before.committed)
    }

    func testFinalizationFailureRetainsCommittedCandidateAndBothBoundaries() throws {
        let fixture = try Fixture(), before = try fixture.store.read()
        try fixture.sql("CREATE TRIGGER fail_finalize BEFORE UPDATE ON continuity_v1 WHEN NEW.pending IS NULL BEGIN SELECT RAISE(ABORT,'injected'); END")
        let coordinator = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
        XCTAssertThrowsError(try coordinator.write(epoch: fixture.epoch) { try fixture.append($0); return "must not escape" })
        let prepared = try fixture.store.read()
        XCTAssertEqual(prepared.committed, before.committed)
        XCTAssertEqual(prepared.pending, try fixture.observed(generation: 2))
        XCTAssertFalse(prepared.recoveryRequired)
        try fixture.reopen()
        XCTAssertEqual(try fixture.store.read(), prepared)
        XCTAssertEqual(prepared.pending, try fixture.observed(generation: 2))
        let restarted = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
        XCTAssertThrowsError(try restarted.write(epoch: fixture.epoch) { _ in XCTFail("unresolved callback ran") }) {
            XCTAssertEqual($0 as? CheckpointedJournal.Failure, .unresolvedPreparation)
        }
    }

    func testCallbackFailureLeavesOldBoundaryAndMismatchDoesNotRunCallback() throws {
        let fixture = try Fixture(), before = try fixture.store.read()
        let coordinator = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
        XCTAssertThrowsError(try coordinator.write(epoch: fixture.epoch) { transaction in
            try fixture.append(transaction)
            throw Fault.injected
        })
        XCTAssertEqual(try fixture.store.read(), before)
        XCTAssertEqual(try fixture.observed(generation: 1), before.committed)
        try fixture.journal.write { try fixture.append($0) }
        let mismatched = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
        XCTAssertThrowsError(try mismatched.write(epoch: fixture.epoch) { _ in XCTFail("mismatched callback ran") }) {
            XCTAssertEqual($0 as? CheckpointedJournal.Failure, .boundaryMismatch)
        }
        XCTAssertFalse(try fixture.store.read().recoveryRequired)
    }

    func testJournalRollbackAfterPreparationRetainsOldBoundaryForRecovery() throws {
        let fixture = try Fixture(), before = try fixture.store.read()
        let coordinator = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
        XCTAssertThrowsError(try coordinator.write(epoch: fixture.epoch) { transaction in
            try fixture.append(transaction)
            // A swallowed mutation error still poisons the enclosing journal transaction.
            XCTAssertThrowsError(try transaction.append(Data([0]), writer: fixture.writer, expectedHead: 1))
            return "must not escape"
        })
        let prepared = try fixture.store.read()
        XCTAssertNotNil(prepared.pending)
        XCTAssertEqual(prepared.pending?.journalHead, 1)
        XCTAssertEqual(prepared.committed, before.committed)
        XCTAssertFalse(prepared.recoveryRequired)
        try fixture.reopen()
        XCTAssertEqual(try fixture.store.read(), prepared)
        XCTAssertEqual(try fixture.observed(generation: 1), before.committed)
    }

    private final class Fixture {
        let root: URL
        let epoch = Data(repeating: 3, count: 16)
        let limits = try! CBORLimits(maxBytes: 16384, maxDepth: 8, maxItems: 512)
        var journal: JournalDatabase!
        var store: ContinuityStore!
        var writer: AuditEpochWriter!
        init() throws {
            guard let canonical = realpath(FileManager.default.temporaryDirectory.path, nil) else { throw Fault.injected }
            defer { free(canonical) }
            root = URL(fileURLWithPath: String(cString: canonical)).appendingPathComponent(UUID().uuidString)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            for name in ["journal", "continuity"] {
                let directory = root.appendingPathComponent(name)
                try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
                for file in ["writer.lock", "\(name).sqlite"] {
                    let fd = Darwin.open(directory.appendingPathComponent(file).path, O_CREAT | O_EXCL | O_WRONLY, 0o600)
                    guard fd >= 0 else { throw Fault.injected }
                    Darwin.close(fd)
                }
            }
            journal = try openJournal(initialize: true)
            let descriptor = try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
                0: .unsigned(1), 1: .bytes(Data(repeating: 1, count: 16)), 2: .bytes(Data(repeating: 2, count: 16)),
                3: .bytes(epoch), 4: .unsigned(7), 5: .unsigned(1), 6: .null, 7: .null, 8: .null,
            ]), limits: limits), limits: limits)
            writer = try journal.write { try $0.createEpoch(descriptor) }
            store = try openStore(initial: observed(generation: 1))
        }
        deinit { try? journal?.close(); store?.close(); try? FileManager.default.removeItem(at: root) }
        func openJournal(initialize: Bool = false) throws -> JournalDatabase {
            try JournalDatabase(lease: ProtectedJournalLease(anchor: root.path, relativeDirectory: "journal", owner: geteuid()),
                macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16),
                recordLimits: limits, descriptorLimits: limits, decisionLimits: limits, maximumConsumptions: 10,
                busyMilliseconds: 100, initialize: initialize)
        }
        func openStore(initial: ContinuityCheckpoint? = nil) throws -> ContinuityStore {
            try ContinuityStore(lease: ProtectedContinuityLease(anchor: root.path, relativeDirectory: "continuity", owner: geteuid()),
                macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16), initialize: initial)
        }
        func reopen() throws {
            try journal.close(); store.close()
            journal = try openJournal(); store = try openStore()
        }
        func observed(generation: UInt64) throws -> ContinuityCheckpoint {
            try journal.read { try CheckpointedJournal.checkpoint(transaction: $0, epoch: epoch, generation: generation) }
        }
        func append(_ transaction: JournalTransaction) throws {
            let event = try AuditEventMetadata(eventID: Data(repeating: 4, count: 16), macID: Data(repeating: 1, count: 16),
                accountID: Data(repeating: 2, count: 16), journalEpoch: epoch, sequence: 1, requestID: nil,
                eventTimeMs: nil, authorityReceiptTimeMs: nil, kind: .consumed, category: .command, action: nil,
                decisionPhoneID: nil, authentication: .system, outcome: .accepted, reason: .none,
                droppedEventCount: nil, peerDeviceID: nil).encode(limits: limits)
            try transaction.append(event, writer: writer, expectedHead: 0)
        }
        func sql(_ query: String) throws {
            var connection: OpaquePointer?
            guard sqlite3_open(root.appendingPathComponent("continuity/continuity.sqlite").path, &connection) == SQLITE_OK,
                  let connection else { throw Fault.injected }
            defer { sqlite3_close(connection) }
            guard sqlite3_exec(connection, query, nil, nil, nil) == SQLITE_OK else { throw Fault.injected }
        }
    }
}
