import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class MachineUpdateHealthJournalTests: XCTestCase {
    private enum Failure: Error { case injected }
    private typealias Fixture = CheckpointedJournalTests.Fixture

    private func close(_ fixture: Fixture) throws {
        try fixture.journal.close()
        fixture.store.close()
    }

    private func bytes(_ fixture: Fixture) throws -> [Data] {
        try ["journal/journal.sqlite", "continuity/continuity.sqlite"].map {
            try Data(contentsOf: fixture.root.appendingPathComponent($0))
        }
    }

    private func open(_ fixture: Fixture,
                      validateSelf: (JournalTransaction) throws -> Void = { _ in }) throws -> AuthorityJournal {
        try AuthorityJournal(updateHealthStorage: fixture.openTransferredStorage(readOnlyForCutover: true),
            validateSelf: validateSelf)
    }

    func testMatchingCheckpointAllowsHealthReadButNeverRequestStartupOrWrites() throws {
        let fixture = try Fixture(), epoch = fixture.epoch
        let checkpoint = try fixture.store.read().committed
        try close(fixture)
        let before = try bytes(fixture), owner = try open(fixture)
        XCTAssertEqual(try owner.readForUpdateHealth { try $0.epoch(epoch)?.head }, 0)
        for _ in 0..<2 {
            XCTAssertThrowsError(try owner.prepareRequests(clockEpoch: UUID(), maximumPayloadBytes: 16384)) {
                XCTAssertEqual($0 as? JournalDatabaseError, .readOnly)
            }
            XCTAssertThrowsError(try owner.write { _ in true }) {
                XCTAssertEqual($0 as? JournalDatabaseError, .readOnly)
            }
        }
        XCTAssertThrowsError(try owner.withRequests { _ in true })
        XCTAssertEqual(try owner.readForUpdateHealth { try $0.epoch(epoch)?.head }, 0)
        try owner.close()
        XCTAssertEqual(try bytes(fixture), before)
        try fixture.reopen()
        XCTAssertEqual(try fixture.store.read().committed, checkpoint)
    }

    func testWritableStoresAreRejectedAndBothLeasesAreReleased() throws {
        let fixture = try Fixture()
        try close(fixture)
        let before = try bytes(fixture)
        XCTAssertThrowsError(try AuthorityJournal(updateHealthStorage: fixture.openTransferredStorage(), validateSelf: { _ in })) {
            XCTAssertEqual($0 as? JournalDatabaseError, .readOnly)
        }
        let owner = try open(fixture)
        try owner.close()
        XCTAssertEqual(try bytes(fixture), before)
    }

    func testPendingCheckpointIsNeitherFinalizedNorDiscarded() throws {
        for committed in [false, true] {
            let fixture = try Fixture(), old = try fixture.store.read().committed
            do {
                try fixture.journal.write { transaction in
                    try fixture.append(transaction)
                    let candidate = try CheckpointedJournal.checkpoint(transaction: transaction,
                        epoch: fixture.epoch, generation: old.generation + 1, authorityGeneration: old.authorityGeneration)
                    try fixture.store.prepare(expected: old, candidate: candidate)
                    if !committed { throw Failure.injected }
                }
            } catch {
                guard !committed, error is Failure else { throw error }
            }
            let pending = try XCTUnwrap(fixture.store.read().pending)
            try close(fixture)
            let before = try bytes(fixture)
            XCTAssertThrowsError(try open(fixture))
            XCTAssertEqual(try bytes(fixture), before)
            try fixture.reopen()
            XCTAssertEqual(try fixture.store.read().committed, old)
            XCTAssertEqual(try fixture.store.read().pending, pending)
        }
    }

    func testCheckpointMismatchDoesNotCreateRecoveryEvidenceOrChangeEitherStore() throws {
        let fixture = try Fixture()
        try fixture.journal.write { try fixture.append($0) }
        try close(fixture)
        let before = try bytes(fixture)
        XCTAssertThrowsError(try open(fixture))
        XCTAssertEqual(try bytes(fixture), before)
        try fixture.reopen()
        XCTAssertNil(try fixture.store.historyRecovery())
        XCTAssertNil(try fixture.store.historyRecoveryCandidate())
        XCTAssertFalse(try fixture.store.read().recoveryRequired)
    }

    func testHistoryRecoveryIntentAndCandidateRemainUnchanged() throws {
        for candidate in [false, true] {
            let fixture = try Fixture()
            let policy = try AuthorityCodePolicy(entries: [.init(role: .authority, teamID: "ABCDEF1234",
                identifier: "dev.remozio.authority", installedGeneration: 4, minimumGeneration: 2,
                codeDirectoryHash: Data(repeating: 8, count: 20), active: true)])
            let commits = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
            _ = try commits.write(epoch: fixture.epoch) { try $0.installCodePolicy(policy, expectedRevision: nil) }
            let old = try fixture.store.read()
            try fixture.journal.write { try fixture.append($0) }
            let digests = try fixture.journal.read { try $0.continuityDigests() }
            let intent = try HistoryRecoveryIntent(previous: old, authorityDigest: digests.authority,
                ledgerDigest: digests.ledger, recoveryEpoch: Data(repeating: 9, count: 16))
            try fixture.store.prepareHistoryRecovery(intent)
            if candidate {
                try fixture.sql("CREATE TRIGGER fail_finalize BEFORE UPDATE ON continuity_v1 WHEN NEW.history IS NULL BEGIN SELECT RAISE(ABORT,'injected'); END")
                XCTAssertThrowsError(try JournalHistoryRecovery.resume(journal: fixture.journal, continuity: fixture.store,
                    macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16)))
                try fixture.sql("DROP TRIGGER fail_finalize")
            }
            let retained = try fixture.store.historyRecoveryCandidate()
            XCTAssertEqual(retained != nil, candidate)
            try close(fixture)
            let before = try bytes(fixture)
            XCTAssertThrowsError(try open(fixture))
            XCTAssertEqual(try bytes(fixture), before)
            try fixture.reopen()
            XCTAssertEqual(try fixture.store.historyRecovery(), intent)
            XCTAssertEqual(try fixture.store.historyRecoveryCandidate(), retained)
        }
    }

    func testRepairRequiredStateRemainsClosedAndUnchanged() throws {
        let fixture = try Fixture()
        try fixture.store.requireRecovery()
        try close(fixture)
        let before = try bytes(fixture)
        XCTAssertThrowsError(try open(fixture))
        XCTAssertEqual(try bytes(fixture), before)
        try fixture.reopen()
        XCTAssertTrue(try fixture.store.read().recoveryRequired)
    }

    func testSelfValidationFailureReleasesBothStoresWithoutRecovery() throws {
        let fixture = try Fixture()
        try close(fixture)
        let before = try bytes(fixture)
        XCTAssertThrowsError(try open(fixture, validateSelf: { _ in throw Failure.injected })) {
            XCTAssertTrue($0 is Failure)
        }
        XCTAssertEqual(try bytes(fixture), before)
        let owner = try open(fixture)
        try owner.close()
        XCTAssertEqual(try bytes(fixture), before)
    }
}
