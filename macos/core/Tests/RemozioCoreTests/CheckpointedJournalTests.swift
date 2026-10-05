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

    func testRecoveryFinalizesCommittedCandidateAndIsIdempotent() throws {
        let fixture = try Fixture()
        try fixture.sql("CREATE TRIGGER fail_finalize BEFORE UPDATE ON continuity_v1 WHEN NEW.pending IS NULL BEGIN SELECT RAISE(ABORT,'injected'); END")
        let coordinator = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
        XCTAssertThrowsError(try coordinator.write(epoch: fixture.epoch) { try fixture.append($0) })
        try fixture.reopen()
        let candidate = try XCTUnwrap(fixture.store.read().pending)
        try fixture.sql("DROP TRIGGER fail_finalize")
        XCTAssertEqual(try JournalCheckpointRecovery.reconcile(journal: fixture.journal, continuity: fixture.store), .finalized(candidate))
        XCTAssertEqual(try JournalCheckpointRecovery.reconcile(journal: fixture.journal, continuity: fixture.store), .unchanged(candidate))
        XCTAssertNil(try fixture.store.read().pending)
        XCTAssertEqual(try fixture.observed(generation: 2), candidate)
    }

    func testRecoveryDiscardsPreparationWhenJournalRolledBack() throws {
        let fixture = try Fixture(), before = try fixture.store.read().committed
        let coordinator = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
        XCTAssertThrowsError(try coordinator.write(epoch: fixture.epoch) { transaction in
            try fixture.append(transaction)
            XCTAssertThrowsError(try transaction.append(Data([0]), writer: fixture.writer, expectedHead: 1))
        })
        try fixture.reopen()
        XCTAssertEqual(try JournalCheckpointRecovery.reconcile(journal: fixture.journal, continuity: fixture.store), .discarded(before))
        XCTAssertEqual(try fixture.observed(generation: 1), before)
        XCTAssertEqual(try JournalCheckpointRecovery.reconcile(journal: fixture.journal, continuity: fixture.store), .unchanged(before))
    }

    func testRecoveryPreservesHistoryMismatchWithoutRequiringAdministratorRepair() throws {
        let fixture = try Fixture(), before = try fixture.store.read()
        try fixture.journal.write { try fixture.append($0) }
        XCTAssertEqual(try JournalCheckpointRecovery.reconcile(journal: fixture.journal, continuity: fixture.store), .historyDiscontinuity(before))
        XCTAssertEqual(try fixture.store.read(), before)
        XCTAssertEqual(try fixture.journal.read { try $0.epoch(fixture.epoch)?.head }, 1)
    }

    func testRecoveryFailurePreservesPreparationAndAllowsStorageRetry() throws {
        let fixture = try Fixture()
        try fixture.sql("CREATE TRIGGER fail_finalize BEFORE UPDATE ON continuity_v1 WHEN NEW.pending IS NULL BEGIN SELECT RAISE(ABORT,'injected'); END")
        let coordinator = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
        XCTAssertThrowsError(try coordinator.write(epoch: fixture.epoch) { try fixture.append($0) })
        let before = try fixture.store.read()
        XCTAssertThrowsError(try JournalCheckpointRecovery.reconcile(journal: fixture.journal, continuity: fixture.store))
        XCTAssertEqual(try fixture.store.read(), before)
        try fixture.sql("DROP TRIGGER fail_finalize")
        XCTAssertEqual(try JournalCheckpointRecovery.reconcile(journal: fixture.journal, continuity: fixture.store),
                       .finalized(try XCTUnwrap(before.pending)))
    }

    func testRecoveryPersistsTrustMismatchAndMarkerFailureDoesNotHideIt() throws {
        let fixture = try Fixture()
        try fixture.sql("INSERT INTO approval_enrollments_v1 VALUES(zeroblob(16),zeroblob(16),0,x'01')", journal: true)
        try fixture.sql("CREATE TRIGGER fail_marker BEFORE UPDATE ON continuity_v1 WHEN NEW.repair=1 BEGIN SELECT RAISE(ABORT,'injected'); END")
        XCTAssertThrowsError(try JournalCheckpointRecovery.reconcile(journal: fixture.journal, continuity: fixture.store))
        XCTAssertFalse(try fixture.store.read().recoveryRequired)
        try fixture.reopen()
        try fixture.sql("DROP TRIGGER fail_marker")
        XCTAssertEqual(try JournalCheckpointRecovery.reconcile(journal: fixture.journal, continuity: fixture.store), .repairRequired)
        XCTAssertTrue(try fixture.store.read().recoveryRequired)
        try fixture.sql("DELETE FROM approval_enrollments_v1", journal: true)
        try fixture.reopen()
        XCTAssertEqual(try JournalCheckpointRecovery.reconcile(journal: fixture.journal, continuity: fixture.store), .repairRequired)
    }

    func testRecoveryDoesNotTurnClosedJournalIntoRepairMarker() throws {
        let fixture = try Fixture(), before = try fixture.store.read()
        try fixture.journal.close()
        XCTAssertThrowsError(try JournalCheckpointRecovery.reconcile(journal: fixture.journal, continuity: fixture.store)) {
            XCTAssertEqual($0 as? JournalDatabaseError, .closed)
        }
        XCTAssertEqual(try fixture.store.read(), before)
    }

    func testStartupWithholdsWriterUntilCheckpointedRecoveryCompletes() throws {
        let fixture = try Fixture()
        try fixture.reopen()
        let startup = try JournalStartupRecovery(journal: fixture.journal, continuity: fixture.store,
            maximumRecords: 1, maximumBytes: 16384)
        XCTAssertThrowsError(try startup.completedWriter())
        let next = Data(repeating: 9, count: 16)
        guard case .recovering = try startup.start(descriptor: fixture.descriptor(next)) else { return XCTFail("startup did not begin") }
        XCTAssertThrowsError(try startup.completedWriter())
        XCTAssertEqual(try fixture.store.read().committed.journalEpoch, next)
        guard case .complete = try startup.advance() else { return XCTFail("empty recovery did not finish") }
        XCTAssertEqual(try startup.completedWriter().epoch, next)
        XCTAssertThrowsError(try startup.start(descriptor: fixture.descriptor(Data(repeating: 10, count: 16))))
        try fixture.reopen()
        XCTAssertNil(try fixture.store.read().pending)
        XCTAssertEqual(try fixture.store.read().committed.journalEpoch, next)
    }

    func testStartupFailureNeverReleasesWriterAndCanRecoverAfterReopen() throws {
        let fixture = try Fixture()
        try fixture.reopen()
        let startup = try JournalStartupRecovery(journal: fixture.journal, continuity: fixture.store,
            maximumRecords: 1, maximumBytes: 16384)
        try fixture.sql("CREATE TRIGGER fail_finalize BEFORE UPDATE ON continuity_v1 WHEN NEW.pending IS NULL BEGIN SELECT RAISE(ABORT,'injected'); END")
        XCTAssertThrowsError(try startup.start(descriptor: fixture.descriptor(Data(repeating: 9, count: 16))))
        XCTAssertThrowsError(try startup.completedWriter())
        XCTAssertThrowsError(try startup.advance())
        try fixture.sql("DROP TRIGGER fail_finalize")
        try fixture.reopen()
        let retry = try JournalStartupRecovery(journal: fixture.journal, continuity: fixture.store,
            maximumRecords: 1, maximumBytes: 16384)
        let next = Data(repeating: 10, count: 16)
        guard case .recovering = try retry.start(descriptor: fixture.descriptor(next)) else { return XCTFail("retry did not begin") }
        guard case .complete = try retry.advance() else { return XCTFail("retry did not complete") }
        XCTAssertEqual(try retry.completedWriter().epoch, next)
        XCTAssertFalse(try fixture.store.read().recoveryRequired)
    }

    func testStartupPreservesHistoryDiscontinuityWithoutCreatingEpoch() throws {
        let fixture = try Fixture()
        try fixture.journal.write { try fixture.append($0) }
        try fixture.reopen()
        let startup = try JournalStartupRecovery(journal: fixture.journal, continuity: fixture.store,
            maximumRecords: 1, maximumBytes: 16384)
        let next = Data(repeating: 9, count: 16)
        guard case .historyDiscontinuity = try startup.start(descriptor: fixture.descriptor(next)) else {
            return XCTFail("history loss was not surfaced")
        }
        XCTAssertNil(try fixture.journal.read { try $0.epoch(next) })
        XCTAssertThrowsError(try startup.completedWriter())
        XCTAssertFalse(try fixture.store.read().recoveryRequired)
    }

    func testStorageOwnerHoldsAndReleasesBothLeases() throws {
        let fixture = try Fixture()
        try fixture.journal.close(); fixture.store.close()
        var storage: AuthorityStorage? = try AuthorityStorage(openJournal: { try fixture.openJournal() },
            openContinuity: { try fixture.openStore(excludingDirectory: $0) })
        XCTAssertNotNil(storage)
        XCTAssertThrowsError(try fixture.openJournal())
        XCTAssertThrowsError(try fixture.openStore())
        storage = nil
        try fixture.reopen()
        XCTAssertEqual(try fixture.store.read().committed, try fixture.observed(generation: 1))
    }

    func testStorageRejectsNestedDirectoryIdentitiesAndReleasesBothLeases() throws {
        for useCaseAlias in [false, true] {
            let fixture = try Fixture()
            try fixture.journal.close(); fixture.store.close()
            try FileManager.default.moveItem(at: fixture.root.appendingPathComponent("continuity"),
                to: fixture.root.appendingPathComponent("journal/continuity"))
            let directory = useCaseAlias ? "JOURNAL/continuity" : "journal/continuity"
            if useCaseAlias && !FileManager.default.fileExists(atPath: fixture.root.appendingPathComponent(directory).path) {
                continue // The non-alias case still exercises containment on case-sensitive volumes.
            }
            XCTAssertThrowsError(try AuthorityStorage(openJournal: { try fixture.openJournal() },
                openContinuity: { try fixture.openStore(directory: directory, excludingDirectory: $0) })) {
                XCTAssertTrue($0 is AuthorityServiceConfigurationError)
            }
            let journal = try fixture.openJournal(), continuity = try fixture.openStore(directory: directory)
            try journal.close(); continuity.close()
        }
    }

    func testAliasedStoreIsConfigurationFailureBeforeLockContention() throws {
        let fixture = try Fixture()
        try fixture.journal.close(); fixture.store.close()
        for directory in ["journal", "JOURNAL"] {
            if !FileManager.default.fileExists(atPath: fixture.root.appendingPathComponent(directory).path) { continue }
            XCTAssertThrowsError(try AuthorityStorage(openJournal: { try fixture.openJournal() },
                openContinuity: { try fixture.openStore(directory: directory, excludingDirectory: $0) })) {
                XCTAssertEqual($0 as? JournalLeaseError, .invalidPath)
                XCTAssertEqual(AuthorityStartupFailure(error: $0), .configurationFailure)
            }
            let reopened = try fixture.openJournal()
            try reopened.close()
        }
        let competing = try fixture.openStore()
        defer { competing.close() }
        XCTAssertThrowsError(try AuthorityStorage(openJournal: { try fixture.openJournal() },
            openContinuity: { try fixture.openStore(excludingDirectory: $0) })) {
            XCTAssertEqual($0 as? JournalLeaseError, .busy)
            XCTAssertEqual(AuthorityStartupFailure(error: $0), .temporaryStorageFailure)
        }
        let reopened = try fixture.openJournal()
        try reopened.close()
    }

    func testFailedContinuityOpenReleasesJournalAndPreservesError() throws {
        let fixture = try Fixture()
        try fixture.journal.close()
        XCTAssertThrowsError(try AuthorityStorage(openJournal: { try fixture.openJournal() }, openContinuity: { _ in
            throw Fault.injected
        })) { XCTAssertTrue($0 is Fault) }
        fixture.journal = try fixture.openJournal()
        XCTAssertEqual(try fixture.store.read().committed, try fixture.observed(generation: 1))
    }

    func testPairedAuthorityOwnerChecksContinuityAndClosesBothStores() throws {
        let fixture = try Fixture()
        try fixture.journal.close(); fixture.store.close()
        let owner = try AuthorityJournal(storage: fixture.openTransferredStorage())
        XCTAssertEqual(try owner.read { try $0.epoch(Data(repeating: 3, count: 16))?.head }, 0)
        XCTAssertThrowsError(try owner.write { _ in XCTFail("raw write callback ran") }) {
            XCTAssertEqual($0 as? JournalDatabaseError, .readOnly)
        }
        try fixture.sql("UPDATE continuity_v1 SET repair=1")
        XCTAssertThrowsError(try owner.read { _ in XCTFail("read callback ran after repair marker") })
        try owner.close()
        try fixture.reopen()
        XCTAssertTrue(try fixture.store.read().recoveryRequired)
    }

    func testRejectedReentrantClosePreservesBothStores() throws {
        let fixture = try Fixture()
        try fixture.journal.close(); fixture.store.close()
        let owner = try AuthorityJournal(storage: fixture.openTransferredStorage())
        let head = try owner.read { transaction in
            XCTAssertThrowsError(try owner.close()) {
                XCTAssertEqual($0 as? JournalDatabaseError, .transactionActive)
            }
            return try transaction.epoch(Data(repeating: 3, count: 16))?.head
        }
        XCTAssertEqual(head, 0)
        XCTAssertThrowsError(try fixture.openJournal()) {
            XCTAssertEqual($0 as? JournalLeaseError, .busy)
        }
        XCTAssertThrowsError(try fixture.openStore()) {
            XCTAssertEqual($0 as? JournalLeaseError, .busy)
        }
        XCTAssertEqual(try owner.read { try $0.epoch(Data(repeating: 3, count: 16))?.head }, 0)
        try owner.close()
        try owner.close()
        try fixture.reopen()
        XCTAssertFalse(try fixture.store.read().recoveryRequired)
    }

    func testPairedAuthorityOwnerRejectsHistoryLossAndReleasesBothStores() throws {
        let fixture = try Fixture()
        try fixture.journal.write { try fixture.append($0) }
        try fixture.journal.close(); fixture.store.close()
        XCTAssertThrowsError(try AuthorityJournal(storage: fixture.openTransferredStorage())) {
            guard case AuthorityStorageStartupError.historyRecoveryRequired = $0 else { return XCTFail("wrong startup failure") }
        }
        try fixture.reopen()
        XCTAssertFalse(try fixture.store.read().recoveryRequired)
    }

    func testServiceClosesPairedStoresOnShutdownAndConstructionFailure() throws {
        for wrongScope in [false, true] {
            let fixture = try Fixture()
            let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1)
            let commits = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
            _ = try commits.write(epoch: fixture.epoch) {
                try $0.configureApprovalAuthority(capabilities: ContractCapabilities(contracts: [contract: []]), allowedContracts: [contract])
            }
            try fixture.journal.close(); fixture.store.close()
            let owner = try AuthorityJournal(storage: fixture.openTransferredStorage())
            let configuration = try AuthorityServiceConfiguration(macID: Data(repeating: wrongScope ? 9 : 1, count: 16),
                accountID: Data(repeating: 2, count: 16), journalDirectory: fixture.root.appendingPathComponent("journal").path,
                serviceName: "dev.remozio.authority.test", teamID: "ABCDEFGHIJ", transportIdentifier: "dev.remozio.transport",
                transportHashes: [Data(repeating: 3, count: 20)], transportUID: 501,
                continuityDirectory: fixture.root.appendingPathComponent("continuity").path)
            if wrongScope {
                XCTAssertThrowsError(try AuthorityService(configuration: configuration, journal: owner))
            } else {
                let service = try AuthorityService(configuration: configuration, journal: owner)
                XCTAssertThrowsError(try fixture.openJournal())
                XCTAssertThrowsError(try fixture.openStore())
                try service.close()
            }
            XCTAssertThrowsError(try owner.read { _ in 1 })
            try fixture.reopen()
            XCTAssertFalse(try fixture.store.read().recoveryRequired)
        }
    }

    func testStartupRetryReleasesJournalWhileContinuityIsBusy() throws {
        let fixture = try Fixture()
        try fixture.journal.close()
        let anchor = fixture.root.path, limits = fixture.limits
        let waiting = expectation(description: "continuity contention")
        waiting.assertForOverFulfill = false
        let running = expectation(description: "paired storage acquired")
        let runner = try AuthorityServiceRunner(initialRetryMilliseconds: 1000, maximumRetryMilliseconds: 1000, open: {
            let owner = try AuthorityJournal(storage: Fixture.openTransferredStorage(anchor: anchor, limits: limits))
            return { try owner.close() }
        }, report: {
            if case .waiting = $0 { waiting.fulfill() }
            if $0 == .running { running.fulfill() }
        })
        defer { try? runner.close() }
        try runner.start()
        wait(for: [waiting], timeout: 3)
        let availableJournal = try fixture.openJournal()
        try availableJournal.close()
        fixture.store.close()
        wait(for: [running], timeout: 5)
        XCTAssertThrowsError(try fixture.openJournal()) {
            XCTAssertEqual($0 as? JournalLeaseError, .busy)
        }
        XCTAssertThrowsError(try fixture.openStore()) {
            XCTAssertEqual($0 as? JournalLeaseError, .busy)
        }
        try runner.close()
        try fixture.reopen()
        XCTAssertEqual(try fixture.store.read().committed, try fixture.observed(generation: 1))
    }

    func testTrustGenerationChangesOnlyForAuthorityStateAndBindsFreshEpoch() throws {
        let fixture = try Fixture()
        let commits = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
        let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1)
        _ = try commits.write(epoch: fixture.epoch) {
            try $0.configureApprovalAuthority(capabilities: ContractCapabilities(contracts: [contract: []]), allowedContracts: [contract])
        }
        XCTAssertEqual(try fixture.store.read().committed.authorityGeneration, 8)
        try commits.write(epoch: fixture.epoch) { _ in () }
        try commits.write(epoch: fixture.epoch) { try fixture.append($0) }
        XCTAssertEqual(try fixture.store.read().committed.generation, 4)
        XCTAssertEqual(try fixture.store.read().committed.authorityGeneration, 8)
        try fixture.reopen()
        XCTAssertEqual(try fixture.store.read().committed.authorityGeneration, 8)
        XCTAssertEqual(try fixture.journal.read { try $0.epoch(fixture.epoch)?.descriptor.generation }, 7)
        let next = Data(repeating: 9, count: 16)
        let stale = try JournalStartupRecovery(journal: fixture.journal, continuity: fixture.store,
            maximumRecords: 1, maximumBytes: 16384)
        XCTAssertThrowsError(try stale.start(descriptor: fixture.descriptor(next))) {
            guard case JournalStartupRecovery.Failure.invalidEpoch = $0 else { return XCTFail("wrong error") }
        }
        XCTAssertNil(try fixture.journal.read { try $0.epoch(next) })
        let current = try JournalStartupRecovery(journal: fixture.journal, continuity: fixture.store,
            maximumRecords: 1, maximumBytes: 16384)
        guard case .recovering = try current.start(descriptor: fixture.descriptor(next, generation: 8)) else {
            return XCTFail("startup did not begin")
        }
        XCTAssertEqual(try fixture.journal.read { try $0.epoch(next)?.descriptor.generation }, 8)
        XCTAssertEqual(try fixture.store.read().committed.authorityGeneration, 8)
        guard case .complete = try current.advance() else { return XCTFail("recovery did not complete") }
    }

    func testTrustGenerationRecoveryFinalizesOnlyOnce() throws {
        let fixture = try Fixture()
        try fixture.sql("CREATE TRIGGER fail_finalize BEFORE UPDATE ON continuity_v1 WHEN NEW.pending IS NULL BEGIN SELECT RAISE(ABORT,'injected'); END")
        let commits = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
        let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1)
        XCTAssertThrowsError(try commits.write(epoch: fixture.epoch) {
            try $0.configureApprovalAuthority(capabilities: ContractCapabilities(contracts: [contract: []]), allowedContracts: [contract])
        })
        XCTAssertEqual(try fixture.store.read().committed.authorityGeneration, 7)
        XCTAssertEqual(try fixture.store.read().pending?.authorityGeneration, 8)
        try fixture.reopen()
        try fixture.sql("DROP TRIGGER fail_finalize")
        _ = try JournalCheckpointRecovery.reconcile(journal: fixture.journal, continuity: fixture.store)
        XCTAssertEqual(try fixture.store.read().committed.authorityGeneration, 8)
        let recovered = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
        try recovered.write(epoch: fixture.epoch) { _ in () }
        XCTAssertEqual(try fixture.store.read().committed.authorityGeneration, 8)
    }

    func testLegacyPreparedBoundaryAndInterruptedUpgradeRemainRecoverable() throws {
        let fixture = try Fixture(authorityGeneration: nil)
        let legacy = try fixture.store.read().committed
        XCTAssertNil(legacy.authorityGeneration)
        let pending = try fixture.observed(generation: 2, authorityGeneration: nil)
        try fixture.store.prepare(expected: legacy, candidate: pending)
        try fixture.reopen()
        XCTAssertEqual(try JournalCheckpointRecovery.reconcile(journal: fixture.journal, continuity: fixture.store), .finalized(pending))
        try fixture.sql("CREATE TRIGGER fail_finalize BEFORE UPDATE ON continuity_v1 WHEN NEW.pending IS NULL BEGIN SELECT RAISE(ABORT,'injected'); END")
        let commits = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
        XCTAssertThrowsError(try commits.write(epoch: fixture.epoch) { _ in () })
        XCTAssertNil(try fixture.store.read().committed.authorityGeneration)
        XCTAssertEqual(try fixture.store.read().pending?.authorityGeneration, 2)
        try fixture.reopen()
        try fixture.sql("DROP TRIGGER fail_finalize")
        _ = try JournalCheckpointRecovery.reconcile(journal: fixture.journal, continuity: fixture.store)
        XCTAssertEqual(try fixture.store.read().committed.authorityGeneration, 2)
        XCTAssertEqual(try fixture.store.read().committed.generation, 3)
        XCTAssertEqual(try fixture.journal.read { try $0.epoch(fixture.epoch)?.descriptor.generation }, 7)
    }

    func testTrustGenerationExhaustionRollsBackTrustButAllowsAuditWrites() throws {
        let fixture = try Fixture(authorityGeneration: .max)
        let commits = CheckpointedJournal(journal: fixture.journal, continuity: fixture.store)
        try commits.write(epoch: fixture.epoch) { try fixture.append($0) }
        let before = try fixture.store.read()
        let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1)
        XCTAssertThrowsError(try commits.write(epoch: fixture.epoch) {
            try $0.configureApprovalAuthority(capabilities: ContractCapabilities(contracts: [contract: []]), allowedContracts: [contract])
        })
        try fixture.reopen()
        XCTAssertEqual(try fixture.store.read(), before)
        XCTAssertFalse(try fixture.store.read().recoveryRequired)
        XCTAssertThrowsError(try fixture.journal.read { try $0.approvalTrustSnapshot() }) {
            XCTAssertEqual($0 as? EnrollmentJournalError, .unconfigured)
        }
    }

    private final class Fixture {
        let root: URL
        let epoch = Data(repeating: 3, count: 16)
        let limits = try! CBORLimits(maxBytes: 16384, maxDepth: 8, maxItems: 512)
        var journal: JournalDatabase!
        var store: ContinuityStore!
        var writer: AuditEpochWriter!
        init(authorityGeneration: UInt64? = 7) throws {
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
            store = try openStore(initial: observed(generation: 1, authorityGeneration: authorityGeneration))
        }
        deinit { try? journal?.close(); store?.close(); try? FileManager.default.removeItem(at: root) }
        func openJournal(initialize: Bool = false) throws -> sending JournalDatabase {
            try JournalDatabase(lease: ProtectedJournalLease(anchor: root.path, relativeDirectory: "journal", owner: geteuid()),
                macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16),
                recordLimits: limits, descriptorLimits: limits, decisionLimits: limits, maximumConsumptions: 10,
                busyMilliseconds: 100, initialize: initialize)
        }
        func openStore(initial: ContinuityCheckpoint? = nil, directory: String = "continuity",
                       excludingDirectory: ProtectedStorageLease.DirectoryIdentity? = nil) throws -> sending ContinuityStore {
            try ContinuityStore(lease: ProtectedContinuityLease(anchor: root.path, relativeDirectory: directory, owner: geteuid(), excludingDirectory: excludingDirectory),
                macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16), initialize: initial)
        }
        func reopen() throws {
            try journal.close(); store.close()
            journal = try openJournal(); store = try openStore()
        }
        func observed(generation: UInt64, authorityGeneration: UInt64? = 7) throws -> ContinuityCheckpoint {
            try journal.read { try CheckpointedJournal.checkpoint(transaction: $0, epoch: epoch, generation: generation, authorityGeneration: authorityGeneration) }
        }
        func openTransferredStorage() throws -> sending AuthorityStorage {
            try Self.openTransferredStorage(anchor: root.path, limits: limits)
        }
        static func openTransferredStorage(anchor: String, limits: CBORLimits) throws -> sending AuthorityStorage {
            return try AuthorityStorage(openJournal: {
                try JournalDatabase(lease: ProtectedJournalLease(anchor: anchor, relativeDirectory: "journal", owner: geteuid()),
                    macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16),
                    recordLimits: limits, descriptorLimits: limits, decisionLimits: limits,
                    maximumConsumptions: 10, busyMilliseconds: 100, initialize: false)
            }, openContinuity: { journalDirectory in
                try ContinuityStore(lease: ProtectedContinuityLease(anchor: anchor, relativeDirectory: "continuity", owner: geteuid(),
                    excludingDirectory: journalDirectory),
                    macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16), initialize: nil)
            })
        }
        func descriptor(_ next: Data, generation: UInt64 = 7) throws -> AuditEpochDescriptor {
            try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
                0: .unsigned(1), 1: .bytes(Data(repeating: 1, count: 16)), 2: .bytes(Data(repeating: 2, count: 16)),
                3: .bytes(next), 4: .unsigned(generation), 5: .unsigned(1), 6: .null, 7: .null, 8: .null,
            ]), limits: limits), limits: limits)
        }
        func append(_ transaction: JournalTransaction) throws {
            let event = try AuditEventMetadata(eventID: Data(repeating: 4, count: 16), macID: Data(repeating: 1, count: 16),
                accountID: Data(repeating: 2, count: 16), journalEpoch: epoch, sequence: 1, requestID: nil,
                eventTimeMs: nil, authorityReceiptTimeMs: nil, kind: .consumed, category: .command, action: nil,
                decisionPhoneID: nil, authentication: .system, outcome: .accepted, reason: .none,
                droppedEventCount: nil, peerDeviceID: nil).encode(limits: limits)
            try transaction.append(event, writer: writer, expectedHead: 0)
        }
        func sql(_ query: String, journal: Bool = false) throws {
            var connection: OpaquePointer?
            guard sqlite3_open(root.appendingPathComponent(journal ? "journal/journal.sqlite" : "continuity/continuity.sqlite").path, &connection) == SQLITE_OK,
                  let connection else { throw Fault.injected }
            defer { sqlite3_close(connection) }
            guard sqlite3_exec(connection, query, nil, nil, nil) == SQLITE_OK else { throw Fault.injected }
        }
    }
}
