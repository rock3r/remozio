import Darwin
import Foundation
import SQLite3
import XCTest
import RemozioProtocol
@testable import RemozioCore

final class ContinuityStoreTests: XCTestCase {
    private let mac = Data(repeating: 1, count: 16), account = Data(repeating: 2, count: 16)
    private func checkpoint(_ generation: UInt64) throws -> ContinuityCheckpoint {
        try ContinuityCheckpoint(generation: generation, authorityDigest: Data(repeating: 3, count: 32),
            ledgerDigest: Data(repeating: UInt8(generation), count: 32), journalEpoch: Data(repeating: 4, count: 16),
            journalHead: generation, authorityGeneration: 1)
    }
    private func open(_ fixture: Fixture, initial: ContinuityCheckpoint? = nil) throws -> ContinuityStore {
        try ContinuityStore(lease: fixture.acquire(), macID: mac, accountID: account, initialize: initial)
    }

    func testPreparationAndFinalizationSurviveReopen() throws {
        let fixture = try Fixture(), first = try checkpoint(1), second = try checkpoint(2)
        var store = try open(fixture, initial: first)
        XCTAssertEqual(try store.read().committed, first)
        try store.prepare(expected: first, candidate: second)
        let prepared = try store.read()
        XCTAssertEqual(prepared.pending, second)
        store.close()
        store = try open(fixture)
        XCTAssertEqual(try store.read(), prepared)
        try store.finalize(expected: prepared)
        XCTAssertThrowsError(try store.finalize(expected: prepared))
        store.close()
        store = try open(fixture)
        defer { store.close() }
        XCTAssertEqual(try store.read().committed, second)
        XCTAssertNil(try store.read().pending)
    }

    func testDiscardAndStickyRecoveryMarker() throws {
        let fixture = try Fixture(), first = try checkpoint(1), second = try checkpoint(2)
        var store = try open(fixture, initial: first)
        try store.prepare(expected: first, candidate: second)
        try store.discardPreparation(expected: store.read())
        XCTAssertEqual(try store.read().committed, first)
        XCTAssertNil(try store.read().pending)
        try store.prepare(expected: first, candidate: second)
        let prepared = try store.read()
        try store.requireRecovery(); try store.requireRecovery()
        store.close()
        store = try open(fixture)
        defer { store.close() }
        XCTAssertTrue(try store.read().recoveryRequired)
        XCTAssertThrowsError(try store.finalize(expected: prepared))
        XCTAssertThrowsError(try store.discardPreparation(expected: prepared))
        XCTAssertThrowsError(try store.prepare(expected: first, candidate: second))
        XCTAssertEqual(try store.read().pending, second)
    }

    func testRejectsMissingInitializationWrongScopeAndStaleTransitions() throws {
        let fixture = try Fixture(), first = try checkpoint(1), second = try checkpoint(2)
        XCTAssertThrowsError(try open(fixture))
        let store = try open(fixture, initial: first)
        XCTAssertThrowsError(try store.prepare(expected: first, candidate: checkpoint(3)))
        XCTAssertEqual(try store.read().committed, first)
        try store.prepare(expected: first, candidate: second)
        XCTAssertThrowsError(try store.prepare(expected: first, candidate: second))
        store.close()
        XCTAssertThrowsError(try store.read()) { XCTAssertEqual($0 as? ContinuityStoreError, .closed) }
        XCTAssertThrowsError(try open(fixture, initial: first))
        XCTAssertThrowsError(try ContinuityStore(lease: fixture.acquire(), macID: Data(repeating: 9, count: 16),
            accountID: account, initialize: nil)) { XCTAssertEqual($0 as? ContinuityStoreError, .wrongScope) }
        let reopened = try open(fixture)
        defer { reopened.close() }
        XCTAssertEqual(try reopened.read().pending, second)
    }

    func testFailedWritesPreserveBothBoundariesAndDoNotSetRecovery() throws {
        for operation in ["prepare", "finalize", "discard", "marker"] {
            let fixture = try Fixture(), first = try checkpoint(1), second = try checkpoint(2)
            var store = try open(fixture, initial: first)
            if operation != "prepare" { try store.prepare(expected: first, candidate: second) }
            let before = try store.read()
            try fixture.sql("CREATE TRIGGER fail_update BEFORE UPDATE ON continuity_v1 BEGIN SELECT RAISE(ABORT,'injected'); END")
            func mutate(_ store: ContinuityStore) throws {
                switch operation {
                case "prepare": try store.prepare(expected: first, candidate: second)
                case "finalize": try store.finalize(expected: before)
                case "discard": try store.discardPreparation(expected: before)
                default: try store.requireRecovery()
                }
            }
            XCTAssertThrowsError(try mutate(store)) { XCTAssertEqual($0 as? ContinuityStoreError, .storage(SQLITE_CONSTRAINT)) }
            XCTAssertEqual(try store.read(), before)
            store.close()
            store = try open(fixture)
            XCTAssertEqual(try store.read(), before)
            try fixture.sql("DROP TRIGGER fail_update")
            try mutate(store)
            XCTAssertNotEqual(try store.read(), before)
            store.close()
        }
    }

    func testCorruptAndUnsupportedStateCannotBeOpenedOrReinitialized() throws {
        for corruption in ["UPDATE continuity_v1 SET committed=x'00'", "UPDATE continuity_v1 SET pending=zeroblob(257)",
                           "DELETE FROM continuity_v1", "PRAGMA user_version=2"] {
            let fixture = try Fixture(), first = try checkpoint(1)
            let store = try open(fixture, initial: first)
            store.close()
            try fixture.sql(corruption)
            XCTAssertThrowsError(try open(fixture))
            XCTAssertThrowsError(try open(fixture, initial: first))
        }
    }

    func testCheckpointBoundsAndExhaustedGeneration() throws {
        let authority = Data(repeating: 1, count: 32), epoch = Data(repeating: 2, count: 16)
        let last = try ContinuityCheckpoint(generation: .max, authorityDigest: authority, ledgerDigest: authority,
                                            journalEpoch: epoch, journalHead: .max)
        XCTAssertEqual(try ContinuityCheckpoint.decode(last.bytes), last)
        XCTAssertThrowsError(try ContinuityState(committed: last, pending: last, recoveryRequired: false))
        XCTAssertThrowsError(try ContinuityCheckpoint(generation: 0, authorityDigest: authority, ledgerDigest: authority,
                                                       journalEpoch: epoch, journalHead: 0))
        XCTAssertThrowsError(try ContinuityCheckpoint(generation: 1, authorityDigest: Data(), ledgerDigest: authority,
                                                       journalEpoch: epoch, journalHead: 0))
        XCTAssertThrowsError(try ContinuityCheckpoint(generation: 1, authorityDigest: authority, ledgerDigest: Data(),
                                                       journalEpoch: epoch, journalHead: 0))
        XCTAssertThrowsError(try ContinuityCheckpoint(generation: 1, authorityDigest: authority, ledgerDigest: authority,
                                                       journalEpoch: Data(), journalHead: 0))
    }

    func testVersionedCheckpointsRoundTripAndRejectMalformedGenerationFields() throws {
        let legacy = try ContinuityCheckpoint(generation: 5, authorityDigest: mac + mac,
            ledgerDigest: account + account, journalEpoch: mac, journalHead: 0)
        let legacyBytes = try legacy.bytes
        XCTAssertEqual(try ContinuityCheckpoint.decode(legacyBytes).bytes, legacyBytes)
        XCTAssertNil(try ContinuityCheckpoint.decode(legacyBytes).authorityGeneration)
        let current = try legacy.successor(authorityDigest: legacy.authorityDigest, ledgerDigest: legacy.ledgerDigest,
            journalEpoch: legacy.journalEpoch, journalHead: legacy.journalHead)
        XCTAssertEqual(current.authorityGeneration, 5)
        XCTAssertEqual(try ContinuityCheckpoint.decode(current.bytes), current)
        let limits = try CBORLimits(maxBytes: 256, maxDepth: 2, maxItems: 64)
        guard case .map(let fields) = try DeterministicCBOR.decode(current.bytes, limits: limits) else { return XCTFail("not a map") }
        for replacement: CBORValue? in [nil, .null, .unsigned(0), .text("5")] {
            var invalid = fields; invalid[6] = replacement
            XCTAssertThrowsError(try ContinuityCheckpoint.decode(DeterministicCBOR.encode(.map(invalid), limits: limits)))
        }
        for version: UInt64 in [0, 1, 3] {
            var invalid = fields; invalid[0] = .unsigned(version)
            XCTAssertThrowsError(try ContinuityCheckpoint.decode(DeterministicCBOR.encode(.map(invalid), limits: limits)))
        }
    }

    func testGenerationTransitionRulesRejectFalseAdvancesAndDowngrades() throws {
        let fixture = try Fixture(), first = try checkpoint(1), store = try open(fixture, initial: first)
        defer { store.close() }
        for (digest, generation): (Data, UInt64?) in [
            (first.authorityDigest, 2), (Data(repeating: 9, count: 32), 1),
            (Data(repeating: 9, count: 32), 3), (first.authorityDigest, nil)
        ] {
            let invalid = try ContinuityCheckpoint(generation: 2, authorityDigest: digest,
                ledgerDigest: first.ledgerDigest, journalEpoch: first.journalEpoch, journalHead: 0,
                authorityGeneration: generation)
            XCTAssertThrowsError(try store.prepare(expected: first, candidate: invalid)) {
                XCTAssertEqual($0 as? ContinuityStoreError, .invalidCheckpoint)
            }
            XCTAssertNil(try store.read().pending)
        }
        let valid = try first.successor(authorityDigest: Data(repeating: 9, count: 32),
            ledgerDigest: first.ledgerDigest, journalEpoch: first.journalEpoch, journalHead: 0)
        XCTAssertEqual(valid.authorityGeneration, 2)
        try store.prepare(expected: first, candidate: valid)
        XCTAssertEqual(try store.read().pending, valid)
    }

    private func recovery(_ state: ContinuityState) throws -> HistoryRecoveryIntent {
        try HistoryRecoveryIntent(previous: state, authorityDigest: state.committed.authorityDigest,
            ledgerDigest: Data(repeating: 9, count: 32), recoveryEpoch: Data(repeating: 8, count: 16))
    }

    private func recoveredCheckpoint(_ intent: HistoryRecoveryIntent) throws -> ContinuityCheckpoint {
        try ContinuityCheckpoint(generation: intent.checkpointGeneration, authorityDigest: intent.authorityDigest,
            ledgerDigest: Data(repeating: 7, count: 32), journalEpoch: intent.recoveryEpoch, journalHead: 1,
            authorityGeneration: intent.authorityGeneration)
    }

    func testHistoryRecoverySurvivesReopenAndBlocksOrdinaryTransitions() throws {
        let fixture = try Fixture(), first = try checkpoint(1), second = try checkpoint(2)
        var store = try open(fixture, initial: first)
        XCTAssertNil(try store.historyRecovery())
        try store.prepare(expected: first, candidate: second)
        let previous = try store.read(), intent = try recovery(previous)
        try store.prepareHistoryRecovery(intent)
        store.close()
        store = try open(fixture)
        XCTAssertEqual(try store.historyRecovery(), intent)
        XCTAssertThrowsError(try store.read()) { XCTAssertEqual($0 as? ContinuityStoreError, .historyRecoveryPending) }
        XCTAssertThrowsError(try store.prepare(expected: first, candidate: second))
        XCTAssertThrowsError(try store.finalize(expected: previous))
        XCTAssertThrowsError(try store.discardPreparation(expected: previous))
        XCTAssertThrowsError(try store.prepareHistoryRecovery(intent))
        XCTAssertEqual(try store.historyRecovery(), intent)
        let candidate = try recoveredCheckpoint(intent)
        try store.finalizeHistoryRecovery(expected: intent, candidate: candidate)
        store.close()
        store = try open(fixture)
        defer { store.close() }
        XCTAssertNil(try store.historyRecovery())
        XCTAssertEqual(try store.read().committed, candidate)
        XCTAssertNil(try store.read().pending)
        XCTAssertThrowsError(try store.finalizeHistoryRecovery(expected: intent, candidate: candidate))
        let next = try candidate.successor(authorityDigest: candidate.authorityDigest, ledgerDigest: candidate.ledgerDigest,
            journalEpoch: candidate.journalEpoch, journalHead: 2)
        try store.prepare(expected: candidate, candidate: next)
        try store.finalize(expected: store.read())
        XCTAssertEqual(try store.read().committed, next)
    }

    func testFailedHistoryPreparationRollsBackMigrationAndEvidence() throws {
        let fixture = try Fixture(), first = try checkpoint(1)
        var store = try open(fixture, initial: first)
        let previous = try store.read(), intent = try recovery(previous)
        try fixture.sql("CREATE TRIGGER fail_update BEFORE UPDATE ON continuity_v1 BEGIN SELECT RAISE(ABORT,'injected'); END")
        XCTAssertThrowsError(try store.prepareHistoryRecovery(intent))
        XCTAssertEqual(try store.read(), previous)
        XCTAssertNil(try store.historyRecovery())
        store.close()
        store = try open(fixture)
        defer { store.close() }
        XCTAssertEqual(try store.read(), previous)
        try fixture.sql("DROP TRIGGER fail_update")
        try store.prepareHistoryRecovery(intent)
        XCTAssertEqual(try store.historyRecovery(), intent)
    }

    func testFailedHistoryFinalizationRetainsEvidenceAcrossReopen() throws {
        let fixture = try Fixture(), first = try checkpoint(1)
        var store = try open(fixture, initial: first)
        let intent = try recovery(store.read()), candidate = try recoveredCheckpoint(intent)
        try store.prepareHistoryRecovery(intent)
        try fixture.sql("CREATE TRIGGER fail_update BEFORE UPDATE ON continuity_v1 BEGIN SELECT RAISE(ABORT,'injected'); END")
        XCTAssertThrowsError(try store.finalizeHistoryRecovery(expected: intent, candidate: candidate))
        XCTAssertEqual(try store.historyRecovery(), intent)
        store.close()
        store = try open(fixture)
        defer { store.close() }
        XCTAssertEqual(try store.historyRecovery(), intent)
        XCTAssertThrowsError(try store.read())
        try fixture.sql("DROP TRIGGER fail_update")
        try store.finalizeHistoryRecovery(expected: intent, candidate: candidate)
        XCTAssertEqual(try store.read().committed, candidate)
    }

    func testHistoryRecoveryRejectsStaleAndWrongCandidatesAndPreservesRepairMarker() throws {
        let fixture = try Fixture(), first = try checkpoint(1), second = try checkpoint(2)
        var store = try open(fixture, initial: first)
        let stale = try recovery(store.read())
        try store.prepare(expected: first, candidate: second)
        XCTAssertThrowsError(try store.prepareHistoryRecovery(stale))
        let intent = try recovery(store.read()), candidate = try recoveredCheckpoint(intent)
        try store.prepareHistoryRecovery(intent)
        XCTAssertThrowsError(try store.finalizeHistoryRecovery(expected: stale, candidate: candidate))
        XCTAssertThrowsError(try store.finalizeHistoryRecovery(expected: intent, candidate: second))
        XCTAssertEqual(try store.historyRecovery(), intent)
        try store.requireRecovery()
        store.close()
        store = try open(fixture)
        defer { store.close() }
        XCTAssertThrowsError(try store.historyRecovery()) { XCTAssertEqual($0 as? ContinuityStoreError, .recoveryRequired) }
        XCTAssertThrowsError(try store.finalizeHistoryRecovery(expected: intent, candidate: candidate)) {
            XCTAssertEqual($0 as? ContinuityStoreError, .recoveryRequired)
        }
    }

    func testCorruptHistoryEvidenceFailsReopen() throws {
        for corruption in ["UPDATE continuity_v1 SET history=x'00'", "UPDATE continuity_v1 SET history=zeroblob(1025)",
                           "UPDATE continuity_v1 SET pending=NULL"] {
            let fixture = try Fixture(), first = try checkpoint(1), store = try open(fixture, initial: first)
            try store.prepare(expected: first, candidate: checkpoint(2))
            try store.prepareHistoryRecovery(recovery(store.read()))
            store.close()
            try fixture.sql(corruption)
            XCTAssertThrowsError(try open(fixture))
        }
    }

    private final class Fixture {
        let root: URL
        init() throws {
            guard let canonical = realpath(FileManager.default.temporaryDirectory.path, nil) else {
                throw JournalLeaseError.system(errno)
            }
            defer { free(canonical) }
            root = URL(fileURLWithPath: String(cString: canonical)).appendingPathComponent(UUID().uuidString)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            for name in ["journal", "continuity"] {
                try FileManager.default.createDirectory(atPath: path(name), withIntermediateDirectories: false,
                                                        attributes: [.posixPermissions: 0o700])
                try Self.file(path(name + "/writer.lock"))
                try Self.file(path(name + "/" + name + ".sqlite"))
            }
        }
        deinit { try? FileManager.default.removeItem(at: root) }
        func path(_ suffix: String) -> String { root.appendingPathComponent(suffix).path }
        func acquire() throws -> ProtectedContinuityLease {
            try ProtectedContinuityLease(anchor: root.path, relativeDirectory: "continuity", owner: geteuid())
        }
        func sql(_ query: String) throws {
            var connection: OpaquePointer?
            let result = sqlite3_open(path("continuity/continuity.sqlite"), &connection)
            guard result == SQLITE_OK, let connection else { throw ContinuityStoreError.storage(result) }
            defer { sqlite3_close(connection) }
            let status = sqlite3_exec(connection, query, nil, nil, nil)
            guard status == SQLITE_OK else { throw ContinuityStoreError.storage(status) }
        }
        static func file(_ path: String) throws {
            let fd = Darwin.open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
            guard fd >= 0 else { throw JournalLeaseError.system(errno) }
            Darwin.close(fd)
        }
    }
}
