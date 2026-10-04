import Darwin
import Foundation
import SQLite3
import XCTest
@testable import RemozioCore

final class ContinuityStoreTests: XCTestCase {
    private let mac = Data(repeating: 1, count: 16), account = Data(repeating: 2, count: 16)
    private func checkpoint(_ generation: UInt64) throws -> ContinuityCheckpoint {
        try ContinuityCheckpoint(generation: generation, authorityDigest: Data(repeating: 3, count: 32),
            ledgerDigest: Data(repeating: UInt8(generation), count: 32), journalEpoch: Data(repeating: 4, count: 16),
            journalHead: generation)
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
