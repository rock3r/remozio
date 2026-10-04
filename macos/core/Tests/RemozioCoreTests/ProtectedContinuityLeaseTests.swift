import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class ProtectedContinuityLeaseTests: XCTestCase {
    func testSeparateStoreRetainsExclusiveOwnershipAfterJournalReplacement() throws {
        let fixture = try Fixture()
        let journal = try ProtectedJournalLease(anchor: fixture.root.path, relativeDirectory: "journal", owner: geteuid())
        let continuity = try fixture.acquire()
        defer { journal.close(); continuity.close() }
        XCTAssertEqual(continuity.databasePath, fixture.path("continuity/continuity.sqlite"))
        XCTAssertThrowsError(try fixture.acquire()) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
        XCTAssertEqual(rename(fixture.path("journal/journal.sqlite"), fixture.path("journal/old.sqlite")), 0)
        try Fixture.file(fixture.path("journal/journal.sqlite"))
        XCTAssertThrowsError(try journal.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .identityChanged) }
        try continuity.validate()
        continuity.close()
        let next = try fixture.acquire()
        try next.validate(); next.close()
    }

    func testMissingContinuityFileDoesNotFallBackToJournalOrCreateState() throws {
        let fixture = try Fixture()
        XCTAssertEqual(rename(fixture.path("continuity/continuity.sqlite"), fixture.path("continuity/journal.sqlite")), 0)
        XCTAssertThrowsError(try fixture.acquire())
        XCTAssertFalse(FileManager.default.fileExists(atPath: fixture.path("continuity/continuity.sqlite")))
        try Fixture.file(fixture.path("continuity/continuity.sqlite"))
        let lease = try fixture.acquire()
        lease.close()
    }

    func testProductionRequiresRootAndReplacementRetiresFixtureLease() throws {
        let fixture = try Fixture()
        if geteuid() != 0 {
            XCTAssertThrowsError(try ProtectedContinuityLease.acquire(directoryPath: fixture.path("continuity"))) {
                XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
            }
        }
        let lease = try fixture.acquire()
        defer { lease.close() }
        let path = fixture.path("continuity/continuity.sqlite")
        XCTAssertEqual(rename(path, path + ".old"), 0)
        try Fixture.file(path)
        XCTAssertThrowsError(try lease.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .identityChanged) }
        try FileManager.default.removeItem(atPath: path)
        XCTAssertEqual(rename(path + ".old", path), 0)
        XCTAssertThrowsError(try lease.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
    }

    private final class Fixture {
        let root: URL
        init() throws {
            root = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent(UUID().uuidString)
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
        static func file(_ path: String) throws {
            let fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
            guard fd >= 0 else { throw JournalLeaseError.system(errno) }
            Darwin.close(fd)
        }
    }
}
