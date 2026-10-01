import Darwin
import Foundation
@testable import RemozioCore
import XCTest

final class ProtectedJournalLeaseTests: XCTestCase {
    func testExclusiveOwnershipAndExplicitRelease() throws {
        let fixture = try Fixture()
        let lease = try fixture.acquire()
        XCTAssertEqual(lease.databasePath, fixture.path("journal.sqlite"))
        try lease.validate()
        XCTAssertThrowsError(try fixture.acquire()) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
        lease.close(); lease.close()
        XCTAssertThrowsError(try lease.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .closed) }
        let next = try fixture.acquire()
        try next.validate(); next.close()
    }

    func testAnotherProcessCannotTakeTheHeldLock() throws {
        let fixture = try Fixture(), lease = try fixture.acquire()
        let code = """
            import fcntl, sys
            with open(sys.argv[1], 'r+b') as lock:
                try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError: sys.exit(42)
            """
        XCTAssertEqual(try run("/usr/bin/env", ["python3", "-c", code, fixture.path("writer.lock")]), 42)
        lease.close()
        XCTAssertEqual(try run("/usr/bin/env", ["python3", "-c", code, fixture.path("writer.lock")]), 0)
    }

    func testProductionEntryPointDoesNotAllowAnUnprivilegedOwnerOverride() throws {
        guard geteuid() != 0 else { throw XCTSkip("This test requires a normal user") }
        let fixture = try Fixture()
        XCTAssertThrowsError(try ProtectedJournalLease.acquire(directoryPath: fixture.directory)) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
        XCTAssertThrowsError(try ProtectedJournalLease(anchor: fixture.root.path, relativeDirectory: "parent/store", owner: getuid() + 1))
    }

    func testRejectsAmbiguousPathsWithoutCreatingAnything() throws {
        let fixture = try Fixture()
        for path in ["", "/parent/store", "parent//store", "parent/./store", "parent/../store", "parent/store/", "parent/st\0ore", String(repeating: "a", count: 256)] {
            XCTAssertThrowsError(try ProtectedJournalLease(anchor: fixture.root.path, relativeDirectory: path, owner: getuid())) {
                XCTAssertEqual($0 as? JournalLeaseError, .invalidPath)
            }
        }
        XCTAssertThrowsError(try ProtectedJournalLease(anchor: fixture.root.path, relativeDirectory: "missing", owner: getuid()))
        XCTAssertFalse(FileManager.default.fileExists(atPath: fixture.root.appendingPathComponent("missing").path))
    }

    func testRejectsSymlinksHardlinksAndNonRegularFiles() throws {
        for name in ["writer.lock", "journal.sqlite"] {
            for kind in ["symlink", "hardlink", "fifo", "directory"] {
                let fixture = try Fixture(), path = fixture.path(name), old = path + ".original"
                XCTAssertEqual(rename(path, old), 0)
                switch kind {
                case "symlink": XCTAssertEqual(symlink(old, path), 0)
                case "hardlink": XCTAssertEqual(link(old, path), 0)
                case "fifo": XCTAssertEqual(mkfifo(path, 0o600), 0)
                default: XCTAssertEqual(mkdir(path, 0o700), 0)
                }
                XCTAssertThrowsError(try fixture.acquire(), "\(name): \(kind)")
            }
        }
        let fixture = try Fixture(), parent = fixture.root.appendingPathComponent("parent").path
        XCTAssertEqual(rename(parent, parent + ".original"), 0)
        XCTAssertEqual(symlink(parent + ".original", parent), 0)
        XCTAssertThrowsError(try fixture.acquire())
    }

    func testRejectsWritableAncestorsAndExposedPrivateObjects() throws {
        for (relative, mode) in [("parent", mode_t(0o770)), ("parent/store", mode_t(0o750)),
                                 ("parent/store/writer.lock", mode_t(0o640)), ("parent/store/journal.sqlite", mode_t(0o660))] {
            let fixture = try Fixture()
            XCTAssertEqual(chmod(fixture.root.appendingPathComponent(relative).path, mode), 0)
            XCTAssertThrowsError(try fixture.acquire()) { XCTAssertEqual($0 as? JournalLeaseError, .unsafeMetadata) }
        }
    }

    func testACLGrantsCannotBypassUnixModes() throws {
        let fixture = try Fixture(), parent = fixture.root.appendingPathComponent("parent").path
        defer { _ = try? run("/bin/chmod", ["-N", parent]); _ = try? run("/bin/chmod", ["-N", fixture.path("journal.sqlite")]) }
        XCTAssertEqual(try run("/bin/chmod", ["+a", "everyone allow read", parent]), 0)
        let readableAncestor = try fixture.acquire()
        readableAncestor.close()
        XCTAssertEqual(try run("/bin/chmod", ["+a", "everyone allow write", parent]), 0)
        XCTAssertThrowsError(try fixture.acquire()) { XCTAssertEqual($0 as? JournalLeaseError, .unsafeMetadata) }
        XCTAssertEqual(try run("/bin/chmod", ["-N", parent]), 0)
        XCTAssertEqual(try run("/bin/chmod", ["+a", "everyone allow read", fixture.path("journal.sqlite")]), 0)
        XCTAssertThrowsError(try fixture.acquire()) { XCTAssertEqual($0 as? JournalLeaseError, .unsafeMetadata) }
    }

    func testReplacementRetiresTheLeaseEvenIfTheOriginalIsRestored() throws {
        for relative in ["parent", "parent/store", "parent/store/writer.lock", "parent/store/journal.sqlite"] {
            let fixture = try Fixture(), lease = try fixture.acquire()
            let path = fixture.root.appendingPathComponent(relative).path, old = path + ".original"
            XCTAssertEqual(rename(path, old), 0)
            if relative.hasSuffix("lock") || relative.hasSuffix("sqlite") { try Fixture.file(path) }
            else { XCTAssertEqual(mkdir(path, 0o700), 0) }
            XCTAssertThrowsError(try lease.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .identityChanged) }
            try FileManager.default.removeItem(atPath: path)
            XCTAssertEqual(rename(old, path), 0)
            XCTAssertThrowsError(try lease.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            lease.close()
        }
    }

    func testPermissionChangesRetireTheLeaseAndFailedAcquisitionReleasesItsLock() throws {
        let fixture = try Fixture(), lease = try fixture.acquire()
        XCTAssertEqual(chmod(fixture.path("journal.sqlite"), 0o644), 0)
        XCTAssertThrowsError(try lease.validate())
        XCTAssertEqual(chmod(fixture.path("journal.sqlite"), 0o600), 0)
        XCTAssertThrowsError(try lease.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        lease.close()
        XCTAssertEqual(chmod(fixture.path("journal.sqlite"), 0o644), 0)
        XCTAssertThrowsError(try fixture.acquire())
        XCTAssertEqual(chmod(fixture.path("journal.sqlite"), 0o600), 0)
        let retry = try fixture.acquire()
        try retry.validate(); retry.close()
    }

    func testACLChangeAfterAcquisitionInvalidatesTheLease() throws {
        let fixture = try Fixture(), lease = try fixture.acquire()
        defer { _ = try? run("/bin/chmod", ["-N", fixture.path("journal.sqlite")]); lease.close() }
        XCTAssertEqual(try run("/bin/chmod", ["+a", "everyone allow read", fixture.path("journal.sqlite")]), 0)
        XCTAssertThrowsError(try lease.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .unsafeMetadata) }
        XCTAssertEqual(try run("/bin/chmod", ["-N", fixture.path("journal.sqlite")]), 0)
        XCTAssertThrowsError(try lease.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
    }

    func testContentChangesAreNotConfusedWithFileReplacement() throws {
        let fixture = try Fixture(), lease = try fixture.acquire()
        let handle = try FileHandle(forWritingTo: URL(fileURLWithPath: fixture.path("journal.sqlite")))
        try handle.write(contentsOf: Data([1, 2, 3])); try handle.close()
        try lease.validate() // Database/checkpoint validation belongs to the journal owner.
        lease.close()
    }

    private final class Fixture {
        let root: URL
        var directory: String { root.appendingPathComponent("parent/store").path }
        init() throws {
            root = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent(UUID().uuidString)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            try FileManager.default.createDirectory(at: root.appendingPathComponent("parent"), withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            try Self.file(path("writer.lock")); try Self.file(path("journal.sqlite"))
        }
        deinit { try? FileManager.default.removeItem(at: root) }
        func path(_ name: String) -> String { directory + "/" + name }
        func acquire() throws -> ProtectedJournalLease {
            try ProtectedJournalLease(anchor: root.path, relativeDirectory: "parent/store", owner: getuid())
        }
        static func file(_ path: String) throws {
            let fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
            guard fd >= 0 else { throw JournalLeaseError.system(errno) }
            Darwin.close(fd)
        }
    }

    private func run(_ executable: String, _ arguments: [String]) throws -> Int32 {
        let process = Process(), finished = DispatchSemaphore(value: 0)
        process.executableURL = URL(fileURLWithPath: executable); process.arguments = arguments
        process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
        process.terminationHandler = { _ in finished.signal() }
        try process.run()
        if finished.wait(timeout: .now() + 10) == .timedOut {
            kill(process.processIdentifier, SIGKILL)
            _ = finished.wait(timeout: .now() + 5)
            XCTFail("Lease test child timed out")
            throw JournalLeaseError.busy
        }
        return process.terminationStatus
    }
}
