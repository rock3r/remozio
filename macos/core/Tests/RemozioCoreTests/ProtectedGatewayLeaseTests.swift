import Darwin
import Foundation
@testable import RemozioCore
import XCTest

final class ProtectedGatewayLeaseTests: XCTestCase {
    func testExclusiveServiceStorageAndExplicitRelease() throws {
        let fixture = try Fixture(), lease = try fixture.acquire()
        XCTAssertEqual(lease.databasePath, fixture.path("gateway.sqlite"))
        try lease.validate()
        XCTAssertThrowsError(try fixture.acquire()) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
        lease.close(); lease.close()
        XCTAssertThrowsError(try lease.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .closed) }
        let next = try fixture.acquire()
        try next.validate(); next.close()
    }

    func testProductionRequiresConfiguredNonRootIdentityAndRootAncestors() throws {
        let fixture = try Fixture()
        for uid in [uid_t(0), geteuid() + 1] {
            XCTAssertThrowsError(try ProtectedGatewayLease.acquire(directoryPath: fixture.directory, serviceUID: uid)) {
                XCTAssertEqual($0 as? JournalLeaseError, .serviceIdentityRequired)
            }
        }
        // An ordinary user-owned directory tree cannot stand in for root-provisioned service storage.
        XCTAssertThrowsError(try ProtectedGatewayLease.acquire(directoryPath: fixture.directory, serviceUID: geteuid()))
        XCTAssertThrowsError(try ProtectedGatewayLease(anchor: fixture.root.path, relativeDirectory: "parent/store",
            serviceUID: geteuid(), ancestorUID: 0)) { XCTAssertEqual($0 as? JournalLeaseError, .unsafeMetadata) }
        XCTAssertThrowsError(try ProtectedJournalLease.acquire(directoryPath: fixture.directory)) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
    }

    func testMissingGatewayFileIsNotCreatedAndAuthorityFileIsNotUsed() throws {
        let fixture = try Fixture()
        XCTAssertEqual(rename(fixture.path("gateway.sqlite"), fixture.path("journal.sqlite")), 0)
        XCTAssertThrowsError(try fixture.acquire())
        XCTAssertFalse(FileManager.default.fileExists(atPath: fixture.path("gateway.sqlite")))
        let authorityFixture = try ProtectedJournalLease(anchor: fixture.root.path, relativeDirectory: "parent/store", owner: geteuid())
        authorityFixture.close()
        try Fixture.file(fixture.path("gateway.sqlite"))
        let retry = try fixture.acquire()
        try retry.validate(); retry.close()
    }

    func testCanonicalPathsOnlyAndNoImplicitProvisioning() throws {
        let fixture = try Fixture()
        for path in ["", "/parent/store", "parent//store", "parent/./store", "parent/../store", "parent/store/", "parent/st\0ore", String(repeating: "a", count: 256)] {
            XCTAssertThrowsError(try ProtectedGatewayLease(anchor: fixture.root.path, relativeDirectory: path,
                serviceUID: geteuid(), ancestorUID: geteuid())) { XCTAssertEqual($0 as? JournalLeaseError, .invalidPath) }
        }
        XCTAssertThrowsError(try ProtectedGatewayLease.acquire(directoryPath: "relative", serviceUID: geteuid())) {
            XCTAssertEqual($0 as? JournalLeaseError, .invalidPath)
        }
        XCTAssertThrowsError(try ProtectedGatewayLease(anchor: fixture.root.path, relativeDirectory: "missing",
            serviceUID: geteuid(), ancestorUID: geteuid()))
        XCTAssertFalse(FileManager.default.fileExists(atPath: fixture.root.appendingPathComponent("missing").path))
    }

    func testFileSubstitutionsAndExposedModesAreRejected() throws {
        for name in ["writer.lock", "gateway.sqlite"] {
            for kind in ["symlink", "hardlink", "fifo", "directory", "exposed"] {
                let fixture = try Fixture(), path = fixture.path(name), old = path + ".original"
                XCTAssertEqual(rename(path, old), 0)
                switch kind {
                case "symlink": XCTAssertEqual(symlink(old, path), 0)
                case "hardlink": XCTAssertEqual(link(old, path), 0)
                case "fifo": XCTAssertEqual(mkfifo(path, 0o600), 0)
                case "directory": XCTAssertEqual(mkdir(path, 0o700), 0)
                default: try Fixture.file(path); XCTAssertEqual(chmod(path, 0o644), 0)
                }
                XCTAssertThrowsError(try fixture.acquire(), "\(name): \(kind)")
            }
        }
        for (relative, mode) in [("parent", mode_t(0o770)), ("parent/store", mode_t(0o750))] {
            let fixture = try Fixture()
            XCTAssertEqual(chmod(fixture.root.appendingPathComponent(relative).path, mode), 0)
            XCTAssertThrowsError(try fixture.acquire()) { XCTAssertEqual($0 as? JournalLeaseError, .unsafeMetadata) }
        }
    }

    func testReplacementInvalidatesEvenAfterRestoration() throws {
        for relative in ["parent", "parent/store", "parent/store/writer.lock", "parent/store/gateway.sqlite"] {
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

    func testPermissionChangesRetireTheLeaseAndDeinitReleasesLock() throws {
        let fixture = try Fixture()
        do {
            let lease = try fixture.acquire()
            XCTAssertEqual(chmod(fixture.path("gateway.sqlite"), 0o644), 0)
            XCTAssertThrowsError(try lease.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .unsafeMetadata) }
            XCTAssertEqual(chmod(fixture.path("gateway.sqlite"), 0o600), 0)
            XCTAssertThrowsError(try lease.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        }
        let next = try fixture.acquire()
        try next.validate(); next.close()
    }

    func testPrivateACLGrantInvalidatesAndCannotBeHiddenByModes() throws {
        let fixture = try Fixture(), lease = try fixture.acquire(), path = fixture.path("gateway.sqlite")
        defer { _ = try? run(["-N", path]); lease.close() }
        XCTAssertEqual(try run(["+a", "everyone allow read", path]), 0)
        XCTAssertThrowsError(try lease.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .unsafeMetadata) }
        XCTAssertEqual(try run(["-N", path]), 0)
        XCTAssertThrowsError(try lease.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
    }

    private final class Fixture {
        let root: URL
        var directory: String { root.appendingPathComponent("parent/store").path }
        init() throws {
            guard geteuid() != 0 else { throw XCTSkip("Gateway fixtures require an unprivileged process") }
            root = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent(UUID().uuidString)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            try FileManager.default.createDirectory(at: root.appendingPathComponent("parent"), withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            try Self.file(path("writer.lock")); try Self.file(path("gateway.sqlite"))
        }
        deinit { try? FileManager.default.removeItem(at: root) }
        func path(_ name: String) -> String { directory + "/" + name }
        func acquire() throws -> ProtectedGatewayLease {
            try ProtectedGatewayLease(anchor: root.path, relativeDirectory: "parent/store", serviceUID: geteuid(), ancestorUID: geteuid())
        }
        static func file(_ path: String) throws {
            let fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
            guard fd >= 0 else { throw JournalLeaseError.system(errno) }
            Darwin.close(fd)
        }
    }
    private func run(_ arguments: [String]) throws -> Int32 {
        let process = Process(), finished = DispatchSemaphore(value: 0)
        process.executableURL = URL(fileURLWithPath: "/bin/chmod"); process.arguments = arguments
        process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
        process.terminationHandler = { _ in finished.signal() }
        try process.run()
        if finished.wait(timeout: .now() + 10) == .timedOut {
            kill(process.processIdentifier, SIGKILL)
            _ = finished.wait(timeout: .now() + 5)
            XCTFail("Gateway lease fixture command timed out")
            throw JournalLeaseError.busy
        }
        return process.terminationStatus
    }
}
