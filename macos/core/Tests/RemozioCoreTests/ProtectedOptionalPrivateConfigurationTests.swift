import Darwin
import Foundation
import XCTest
@testable import RemozioCore

/// Owned paths exercise the checked private reader. They do not prove Root or service ownership on installed paths.
final class ProtectedOptionalPrivateConfigurationTests: XCTestCase {
    private final class Fixture {
        let root = URL(fileURLWithPath: "/private/tmp/remozio-private-optional-" + UUID().uuidString)
        var directory: String { root.path + "/config" }
        var file: String { directory + "/value.cbor" }
        init(_ bytes: Data = Data([1, 2, 3])) throws {
            try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            try bytes.write(to: URL(fileURLWithPath: file)); guard chmod(file, 0o600) == 0 else { throw JournalLeaseError.system(errno) }
        }
        deinit { try? FileManager.default.removeItem(at: root) }
        func read(_ path: String = "config/value.cbor", owner: uid_t = getuid(), ancestor: uid_t? = nil) throws -> Data? {
            try ProtectedServiceConfiguration.readOptionalPrivate(anchor: root.path, relativePath: path, owner: owner, ancestorOwner: ancestor)
        }
    }
    private func acl(_ arguments: [String], path: String) throws {
        let process = Process(); process.executableURL = URL(fileURLWithPath: "/bin/chmod"); process.arguments = arguments + [path]
        try process.run(); process.waitUntilExit(); XCTAssertEqual(process.terminationStatus, 0)
    }
    func testNativePrivateKindsRequireRootBeforePathAndOwnerValidation() throws {
        XCTAssertNotEqual(getuid(), 0)
        for kind in [ProtectedServiceConfiguration.OptionalPrivateOwner.root, .service(getuid()), .service(0), .service(UInt32.max)] {
            for path in ["relative", "/does-not-exist/private.cbor"] {
                XCTAssertThrowsError(try ProtectedServiceConfiguration.readOptionalPrivate(path: path, kind: kind)) {
                    XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
                }
            }
        }
    }
    func testMissingLeafDoesNotHideMissingChangedOrSymlinkedAncestors() throws {
        let f = try Fixture(); XCTAssertEqual(try f.read(), Data([1, 2, 3]))
        XCTAssertEqual(unlink(f.file), 0); XCTAssertNil(try f.read())
        XCTAssertThrowsError(try f.read("missing/value.cbor")) { XCTAssertEqual($0 as? JournalLeaseError, .system(ENOENT)) }
        XCTAssertEqual(chmod(f.directory, 0o770), 0)
        XCTAssertThrowsError(try f.read()) { XCTAssertEqual($0 as? JournalLeaseError, .unsafeMetadata) }
        XCTAssertEqual(chmod(f.directory, 0o700), 0)
        try acl(["+a", "everyone allow write"], path: f.directory)
        XCTAssertThrowsError(try f.read()) { XCTAssertEqual($0 as? JournalLeaseError, .unsafeMetadata) }
        try acl(["-N"], path: f.directory)
        XCTAssertEqual(rename(f.directory, f.directory + ".old"), 0)
        XCTAssertEqual(symlink(f.directory + ".old", f.directory), 0); XCTAssertThrowsError(try f.read())
    }
    func testPrivateOptionalKeepsOwnershipACLLinksModesAndTheOriginalByteBound() throws {
        let f = try Fixture()
        XCTAssertThrowsError(try f.read(owner: getuid() + 1, ancestor: getuid()))
        XCTAssertThrowsError(try f.read(owner: getuid(), ancestor: getuid() + 1))
        XCTAssertEqual(chmod(f.file, 0o640), 0); XCTAssertThrowsError(try f.read()); XCTAssertEqual(chmod(f.file, 0o600), 0)
        try acl(["+a", "everyone allow read"], path: f.file)
        XCTAssertThrowsError(try f.read()) { XCTAssertEqual($0 as? JournalLeaseError, .unsafeMetadata) }; try acl(["-N"], path: f.file)
        for kind in ["symlink", "hardlink", "fifo", "directory"] {
            let other = try Fixture(), original = other.file + ".old"; XCTAssertEqual(rename(other.file, original), 0)
            switch kind {
            case "symlink": XCTAssertEqual(symlink(original, other.file), 0)
            case "hardlink": XCTAssertEqual(link(original, other.file), 0)
            case "fifo": XCTAssertEqual(mkfifo(other.file, 0o600), 0)
            default: XCTAssertEqual(mkdir(other.file, 0o700), 0)
            }
            XCTAssertThrowsError(try other.read(), kind)
        }
        for count in [0, ProtectedServiceConfiguration.maximumBytes + 1] {
            let other = try Fixture(Data(count: count)); XCTAssertThrowsError(try other.read())
        }
        let maximum = try Fixture(Data(count: ProtectedServiceConfiguration.maximumBytes))
        XCTAssertEqual(try maximum.read()?.count, 65_536); XCTAssertEqual(ProtectedServiceConfiguration.maximumBytes, 65_536)
        for path in ["", "/config/value.cbor", "config/../value.cbor", "config//value.cbor", "config/value.cbor/", "config/a\0"] {
            XCTAssertThrowsError(try f.read(path))
        }
    }
}
