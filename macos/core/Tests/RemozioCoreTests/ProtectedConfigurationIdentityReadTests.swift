import Darwin
import Foundation
import XCTest
@testable import RemozioCore

/// Same-owner files exercise the protected reader and inode comparison. Installed Root custody remains untested.
final class ProtectedConfigurationIdentityReadTests: XCTestCase {
    func testIdenticalReplacementHasDifferentIdentityAndIsNotAdopted() throws {
        let root = URL(fileURLWithPath: "/private/tmp/remozio-identity-read-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("record"), old = root.appendingPathComponent("record.old"), bytes = Data([1, 2, 3])
        try bytes.write(to: file); XCTAssertEqual(chmod(file.path, 0o600), 0)
        let first = try ProtectedServiceConfiguration.readIdentity(anchor: root.path, relativePath: "record", owner: getuid())
        XCTAssertNoThrow(try first.requireSame(as: ProtectedServiceConfiguration.readIdentity(anchor: root.path, relativePath: "record", owner: getuid())))
        XCTAssertEqual(rename(file.path, old.path), 0); try bytes.write(to: file); XCTAssertEqual(chmod(file.path, 0o600), 0)
        let second = try ProtectedServiceConfiguration.readIdentity(anchor: root.path, relativePath: "record", owner: getuid())
        XCTAssertEqual(first.bytes, second.bytes); XCTAssertNotEqual(first.identity, second.identity)
        XCTAssertThrowsError(try second.requireSame(as: first)) { XCTAssertEqual($0 as? JournalLeaseError, .identityChanged) }
        XCTAssertTrue(FileManager.default.fileExists(atPath: old.path)); XCTAssertEqual(try Data(contentsOf: file), bytes)
    }
    func testIdentityReaderKeepsRootMetadataAndMissingLeafRefusals() throws {
        XCTAssertNotEqual(getuid(), 0)
        XCTAssertThrowsError(try ProtectedServiceConfiguration.readIdentity(path: "relative")) { XCTAssertEqual($0 as? JournalLeaseError, .rootRequired) }
        let root = URL(fileURLWithPath: "/private/tmp/remozio-identity-metadata-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        XCTAssertThrowsError(try ProtectedServiceConfiguration.readIdentity(anchor: root.path, relativePath: "absent", owner: getuid())) {
            XCTAssertEqual($0 as? JournalLeaseError, .system(ENOENT))
        }
        let file = root.appendingPathComponent("record"); try Data([1]).write(to: file); XCTAssertEqual(chmod(file.path, 0o640), 0)
        XCTAssertThrowsError(try ProtectedServiceConfiguration.readIdentity(anchor: root.path, relativePath: "record", owner: getuid())) {
            XCTAssertEqual($0 as? JournalLeaseError, .unsafeMetadata)
        }
    }
}
