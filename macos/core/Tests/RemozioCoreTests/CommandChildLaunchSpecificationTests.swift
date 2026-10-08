import Darwin
import Foundation
import RemozioMach
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class CommandChildLaunchSpecificationTests: XCTestCase {
    private func capture() throws -> CommandCapture {
        try .init(schemaVersion: 1,
            executable: .init(path: Data("/usr/bin/true".utf8), identity: .init(device: 1, inode: 2), sha256: Data(count: 32)),
            arguments: [Data([0xff]), Data(), Data([0xfe, 0x0a])],
            directory: .init(path: Data("/tmp".utf8), identity: .init(device: 1, inode: 3)),
            target: .init(uid: 1234, gid: 5678, supplementaryGroups: [5678, 42], observedName: nil),
            environment: [.init(name: Data("EMPTY".utf8), value: Data(), source: .requested),
                .init(name: Data("RAW".utf8), value: Data([0xff, 0x3d, 0x0a]), source: .requested)],
            input: .init(kind: .pipe, streamBinding: Data(count: 16), observedPath: nil, identity: nil),
            ioMode: .pipes, disconnectBehavior: .terminate,
            requester: .init(executablePath: Data("/fixture/caller".utf8), realUID: 501, effectiveUID: 501, pid: 10, pidVersion: 11,
                signing: .init(status: .unsigned, identifier: nil, team: nil, cdHash: nil), sessionID: nil, ttyPath: nil),
            ancestry: .init(completeness: .unavailable, entries: [], reason: .unsupported), unverifiedRationale: nil,
            submission: .init(id: Data(count: 16), nonce: Data(count: 32), callerBinding: Data(count: 16)),
            limits: .init(maxBytes: 8192, maxDepth: 16, maxItems: 1024))
    }
    private func frame() throws -> Data {
        try CommandChildLaunchSpecification(capture: capture(), preparationMilliseconds: 1000, fileCreationMask: 0o027).canonicalBytes
    }
    private func decode(_ bytes: Data, inspect: (remozio_child_spec_t) throws -> Void = { _ in }) throws -> Int32 {
        var spec = remozio_child_spec_t()
        defer { remozio_child_spec_close(&spec) }
        let result = bytes.withUnsafeBytes { remozio_child_spec_decode($0.baseAddress, $0.count, &spec) }
        if result == 0 { try inspect(spec) }
        else { XCTAssertNil(spec.storage); XCTAssertNil(spec.arguments); XCTAssertNil(spec.environment); XCTAssertNil(spec.groups) }
        return result
    }
    private func word(_ value: UInt32, offset: Int, bytes: inout Data) {
        var big = value.bigEndian
        withUnsafeBytes(of: &big) { bytes.replaceSubrange(offset..<offset + 4, with: $0) }
    }
    private func raw(_ pointer: UnsafePointer<CChar>?) throws -> Data {
        let pointer = try XCTUnwrap(pointer)
        return Data(bytes: pointer, count: strlen(pointer))
    }
    func testNativeDecoderRetainsEveryRawInvocationAndCredentialField() throws {
        let expected = try capture()
        XCTAssertEqual(try decode(frame()) { spec in
            XCTAssertEqual(spec.uid, expected.target.uid); XCTAssertEqual(spec.gid, expected.target.gid)
            XCTAssertEqual(spec.preparation_milliseconds, 1000); XCTAssertEqual(spec.file_creation_mask, 0o027)
            XCTAssertEqual(spec.group_count, 2); XCTAssertEqual(Array(UnsafeBufferPointer(start: spec.groups, count: 2)), [5678, 42])
            XCTAssertEqual(try raw(spec.executable), expected.executable.path)
            XCTAssertEqual(spec.argument_count, 3); XCTAssertEqual(spec.environment_count, 2)
            for index in 0..<3 { XCTAssertEqual(try raw(spec.arguments[index]), expected.arguments[index]) }
            XCTAssertNil(spec.arguments[3]); XCTAssertNil(spec.environment[2])
            XCTAssertEqual(try raw(spec.environment[0]), Data("EMPTY=".utf8))
            XCTAssertEqual(try raw(spec.environment[1]), Data("RAW=".utf8) + Data([0xff, 0x3d, 0x0a]))
        }, 0)
    }
    func testEveryTruncationAndTrailingByteIsRejectedWithoutOwnedAllocations() throws {
        let original = try frame()
        for count in 0..<original.count { XCTAssertEqual(try decode(original.prefix(count)), EINVAL) }
        XCTAssertEqual(try decode(original + Data([0])), EINVAL)
        var trailing = original + Data([0]); word(UInt32(trailing.count - 40), offset: 4, bytes: &trailing)
        XCTAssertEqual(try decode(trailing), EINVAL)
    }
    func testInvalidVersionsCountsCredentialsTimeoutAndMaskAreRejected() throws {
        let original = try frame()
        for (offset, values): (Int, [UInt32]) in [(0, [0, 0x524d4332]), (4, [0, UInt32.max]), (8, [UInt32.max]),
            (12, [UInt32.max]), (16, [17, UInt32.max]), (20, [0, 262145, UInt32.max]),
            (24, [262145, UInt32.max]), (28, [0, 99, 60001, UInt32.max]), (32, [0o1000, UInt32.max]), (36, [2, UInt32.max]), (40, [UInt32.max])] {
            for value in values { var changed = original; word(value, offset: offset, bytes: &changed); XCTAssertEqual(try decode(changed), EINVAL) }
        }
    }
    func testStringOverflowNulAndRelativeExecutableFailAfterAllocationCleanup() throws {
        var oversized = try frame(); word(UInt32.max, offset: 48, bytes: &oversized)
        XCTAssertEqual(try decode(oversized), EINVAL)
        var nul = try frame(); nul[53] = 0; XCTAssertEqual(try decode(nul), EINVAL)
        var relative = try frame(); relative[52] = 0x2e; XCTAssertEqual(try decode(relative), EINVAL)
        var environment = try frame()
        let value = try XCTUnwrap(environment.range(of: Data("EMPTY=".utf8)))
        environment[value.lowerBound + 5] = 0x2d
        XCTAssertEqual(try decode(environment), EINVAL)
    }
    func testDuplicateOrUnsortedEnvironmentNamesAreRejected() throws {
        var original = try frame()
        let name = try XCTUnwrap(original.range(of: Data("RAW=".utf8)))
        original.replaceSubrange(name.lowerBound..<name.lowerBound + 3, with: Data("AAA".utf8))
        XCTAssertEqual(try decode(original), EINVAL)
        var duplicate = try frame()
        let first = try XCTUnwrap(duplicate.range(of: Data("EMPTY=".utf8)))
        duplicate.replaceSubrange(first.lowerBound..<first.lowerBound + 5, with: Data("RAW".utf8))
        word(4, offset: first.lowerBound - 4, bytes: &duplicate)
        word(UInt32(duplicate.count - 40), offset: 4, bytes: &duplicate)
        XCTAssertEqual(try decode(duplicate), EINVAL)
    }
    func testOversizedFrameIsRejectedBeforeAllocatingDecodedStorage() throws {
        XCTAssertEqual(try decode(Data(count: CommandChildLaunchSpecification.maximumBytes + 1)), EINVAL)
    }
    func testDecodedRawStringsOwnTheirBytesAndCloseIsIdempotent() throws {
        var bytes = try frame(), spec = remozio_child_spec_t()
        XCTAssertEqual(bytes.withUnsafeBytes { remozio_child_spec_decode($0.baseAddress, $0.count, &spec) }, 0)
        defer { remozio_child_spec_close(&spec) }
        bytes.resetBytes(in: 0..<bytes.count)
        XCTAssertEqual(try raw(spec.arguments[0]), Data([0xff]))
        XCTAssertEqual(try raw(spec.environment[1]), Data("RAW=".utf8) + Data([0xff, 0x3d, 0x0a]))
        remozio_child_spec_close(&spec); remozio_child_spec_close(&spec)
        XCTAssertNil(spec.storage); XCTAssertNil(spec.arguments); XCTAssertNil(spec.environment)
    }
    func testDarwinGroupRepresentationUsesOnlyTheApprovedPrimaryAndSupplementaryIDs() throws {
        for (input, expected): ([UInt32], [UInt32]) in [([], [5678]), ([0, 42], [5678, 0, 42]),
            ([42, 5678, 42, 0], [5678, 42, 0])] {
            var spec = remozio_child_spec_t(), groups = [UInt32](repeating: 0, count: 16), count: UInt32 = 0
            spec.gid = 5678; spec.group_count = UInt32(input.count)
            var values = input
            let result = values.withUnsafeMutableBufferPointer { source in
                spec.groups = source.baseAddress
                return remozio_child_spec_groups(&spec, &groups, &count)
            }
            XCTAssertEqual(result, 0); XCTAssertEqual(Array(groups.prefix(Int(count))), expected)
        }
    }
    func testGroupUnionCannotOverflowTheDarwinLimit() throws {
        var spec = remozio_child_spec_t(), groups = [UInt32](repeating: 0, count: 16), count: UInt32 = 0
        spec.gid = 5678; spec.group_count = 16
        var input = Array(UInt32(1)...16)
        XCTAssertEqual(input.withUnsafeMutableBufferPointer { values in
            spec.groups = values.baseAddress
            return remozio_child_spec_groups(&spec, &groups, &count)
        }, EINVAL)
    }
    func testEncoderRejectsUnsupportedPreparationAndMaskWithoutChangingCapture() throws {
        let original = try capture(), bytes = original.canonicalBytes
        for budget: UInt32 in [0, 99, 60001, UInt32.max] {
            XCTAssertThrowsError(try CommandChildLaunchSpecification(capture: original, preparationMilliseconds: budget, fileCreationMask: 0o022))
        }
        XCTAssertThrowsError(try CommandChildLaunchSpecification(capture: original, preparationMilliseconds: 1000, fileCreationMask: 0o1000))
        XCTAssertEqual(original.canonicalBytes, bytes)
    }
}
