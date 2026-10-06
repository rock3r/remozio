import Foundation
import XCTest
@testable import RemozioProtocol

final class CommandSubmissionTests: XCTestCase {
    private var limits: CBORLimits { get throws { try CBORLimits(maxBytes: 8192, maxDepth: 16, maxItems: 1024) } }
    private func submission() throws -> CommandSubmission {
        try CommandSubmission(schemaVersion: 1, executablePath: Data("/synthetic/tool".utf8),
            arguments: [Data("different argv0".utf8), Data(), Data([0xff, 0x0a, 0x22])], directoryPath: Data("/synthetic/cwd".utf8),
            requestedTargetUID: UInt32.max,
            environmentAdditions: [.init(name: Data("A".utf8), value: Data()), .init(name: Data([0xff]), value: Data([0xfe]))],
            ioMode: .pty, disconnectBehavior: .continueRunning, unverifiedRationale: "Unverified\nreason",
            binding: .init(id: Data(repeating: 1, count: 16), nonce: Data(repeating: 2, count: 32), callerBinding: Data(repeating: 3, count: 16)),
            limits: limits)
    }
    func testRoundTripPreservesRawArgumentsEnvironmentAndBindings() throws {
        let value = try submission()
        let decoded = try CommandSubmission(canonicalBytes: value.canonicalBytes, limits: limits, expectedSchemaVersion: 1)
        XCTAssertEqual(decoded, value)
        XCTAssertEqual(decoded.arguments, [Data("different argv0".utf8), Data(), Data([0xff, 0x0a, 0x22])])
        XCTAssertEqual(decoded.environmentAdditions.last?.value, Data([0xfe]))
        XCTAssertEqual(decoded.requestedTargetUID, UInt32.max)
        XCTAssertEqual(decoded.ioMode, .pty)
        XCTAssertEqual(decoded.disconnectBehavior, .continueRunning)
        XCTAssertEqual(decoded.unverifiedRationale, "Unverified\nreason")
        var mutable = value.arguments
        mutable[0][0] ^= 1
        XCTAssertNotEqual(mutable[0], decoded.arguments[0])
        XCTAssertThrowsError(try CommandSubmission(canonicalBytes: value.canonicalBytes, limits: limits, expectedSchemaVersion: 2)) {
            XCTAssertEqual($0 as? CommandCaptureError, .version)
        }
    }
    func testUnknownFieldsAndInvalidInvocationClaimsFail() throws {
        guard case let .map(original) = try DeterministicCBOR.decode(submission().canonicalBytes, limits: limits) else {
            return XCTFail("Expected the submission map")
        }
        let cases: [(UInt64, CBORValue)] = [
            (0, .unsigned(2)), (1, .bytes(Data("relative".utf8))), (1, .bytes(Data([0x2f, 0]))),
            (2, .array([])), (2, .array([.bytes(Data([0]))])), (3, .bytes(Data())),
            (4, .unsigned(UInt64(UInt32.max) + 1)), (6, .unsigned(2)), (7, .unsigned(2)),
            (8, .bytes(Data())), (10, .text("forged requester")),
            (5, .array([.map([0: .bytes(Data()), 1: .bytes(Data())])])),
            (5, .array([.map([0: .bytes(Data("A=B".utf8)), 1: .bytes(Data())])])),
            (5, .array([.map([0: .bytes(Data("A".utf8)), 1: .bytes(Data([0]))])])),
            (5, .array([.map([0: .bytes(Data("A".utf8)), 1: .bytes(Data()), 2: .unsigned(0)])])),
            (5, .array([.map([0: .bytes(Data("B".utf8)), 1: .bytes(Data())]), .map([0: .bytes(Data("A".utf8)), 1: .bytes(Data())])])),
            (5, .array([.map([0: .bytes(Data("A".utf8)), 1: .bytes(Data())]), .map([0: .bytes(Data("A".utf8)), 1: .bytes(Data())])]))
        ]
        for (key, invalid) in cases {
            var fields = original; fields[key] = invalid
            let bytes = try DeterministicCBOR.encode(.map(fields), limits: limits)
            XCTAssertThrowsError(try CommandSubmission(canonicalBytes: bytes, limits: limits, expectedSchemaVersion: 1), "field \(key)")
        }
        for key: UInt64 in [0, 1, 2] {
            guard case var .map(binding) = original[9] else { return XCTFail("Expected the binding") }
            binding[key] = .bytes(Data())
            var fields = original; fields[9] = .map(binding)
            XCTAssertThrowsError(try CommandSubmission(canonicalBytes: DeterministicCBOR.encode(.map(fields), limits: limits),
                limits: limits, expectedSchemaVersion: 1))
        }
        var missing = original; missing.removeValue(forKey: 8)
        XCTAssertThrowsError(try CommandSubmission(canonicalBytes: DeterministicCBOR.encode(.map(missing), limits: limits),
            limits: limits, expectedSchemaVersion: 1))
    }
    func testSubmissionResourceLimitsDoNotTruncate() throws {
        let bytes = try submission().canonicalBytes
        for limit in [try CBORLimits(maxBytes: bytes.count - 1, maxDepth: 16, maxItems: 1024),
                      try CBORLimits(maxBytes: 8192, maxDepth: 1, maxItems: 1024),
                      try CBORLimits(maxBytes: 8192, maxDepth: 16, maxItems: 2)] {
            XCTAssertThrowsError(try CommandSubmission(canonicalBytes: bytes, limits: limit, expectedSchemaVersion: 1))
        }
    }
}
