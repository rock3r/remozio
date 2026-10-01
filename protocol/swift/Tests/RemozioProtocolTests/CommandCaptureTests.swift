import Foundation
import XCTest
@testable import RemozioProtocol

final class CommandCaptureTests: XCTestCase {
    private var limits: CBORLimits { get throws { try CBORLimits(maxBytes: 8192, maxDepth: 16, maxItems: 1024) } }
    private struct Row: Decodable {
        let name: String
        let hex: String
        let arguments: [String]?
        let environmentNames: [String]?
        let inputKind: UInt64?
        let signingStatus: UInt64?
        let ancestry: UInt64?
        let rationale: String?
    }
    private struct Vectors: Decodable { let valid: [Row]; let invalid: [Row] }
    private func vectors() throws -> Vectors {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        return try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: root.appendingPathComponent("vectors/command-capture-v1.json")))
    }
    private func hex(_ value: String) -> Data {
        var result = Data(), cursor = value.startIndex
        while cursor < value.endIndex {
            let end = value.index(cursor, offsetBy: 2)
            result.append(UInt8(value[cursor..<end], radix: 16)!)
            cursor = end
        }
        return result
    }
    func testSharedCapturesPreserveExactBytesAndProvenance() throws {
        let rows = try vectors().valid
        XCTAssertEqual(rows.count, 9)
        for row in rows {
            let bytes = hex(row.hex), capture = try CommandCapture(canonicalBytes: bytes, limits: limits)
            XCTAssertEqual(capture.canonicalBytes, bytes, row.name)
            XCTAssertEqual(capture.arguments, row.arguments!.map(hex), row.name)
            XCTAssertEqual(capture.environment.map(\.name), row.environmentNames!.map(hex), row.name)
            XCTAssertEqual(capture.input.kind.rawValue, row.inputKind, row.name)
            XCTAssertEqual(capture.requester.signing.status.rawValue, row.signingStatus, row.name)
            XCTAssertEqual(capture.ancestry.completeness.rawValue, row.ancestry, row.name)
            XCTAssertEqual(capture.unverifiedRationale, row.rationale, row.name)
        }
        let capture = try CommandCapture(canonicalBytes: hex(rows[0].hex), limits: limits)
        XCTAssertEqual(capture.executable.path, Data("/usr/bin/printf".utf8))
        XCTAssertEqual(capture.executable.identity.inode, 100)
        XCTAssertEqual(capture.executable.sha256, Data(0..<32))
        XCTAssertEqual(capture.directory.identity.inode, 101)
        XCTAssertEqual(capture.target.supplementaryGroups, [0, 80])
        XCTAssertEqual(capture.target.observedName, "root")
        XCTAssertEqual(capture.environment.last?.source, .requested)
        XCTAssertEqual(capture.environment.last?.value, Data([0xff, 0x0a]))
        XCTAssertEqual(capture.requester.pid, 4321)
        XCTAssertEqual(capture.requester.pidVersion, 7)
        XCTAssertEqual(capture.requester.realUID, 501)
        XCTAssertEqual(capture.requester.signing.team, "EXAMPLE")
        XCTAssertEqual(capture.ancestry.reason, .exited)
        XCTAssertEqual(capture.ancestry.entries[0].executablePath, Data("/bin/zsh".utf8))
        XCTAssertEqual(capture.submission.nonce, Data(repeating: 2, count: 32))
        XCTAssertEqual(capture.submission.callerBinding, Data(repeating: 3, count: 16))
    }
    func testSharedInvalidCapturesFail() throws {
        let rows = try vectors().invalid
        XCTAssertEqual(rows.count, 86)
        for row in rows { XCTAssertThrowsError(try CommandCapture(canonicalBytes: hex(row.hex), limits: limits), row.name) }
    }
    func testIndependentResourceBoundsAndValueSemantics() throws {
        var bytes = hex(try vectors().valid[0].hex)
        let capture = try CommandCapture(canonicalBytes: bytes, limits: limits)
        let original = bytes
        bytes[0] ^= 1
        XCTAssertEqual(capture.canonicalBytes, original)
        var arguments = capture.arguments
        arguments[0][0] ^= 1
        XCTAssertEqual(capture.arguments[0], Data("printf".utf8))
        for limit in [try CBORLimits(maxBytes: original.count - 1, maxDepth: 16, maxItems: 1024),
                      try CBORLimits(maxBytes: 8192, maxDepth: 1, maxItems: 1024),
                      try CBORLimits(maxBytes: 8192, maxDepth: 16, maxItems: 2)] {
            XCTAssertThrowsError(try CommandCapture(canonicalBytes: original, limits: limit))
        }
    }
    func testIssuedRequestPreservesCompleteCommandCapture() throws {
        let bytes = hex(try vectors().valid[0].hex)
        let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1)
        let issued = try IssuedRequestPayload(contract: contract, macID: Data(repeating: 1, count: 16),
            accountID: Data(repeating: 2, count: 16), requestID: Data(repeating: 3, count: 16), challenge: Data(repeating: 4, count: 32),
            requiredFeatures: [], createdUnixMilliseconds: 10, expiresUnixMilliseconds: 20, canonicalCapture: bytes,
            permittedActions: [.init(choice: .execute, scope: .currentRequest)], bodyLimits: limits, captureLimits: limits)
        let decoded = try IssuedRequestPayload.decode(issued.encode(limits: limits), bodyLimits: limits, captureLimits: limits,
            localCapabilities: ContractCapabilities(contracts: [contract: []]))
        let command = try CommandCapture(canonicalBytes: decoded.canonicalCapture, limits: limits)
        XCTAssertEqual(command.canonicalBytes, bytes)
        XCTAssertEqual(try decoded.requestDigest(bodyLimits: limits, signingLimits: limits), try issued.requestDigest(bodyLimits: limits, signingLimits: limits))
    }
}
