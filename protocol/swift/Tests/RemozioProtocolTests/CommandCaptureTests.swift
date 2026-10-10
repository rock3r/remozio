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
        let ptyMask: UInt32?
        let streamKinds: [UInt64]?
        let streamAccess: [UInt64]?
        let streamFlags: [UInt64]?
        let terminalSession: UInt32?
    }
    private struct Vectors: Decodable { let valid: [Row]; let invalid: [Row] }
    private func vectors(_ version: Int = 1) throws -> Vectors {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        return try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: root.appendingPathComponent("vectors/command-capture-v\(version).json")))
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
    private func produce(_ capture: CommandCapture, schema: UInt64? = nil, arguments: [Data]? = nil,
                         input: CapturedCommandInput? = nil, limits: CBORLimits? = nil) throws -> CommandCapture {
        try CommandCapture(schemaVersion: schema ?? capture.schemaVersion, executable: capture.executable,
            arguments: arguments ?? capture.arguments, directory: capture.directory, target: capture.target,
            environment: capture.environment, input: input ?? capture.input, ioMode: capture.ioMode,
            disconnectBehavior: capture.disconnectBehavior, requester: capture.requester, ancestry: capture.ancestry,
            unverifiedRationale: capture.unverifiedRationale, submission: capture.submission, stdioLayout: capture.stdioLayout, limits: limits ?? self.limits)
    }

    func testProducerReencodesEverySharedVectorExactly() throws {
        for version in [1, 2, 3] {
            for row in try vectors(version).valid {
                let decoded = try CommandCapture(canonicalBytes: hex(row.hex), limits: limits, expectedSchemaVersion: UInt64(version))
                XCTAssertEqual(try produce(decoded), decoded, row.name)
                XCTAssertEqual(try produce(decoded).canonicalBytes, hex(row.hex), row.name)
            }
        }
    }

    func testProducerRejectsInvalidTypedContentsAndResourceOverflow() throws {
        let capture = try CommandCapture(canonicalBytes: hex(vectors().valid[0].hex), limits: limits)
        XCTAssertThrowsError(try produce(capture, arguments: []))
        XCTAssertThrowsError(try produce(capture, arguments: [Data([0])]))
        XCTAssertThrowsError(try produce(capture, schema: 4)) { XCTAssertEqual($0 as? CommandCaptureError, .version) }
        let socket = CapturedCommandInput(kind: .socket, streamBinding: Data(repeating: 7, count: 16), observedPath: nil, identity: nil)
        XCTAssertThrowsError(try produce(capture, schema: 1, input: socket))
        XCTAssertEqual(try produce(capture, schema: 2, input: socket).input, socket)
        let badNull = CapturedCommandInput(kind: .null, streamBinding: Data(repeating: 7, count: 16), observedPath: nil, identity: nil)
        XCTAssertThrowsError(try produce(capture, input: badNull))
        let small = try CBORLimits(maxBytes: capture.canonicalBytes.count - 1, maxDepth: 16, maxItems: 1024)
        XCTAssertThrowsError(try produce(capture, limits: small)) { XCTAssertEqual($0 as? CBORError, .limitExceeded(.bytes)) }
    }

    func testSharedInvalidCapturesFail() throws {
        let rows = try vectors().invalid
        XCTAssertEqual(rows.count, 86)
        for row in rows { XCTAssertThrowsError(try CommandCapture(canonicalBytes: hex(row.hex), limits: limits), row.name) }
    }
    func testSchemaTwoAndExplicitVersionBinding() throws {
        let rows = try vectors(2)
        XCTAssertEqual(rows.valid.count, 13)
        for row in rows.valid {
            let bytes = hex(row.hex)
            let capture = try CommandCapture(canonicalBytes: bytes, limits: limits, expectedSchemaVersion: 2)
            XCTAssertEqual(capture.schemaVersion, 2)
            XCTAssertEqual(capture.input.kind.rawValue, row.inputKind, row.name)
            XCTAssertEqual(capture.canonicalBytes, bytes)
            XCTAssertThrowsError(try CommandCapture(canonicalBytes: bytes, limits: limits), row.name)
        }
        for row in rows.invalid {
            XCTAssertThrowsError(try CommandCapture(canonicalBytes: hex(row.hex), limits: limits, expectedSchemaVersion: row.name.hasPrefix("schema1-") ? 1 : 2), row.name)
        }
        let oldBytes = hex(try vectors().valid[0].hex)
        XCTAssertThrowsError(try CommandCapture(canonicalBytes: oldBytes, limits: limits, expectedSchemaVersion: 2))
        XCTAssertThrowsError(try CommandCapture(canonicalBytes: oldBytes, limits: limits, expectedSchemaVersion: 3))
        XCTAssertEqual(CommandCapture.supportedSchemaVersions, [1, 2, 3])
    }

    func testSchemaThreeStreamLayoutAndMalformedBindings() throws {
        let rows = try vectors(3)
        XCTAssertEqual(rows.valid.count, 39)
        XCTAssertEqual(rows.invalid.count, 75)
        for row in rows.valid {
            let bytes = hex(row.hex)
            let capture = try CommandCapture(canonicalBytes: bytes, limits: limits, expectedSchemaVersion: 3)
            let layout = try XCTUnwrap(capture.stdioLayout)
            XCTAssertEqual(capture.canonicalBytes, bytes, row.name)
            XCTAssertEqual(layout.input.source, capture.input, row.name)
            XCTAssertEqual(layout.ptyMask, row.ptyMask, row.name)
            let streams = [layout.input, layout.output, layout.error]
            XCTAssertEqual(streams.map { $0.source.kind.rawValue }, row.streamKinds, row.name)
            XCTAssertEqual(streams.map { $0.access.rawValue }, row.streamAccess, row.name)
            XCTAssertEqual(streams.map { $0.flags.rawValue }, row.streamFlags, row.name)
            XCTAssertEqual(layout.terminal?.sessionID, row.terminalSession, row.name)
            XCTAssertEqual(capture.arguments, row.arguments!.map(hex), row.name)
            XCTAssertEqual(capture.environment.map(\.name), row.environmentNames!.map(hex), row.name)
            XCTAssertThrowsError(try CommandCapture(canonicalBytes: bytes, limits: limits), row.name)
            XCTAssertThrowsError(try CommandCapture(canonicalBytes: bytes, limits: limits, expectedSchemaVersion: 2), row.name)
        }
        for row in rows.invalid {
            XCTAssertThrowsError(try CommandCapture(canonicalBytes: hex(row.hex), limits: limits, expectedSchemaVersion: 3), row.name)
        }
        let old = try CommandCapture(canonicalBytes: hex(vectors().valid[0].hex), limits: limits)
        XCTAssertNil(old.stdioLayout)
        XCTAssertThrowsError(try produce(old, schema: 3)) { XCTAssertEqual($0 as? CommandCaptureError, .fields) }
        let new = try CommandCapture(canonicalBytes: hex(rows.valid[0].hex), limits: limits, expectedSchemaVersion: 3)
        XCTAssertThrowsError(try produce(new, schema: 2)) { XCTAssertEqual($0 as? CommandCaptureError, .fields) }
    }

    func testApprovedDigestBindsStreamRoutingAndFlags() throws {
        let rows = try vectors(3).valid
        let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 3)
        func issued(_ name: String) throws -> IssuedRequestPayload {
            let row = try XCTUnwrap(rows.first { $0.name == name })
            return try IssuedRequestPayload(contract: contract, macID: Data(repeating: 1, count: 16),
                accountID: Data(repeating: 2, count: 16), requestID: Data(repeating: 3, count: 16), challenge: Data(repeating: 4, count: 32),
                requiredFeatures: [], createdUnixMilliseconds: 10, expiresUnixMilliseconds: 20, canonicalCapture: hex(row.hex),
                permittedActions: [.init(choice: .execute, scope: .currentRequest)], bodyLimits: limits, captureLimits: limits)
        }
        let first = try issued("schema3-terminal-mask-0")
        let decoded = try IssuedRequestPayload.decode(first.encode(limits: limits), bodyLimits: limits, captureLimits: limits,
            localCapabilities: ContractCapabilities(contracts: [contract: []]))
        XCTAssertEqual(decoded.canonicalCapture, first.canonicalCapture)
        XCTAssertEqual(try CommandCapture(canonicalBytes: decoded.canonicalCapture, limits: limits,
            expectedSchemaVersion: decoded.contract.schemaVersion).stdioLayout?.ptyMask, 0)
        let digest = try first.requestDigest(bodyLimits: limits, signingLimits: limits)
        XCTAssertNotEqual(digest, try issued("schema3-terminal-mask-1").requestDigest(bodyLimits: limits, signingLimits: limits))
        XCTAssertNotEqual(try issued("schema3-semantic-flags-0").requestDigest(bodyLimits: limits, signingLimits: limits),
            try issued("schema3-semantic-flags-1").requestDigest(bodyLimits: limits, signingLimits: limits))
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
