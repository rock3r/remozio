import Foundation
import XCTest
@testable import RemozioProtocol

final class IssuedRequestPayloadTests: XCTestCase {
    private var limits: CBORLimits { get throws { try CBORLimits(maxBytes: 2048, maxDepth: 8, maxItems: 128) } }
    private let kinds: [RequestKind] = [.command, .onePasswordAccess, .onePasswordUnlock, .littleSnitch]
    private let choices: [ActionChoice] = [.decline, .cancelTarget, .execute, .approveAccess, .unlockVault,
                                          .allowOnce, .denyOnce, .allowRule, .denyRule, .removeRule]
    private struct Row: Decodable {
        let name: String; let hex: String; let kind: Int?; let requestDigest: String?
        let capture: String?; let captureDigest: String?; let choices: [Int]?
    }
    private struct Vectors: Decodable { let valid: [Row]; let invalid: [Row] }
    private func vectors() throws -> Vectors {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        return try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: root.appendingPathComponent("vectors/issued-request-v1.json")))
    }
    private func capabilities(features: Set<UInt64> = [1, 2]) throws -> ContractCapabilities {
        ContractCapabilities(contracts: try Dictionary(uniqueKeysWithValues: kinds.map {
            (try RequestContract(requestKind: $0, wireVersion: 1, schemaVersion: 1), features)
        }))
    }
    private func decode(_ data: Data, features: Set<UInt64> = [1, 2]) throws -> IssuedRequestPayload {
        try IssuedRequestPayload.decode(data, bodyLimits: limits, captureLimits: limits, localCapabilities: capabilities(features: features))
    }

    func testSharedBodiesDigestsAndChoiceOrder() throws {
        let rows = try vectors().valid
        XCTAssertEqual(rows.count, 9)
        XCTAssertEqual(Set(kinds), Set(RequestKind.allCases))
        for row in rows {
            let bytes = hex(row.hex), payload = try decode(bytes)
            XCTAssertEqual(payload.contract.requestKind, kinds[row.kind!], row.name)
            XCTAssertEqual(payload.macID, Data(0..<16))
            XCTAssertEqual(payload.accountID, Data(16..<32))
            XCTAssertEqual(payload.requestID, Data(32..<48))
            XCTAssertEqual(payload.challenge, Data(0..<32))
            XCTAssertEqual(payload.canonicalCapture, hex(row.capture!))
            XCTAssertEqual(payload.captureDigest, hex(row.captureDigest!))
            XCTAssertEqual(payload.permittedActions.map(\.choice), row.choices!.map { choices[$0] })
            XCTAssertEqual(try payload.encode(limits: limits), bytes)
            XCTAssertEqual(try payload.requestDigest(bodyLimits: limits, signingLimits: limits), hex(row.requestDigest!))
        }
    }

    func testRejectsMalformedUnsupportedAndDigestMismatch() throws {
        let rows = try vectors().invalid
        XCTAssertEqual(rows.count, 58)
        for row in rows { XCTAssertThrowsError(try decode(hex(row.hex)), row.name) }
        let valid = hex(try vectors().valid[0].hex)
        XCTAssertThrowsError(try decode(valid, features: [1])) {
            XCTAssertEqual($0 as? IssuedRequestError, .unsupportedFeatures)
        }
        XCTAssertThrowsError(try IssuedRequestPayload.decode(valid, bodyLimits: limits, captureLimits: limits,
            localCapabilities: ContractCapabilities(contracts: [:]))) {
            XCTAssertEqual($0 as? IssuedRequestError, .unsupportedContract)
        }
    }

    func testBodyCaptureAndSigningBudgetsStayIndependent() throws {
        let bytes = hex(try vectors().valid[1].hex), payload = try decode(bytes)
        let smallBody = try CBORLimits(maxBytes: bytes.count - 1, maxDepth: 8, maxItems: 128)
        let smallCapture = try CBORLimits(maxBytes: payload.canonicalCapture.count - 1, maxDepth: 8, maxItems: 128)
        let smallSignature = try CBORLimits(maxBytes: bytes.count, maxDepth: 8, maxItems: 128)
        XCTAssertThrowsError(try payload.encode(limits: smallBody))
        XCTAssertThrowsError(try IssuedRequestPayload.decode(bytes, bodyLimits: smallBody, captureLimits: limits, localCapabilities: capabilities()))
        XCTAssertThrowsError(try IssuedRequestPayload.decode(bytes, bodyLimits: limits, captureLimits: smallCapture, localCapabilities: capabilities()))
        XCTAssertThrowsError(try payload.requestDigest(bodyLimits: limits, signingLimits: smallSignature))
        let exact = try CBORLimits(maxBytes: bytes.count, maxDepth: 8, maxItems: 128)
        XCTAssertEqual(try payload.encode(limits: exact), bytes)
    }

    func testConstructionPreservesSnapshotsAndValidatesActions() throws {
        var capture = Data([0xa0]), features: Set<UInt64> = [2, 1]
        var actions = [CapturedAction(choice: .execute, scope: .currentRequest), CapturedAction(choice: .decline, scope: .currentRequest)]
        let payload = try make(capture: capture, features: features, actions: actions)
        capture[0] = 0x80; features.remove(1); actions.reverse()
        XCTAssertEqual(payload.canonicalCapture, Data([0xa0]))
        XCTAssertEqual(payload.requiredFeatures, [1, 2])
        XCTAssertEqual(payload.permittedActions.first?.choice, .execute)
        XCTAssertThrowsError(try make(capture: capture, features: features, actions: actions))
        XCTAssertThrowsError(try make(actions: []))
        XCTAssertThrowsError(try make(actions: [actions[0], actions[0]]))
        XCTAssertThrowsError(try make(actions: [CapturedAction(choice: .allowOnce, scope: .currentRequest)]))
        XCTAssertThrowsError(try make(wire: 2))
    }

    func testCompleteDigestChangesWithRequestBindings() throws {
        let original = try vectors().valid[1]
        let bytes = hex(original.hex), baseline = hex(original.requestDigest!)
        guard case let .map(fields) = try DeterministicCBOR.decode(bytes, limits: limits) else { return XCTFail() }
        for key in UInt64(1)...4 {
            var altered = fields
            guard case var .bytes(value) = altered[key] else { return XCTFail() }
            value[value.startIndex] ^= 1; altered[key] = .bytes(value)
            XCTAssertNotEqual(try decode(DeterministicCBOR.encode(.map(altered), limits: limits)).requestDigest(bodyLimits: limits, signingLimits: limits), baseline)
        }
        for key in [UInt64(8), 9] {
            var altered = fields
            guard case let .unsigned(value) = altered[key] else { return XCTFail() }
            altered[key] = .unsigned(value + 1)
            XCTAssertNotEqual(try decode(DeterministicCBOR.encode(.map(altered), limits: limits)).requestDigest(bodyLimits: limits, signingLimits: limits), baseline)
        }
        var altered = fields
        altered[7] = .array([.unsigned(1)])
        XCTAssertNotEqual(try decode(DeterministicCBOR.encode(.map(altered), limits: limits)).requestDigest(bodyLimits: limits, signingLimits: limits), baseline)
        altered = fields
        guard case let .array(actions) = altered[12] else { return XCTFail() }
        altered[12] = .array(actions.reversed())
        XCTAssertNotEqual(try decode(DeterministicCBOR.encode(.map(altered), limits: limits)).requestDigest(bodyLimits: limits, signingLimits: limits), baseline)
    }

    private func make(capture: Data = Data([0xa0]), features: Set<UInt64> = [1, 2],
                      actions: [CapturedAction] = [CapturedAction(choice: .execute, scope: .currentRequest)], wire: UInt64 = 1) throws -> IssuedRequestPayload {
        let id = Data(repeating: 1, count: 16)
        return try IssuedRequestPayload(contract: RequestContract(requestKind: .command, wireVersion: wire, schemaVersion: 1),
            macID: id, accountID: id, requestID: id, challenge: Data(repeating: 2, count: 32), requiredFeatures: features,
            createdUnixMilliseconds: 1000, expiresUnixMilliseconds: 61000, canonicalCapture: capture,
            permittedActions: actions, bodyLimits: limits, captureLimits: limits)
    }
    private func hex(_ value: String) -> Data {
        Data(stride(from: 0, to: value.count, by: 2).map { offset in
            let start = value.index(value.startIndex, offsetBy: offset)
            return UInt8(value[start..<value.index(start, offsetBy: 2)], radix: 16)!
        })
    }
}
