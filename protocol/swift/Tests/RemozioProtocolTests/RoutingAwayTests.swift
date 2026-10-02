import Foundation
import XCTest
@testable import RemozioProtocol

final class RoutingAwayTests: XCTestCase {
    private var limits: CBORLimits { get throws { try CBORLimits(maxBytes: 1024, maxDepth: 8, maxItems: 64) } }
    private struct Row: Decodable {
        let name: String; let hex: String; let signature: String?; let signingInput: String?
        let revision: String?; let issued: String?; let expires: String?
        let wrongPurposeSignature: String?; let wrongTypeSignature: String?; let wrongVersionSignature: String?
        let approvalSignature: String?; let gatewaySignature: String?
    }
    private struct Vectors: Decodable { let valid: [Row]; let invalid: [Row]; let publicKey: String; let otherPublicKey: String }
    private func vectors() throws -> Vectors {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        return try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: root.appendingPathComponent("vectors/routing-away-v1.json")))
    }
    private func hex(_ text: String) -> Data {
        Data(stride(from: 0, to: text.count, by: 2).map { offset in
            let start = text.index(text.startIndex, offsetBy: offset)
            return UInt8(text[start..<text.index(start, offsetBy: 2)], radix: 16)!
        })
    }
    private func verify(_ signature: Data, _ key: Data, _ payload: Data) throws -> Bool {
        try RoutingAwaySignature.verify(signature: signature, publicKey: key, wireVersion: 1,
            canonicalPayload: payload, payloadLimits: limits, inputLimits: limits)
    }

    func testSharedFieldsRoundTripAndRetainUnsignedBoundaries() throws {
        let rows = try vectors().valid; XCTAssertEqual(rows.count, 3)
        for row in rows {
            let bytes = hex(row.hex), value = try RoutingAwayControl.decode(bytes, limits: limits)
            XCTAssertEqual(try value.encode(limits: limits), bytes)
            XCTAssertEqual(value.expectedRevision, UInt64(row.revision!))
            XCTAssertEqual(value.issuedAtUnixMillis, UInt64(row.issued!)); XCTAssertEqual(value.expiresAtUnixMillis, UInt64(row.expires!))
            let fields = [value.macID, value.accountID, value.phoneID, value.enrollmentEpoch, value.operationID, value.challenge, value.keyID]
            for (i, field) in fields.enumerated() { XCTAssertEqual(field, Data(repeating: UInt8(i + 16), count: i == 5 ? 32 : 16)) }
        }
    }

    func testMalformedAndSignedForbiddenModesAreRejected() throws {
        let vectors = try vectors(); XCTAssertEqual(vectors.invalid.count, 87)
        for row in vectors.invalid {
            let bytes = hex(row.hex)
            XCTAssertThrowsError(try RoutingAwayControl.decode(bytes, limits: limits), row.name)
            XCTAssertThrowsError(try RoutingAwaySigningInput.make(wireVersion: 1, canonicalPayload: bytes, payloadLimits: limits, inputLimits: limits), row.name)
            if let signature = row.signature {
                XCTAssertTrue(P256Verification.verify(signature: hex(signature), publicKey: hex(vectors.publicKey), input: hex(row.signingInput!)))
                XCTAssertThrowsError(try verify(hex(signature), hex(vectors.publicKey), bytes), row.name)
            }
        }
    }

    func testSharedSignaturesSeparateKeysPurposesTypesVersionsAndDomains() throws {
        let vectors = try vectors()
        for row in vectors.valid {
            let bytes = hex(row.hex), signature = hex(row.signature!), key = hex(vectors.publicKey)
            XCTAssertEqual(try RoutingAwaySigningInput.make(wireVersion: 1, canonicalPayload: bytes, payloadLimits: limits, inputLimits: limits), hex(row.signingInput!))
            XCTAssertTrue(try verify(signature, key, bytes)); XCTAssertFalse(try verify(signature, hex(vectors.otherPublicKey), bytes))
            for wrong in [row.wrongPurposeSignature, row.wrongTypeSignature, row.wrongVersionSignature, row.approvalSignature, row.gatewaySignature] {
                XCTAssertFalse(try verify(hex(wrong!), key, bytes))
            }
            XCTAssertFalse(try verify(Data([0]), key, bytes)); XCTAssertFalse(try verify(signature, Data([0]), bytes))
        }
    }

    func testSignatureBindsEveryMutableControlField() throws {
        let vectors = try vectors(), row = vectors.valid[0]
        guard case let .map(original) = try DeterministicCBOR.decode(hex(row.hex), limits: limits) else { return XCTFail() }
        for key in UInt64(1)...10 {
            var changed = original
            switch changed[key] {
            case var .bytes(value): value[0] ^= 1; changed[key] = .bytes(value)
            case let .unsigned(value): changed[key] = .unsigned(value + 1)
            default: return XCTFail()
            }
            let bytes = try DeterministicCBOR.encode(.map(changed), limits: limits)
            XCTAssertFalse(try verify(hex(row.signature!), hex(vectors.publicKey), bytes))
        }
    }

    func testResourceAndVersionBounds() throws {
        let row = try vectors().valid[0], bytes = hex(row.hex)
        XCTAssertEqual(try RoutingAwayControl.decode(bytes, limits: CBORLimits(maxBytes: bytes.count, maxDepth: 8, maxItems: 64)).encode(limits: limits), bytes)
        for bounds in [try CBORLimits(maxBytes: bytes.count - 1, maxDepth: 8, maxItems: 64),
                       try CBORLimits(maxBytes: 1024, maxDepth: 1, maxItems: 2)] {
            XCTAssertThrowsError(try RoutingAwayControl.decode(bytes, limits: bounds))
            XCTAssertThrowsError(try RoutingAwaySigningInput.make(wireVersion: 1, canonicalPayload: bytes, payloadLimits: bounds, inputLimits: limits))
        }
        for version: UInt64 in [0, 2, .max] {
            XCTAssertThrowsError(try RoutingAwaySigningInput.make(wireVersion: version, canonicalPayload: bytes, payloadLimits: limits, inputLimits: limits))
        }
        let short = try CBORLimits(maxBytes: hex(row.signingInput!).count - 1, maxDepth: 8, maxItems: 64)
        XCTAssertThrowsError(try RoutingAwaySigningInput.make(wireVersion: 1, canonicalPayload: bytes, payloadLimits: limits, inputLimits: short))
    }

    func testValueSemanticsAndDescriptions() throws {
        let value = try RoutingAwayControl.decode(hex(vectors().valid[0].hex), limits: limits)
        var challenge = value.challenge; challenge[0] ^= 1
        XCTAssertNotEqual(value.challenge, challenge)
        XCTAssertEqual(String(reflecting: value), "RoutingAwayControl(redacted)")
        XCTAssertThrowsError(try RoutingAwayControl(macID: Data(), accountID: value.accountID, phoneID: value.phoneID,
            enrollmentEpoch: value.enrollmentEpoch, operationID: value.operationID, challenge: value.challenge, keyID: value.keyID,
            expectedRevision: 0, issuedAtUnixMillis: 0, expiresAtUnixMillis: 1))
    }
}
