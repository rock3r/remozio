import Foundation
import XCTest
@testable import RemozioProtocol

final class GatewayRecipientTests: XCTestCase {
    private var limits: CBORLimits { get throws { try CBORLimits(maxBytes: 2048, maxDepth: 8, maxItems: 128) } }
    private struct Row: Decodable { let name: String; let kind: UInt64; let hex: String }
    private struct Valid: Decodable {
        let name: String; let kind: UInt64; let hex: String; let revision: String; let issued: String; let expires: String
        let signingInput: String; let signature: String; let wrongPurposeSignature: String; let wrongTypeSignature: String
        let probeSignature: String; let approvalSignature: String
    }
    private struct Vectors: Decodable { let valid: [Valid]; let invalid: [Row]; let publicKey: String; let otherPublicKey: String }
    private func vectors() throws -> Vectors {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        return try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: root.appendingPathComponent("vectors/gateway-recipient-v1.json")))
    }
    private func hex(_ text: String) -> Data {
        Data(stride(from: 0, to: text.count, by: 2).map { offset in
            let start = text.index(text.startIndex, offsetBy: offset)
            return UInt8(text[start..<text.index(start, offsetBy: 2)], radix: 16)!
        })
    }
    private func roundTrip(_ data: Data, kind: UInt64, limits: CBORLimits) throws -> Data {
        if kind == 2 { return try GatewayMappingActivation.decode(data, limits: limits).encode(limits: limits) }
        return try GatewayPhoneRevocation.decode(data, limits: limits).encode(limits: limits)
    }

    func testSharedControlsRetainAllFieldsAndUnsignedBoundaries() throws {
        let vectors = try vectors(); XCTAssertEqual(vectors.valid.count, 4)
        for row in vectors.valid {
            let bytes = hex(row.hex)
            XCTAssertEqual(try roundTrip(bytes, kind: row.kind, limits: limits), bytes, row.name)
            let revision: UInt64, issued: UInt64, expires: UInt64, operation: Data, fields: [Data]
            if row.kind == 2 {
                let value = try GatewayMappingActivation.decode(bytes, limits: limits), b = value.binding
                revision = value.revision; issued = value.issuedAtUnixMillis; expires = value.expiresAtUnixMillis; operation = value.operationID
                fields = [b.ownerID, b.macID, b.accountID, b.gatewayID, b.lifecycleEpoch, b.phoneID, b.enrollmentEpoch,
                    b.candidateID, b.tokenDigest, b.challenge, b.enrollmentTag]
            } else {
                let value = try GatewayPhoneRevocation.decode(bytes, limits: limits), b = value.binding
                revision = value.revision; issued = value.issuedAtUnixMillis; expires = value.expiresAtUnixMillis; operation = value.operationID
                fields = [b.ownerID, b.macID, b.accountID, b.gatewayID, b.lifecycleEpoch, b.phoneID, b.enrollmentEpoch]
            }
            XCTAssertEqual(revision, UInt64(row.revision)); XCTAssertEqual(issued, UInt64(row.issued)); XCTAssertEqual(expires, UInt64(row.expires))
            XCTAssertEqual(operation, Data(repeating: 0x56, count: 16))
            for (i, field) in fields.enumerated() { XCTAssertEqual(field, Data(repeating: UInt8(i + 16), count: i < 8 ? 16 : 32)) }
        }
    }

    func testSharedMalformedControlsFailClosed() throws {
        let rows = try vectors().invalid; XCTAssertEqual(rows.count, 134)
        for row in rows { XCTAssertThrowsError(try roundTrip(hex(row.hex), kind: row.kind, limits: limits), row.name) }
    }

    func testSharedSignaturesSeparateKeysKindsPurposesAndDomains() throws {
        let vectors = try vectors()
        for row in vectors.valid {
            let bytes = hex(row.hex), kind = GatewayRecipientKind(rawValue: row.kind)!
            XCTAssertEqual(try GatewayRecipientSigningInput.make(wireVersion: 1, kind: kind, canonicalPayload: bytes,
                payloadLimits: limits, inputLimits: limits), hex(row.signingInput))
            func verify(_ signature: String, key: String? = nil) throws -> Bool {
                try GatewayRecipientSignature.verify(signature: hex(signature), publicKey: hex(key ?? vectors.publicKey), wireVersion: 1,
                    kind: kind, canonicalPayload: bytes, payloadLimits: limits, inputLimits: limits)
            }
            XCTAssertTrue(try verify(row.signature)); XCTAssertFalse(try verify(row.signature, key: vectors.otherPublicKey))
            for signature in [row.wrongPurposeSignature, row.wrongTypeSignature, row.probeSignature, row.approvalSignature] {
                XCTAssertFalse(try verify(signature))
            }
            XCTAssertFalse(try verify("00")); XCTAssertFalse(try verify(row.signature, key: "00"))
        }
    }

    func testSignaturesBindEveryIdentityAndControlField() throws {
        let vectors = try vectors()
        for row in vectors.valid where row.name.hasSuffix("ordinary") {
            guard case let .map(original) = try DeterministicCBOR.decode(hex(row.hex), limits: limits),
                  case let .map(binding) = original[1] else { return XCTFail() }
            var mutations: [[UInt64: CBORValue]] = []
            for key in binding.keys {
                var nested = binding; guard case var .bytes(bytes) = nested[key] else { return XCTFail() }
                bytes[0] ^= 1; nested[key] = .bytes(bytes)
                var changed = original; changed[1] = .map(nested); mutations.append(changed)
            }
            for key in UInt64(2)...5 {
                var changed = original
                switch changed[key] {
                case let .unsigned(value): changed[key] = .unsigned(value + 1)
                case var .bytes(value): value[0] ^= 1; changed[key] = .bytes(value)
                default: return XCTFail()
                }
                mutations.append(changed)
            }
            for changed in mutations {
                XCTAssertFalse(try GatewayRecipientSignature.verify(signature: hex(row.signature), publicKey: hex(vectors.publicKey), wireVersion: 1,
                    kind: GatewayRecipientKind(rawValue: row.kind)!, canonicalPayload: DeterministicCBOR.encode(.map(changed), limits: limits),
                    payloadLimits: limits, inputLimits: limits))
            }
        }
    }

    func testBoundsVersionsAndOtherMessageShapesFail() throws {
        for row in try vectors().valid {
            let bytes = hex(row.hex), kind = GatewayRecipientKind(rawValue: row.kind)!
            XCTAssertEqual(try roundTrip(bytes, kind: row.kind, limits: CBORLimits(maxBytes: bytes.count, maxDepth: 8, maxItems: 128)), bytes)
            for bounded in [try CBORLimits(maxBytes: bytes.count - 1, maxDepth: 8, maxItems: 128),
                            try CBORLimits(maxBytes: 2048, maxDepth: 1, maxItems: 128),
                            try CBORLimits(maxBytes: 2048, maxDepth: 8, maxItems: 2)] {
                XCTAssertThrowsError(try roundTrip(bytes, kind: row.kind, limits: bounded))
                XCTAssertThrowsError(try GatewayRecipientSigningInput.make(wireVersion: 1, kind: kind, canonicalPayload: bytes, payloadLimits: bounded, inputLimits: limits))
            }
            let short = try CBORLimits(maxBytes: hex(row.signingInput).count - 1, maxDepth: 8, maxItems: 128)
            XCTAssertThrowsError(try GatewayRecipientSigningInput.make(wireVersion: 1, kind: kind, canonicalPayload: bytes, payloadLimits: limits, inputLimits: short))
            for version: UInt64 in [0, 2, .max] {
                XCTAssertThrowsError(try GatewayRecipientSigningInput.make(wireVersion: version, kind: kind, canonicalPayload: bytes, payloadLimits: limits, inputLimits: limits))
            }
            XCTAssertThrowsError(try GatewayRecipientSigningInput.make(wireVersion: 1, kind: kind == .activation ? .phoneRevocation : .activation,
                canonicalPayload: bytes, payloadLimits: limits, inputLimits: limits))
            XCTAssertThrowsError(try GatewayTokenCandidate.decode(bytes, limits: limits))
            XCTAssertThrowsError(try GatewayTokenProof.decode(bytes, limits: limits))
            guard case var .map(fields) = try DeterministicCBOR.decode(bytes, limits: limits) else { return XCTFail() }
            fields.removeValue(forKey: 6)
            let untyped = try DeterministicCBOR.encode(.map(fields), limits: limits)
            XCTAssertThrowsError(try GatewayRecipientSigningInput.make(wireVersion: 1, kind: kind, canonicalPayload: untyped, payloadLimits: limits, inputLimits: limits))
        }
    }

    func testDescriptionsRedactAndBindingsHaveValueSemantics() throws {
        let rows = try vectors().valid
        let activation = try GatewayMappingActivation.decode(hex(rows[0].hex), limits: limits)
        let revocation = try GatewayPhoneRevocation.decode(hex(rows[2].hex), limits: limits)
        var operation = revocation.operationID; operation[0] ^= 1
        var owner = revocation.binding.ownerID; owner[0] ^= 1
        XCTAssertNotEqual(operation, revocation.operationID); XCTAssertNotEqual(owner, revocation.binding.ownerID)
        XCTAssertEqual(String(reflecting: activation), "GatewayMappingActivation(redacted)")
        XCTAssertEqual(String(reflecting: revocation), "GatewayPhoneRevocation(redacted)")
        XCTAssertEqual(String(reflecting: revocation.binding), "GatewayPhoneEpochBinding(redacted)")
    }
}
