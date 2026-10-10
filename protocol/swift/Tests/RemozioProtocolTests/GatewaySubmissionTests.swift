import Foundation
import XCTest
@testable import RemozioProtocol

final class GatewaySubmissionTests: XCTestCase {
    private var limits: CBORLimits { get throws { try CBORLimits(maxBytes: 2048, maxDepth: 8, maxItems: 128) } }
    private struct Valid: Decodable {
        let name: String; let kind: UInt64; let hex: String; let revision: String; let issued: String; let expires: String
        let signingInput: String; let signature: String; let wrongPurposeSignature: String; let wrongTypeSignature: String
        let approvalSignature: String; let credentialSignature: String
    }
    private struct Invalid: Decodable { let name: String; let kind: UInt64; let hex: String }
    private struct Vectors: Decodable {
        let valid: [Valid]; let invalid: [Invalid]; let publicKey: String; let otherPublicKey: String; let credentialPublicKey: String
    }
    private func vectors() throws -> Vectors {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        return try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: root.appendingPathComponent("vectors/gateway-submission-v1.json")))
    }
    private func hex(_ text: String) -> Data {
        Data(stride(from: 0, to: text.count, by: 2).map { offset in
            let start = text.index(text.startIndex, offsetBy: offset)
            return UInt8(text[start..<text.index(start, offsetBy: 2)], radix: 16)!
        })
    }
    func testSharedFieldsAndUnsignedBoundaries() throws {
        let vectors = try vectors(); XCTAssertEqual(vectors.valid.count, 4)
        for row in vectors.valid {
            let bytes = hex(row.hex), value = try GatewaySubmissionControl.decode(bytes, limits: limits)
            XCTAssertEqual(try value.encode(limits: limits), bytes)
            XCTAssertEqual(value.kind.rawValue, row.kind); XCTAssertEqual(value.revision, UInt64(row.revision))
            XCTAssertEqual(value.issuedAtUnixMillis, UInt64(row.issued)); XCTAssertEqual(value.expiresAtUnixMillis, UInt64(row.expires))
            XCTAssertEqual(value.operationID, Data(repeating: 0x56, count: 16)); XCTAssertEqual(value.credentialID, Data(repeating: 0x57, count: 16))
            let b = value.binding
            for (i, data) in [b.ownerID,b.macID,b.accountID,b.gatewayID,b.lifecycleEpoch].enumerated() {
                XCTAssertEqual(data, Data(repeating: UInt8(i+16), count: 16))
            }
            XCTAssertEqual(value.publicKey, row.kind == 4 ? hex(vectors.credentialPublicKey) : nil)
        }
    }
    func testMalformedSharedControlsFail() throws {
        let rows = try vectors().invalid; XCTAssertEqual(rows.count, 124)
        for row in rows {
            XCTAssertThrowsError(try GatewaySubmissionControl.decode(hex(row.hex), limits: limits), row.name)
            XCTAssertThrowsError(try GatewaySubmissionSigningInput.make(wireVersion: 1, kind: GatewaySubmissionKind(rawValue: row.kind)!,
                canonicalPayload: hex(row.hex), payloadLimits: limits, inputLimits: limits), row.name)
        }
    }
    func testSharedRootSignaturesSeparateKindsKeysAndPurposes() throws {
        let vectors = try vectors()
        for row in vectors.valid {
            let bytes = hex(row.hex), kind = GatewaySubmissionKind(rawValue: row.kind)!
            XCTAssertEqual(try GatewaySubmissionControl.decode(bytes, limits: CBORLimits(maxBytes: bytes.count, maxDepth: 8, maxItems: 128))
                .encode(limits: limits), bytes)
            XCTAssertThrowsError(try GatewaySubmissionSigningInput.make(wireVersion: 1, kind: kind, canonicalPayload: bytes,
                payloadLimits: limits, inputLimits: CBORLimits(maxBytes: hex(row.signingInput).count-1, maxDepth: 8, maxItems: 128)))
            XCTAssertEqual(try GatewaySubmissionSigningInput.make(wireVersion: 1, kind: kind, canonicalPayload: bytes,
                payloadLimits: limits, inputLimits: limits), hex(row.signingInput))
            func verify(_ signature: String, key: String? = nil) throws -> Bool {
                try GatewaySubmissionSignature.verify(signature: hex(signature), publicKey: hex(key ?? vectors.publicKey), wireVersion: 1,
                    kind: kind, canonicalPayload: bytes, payloadLimits: limits, inputLimits: limits)
            }
            XCTAssertTrue(try verify(row.signature))
            XCTAssertFalse(try verify(row.signature, key: vectors.otherPublicKey))
            XCTAssertFalse(try verify(row.signature, key: vectors.credentialPublicKey))
            for signature in [row.wrongPurposeSignature,row.wrongTypeSignature,row.approvalSignature,row.credentialSignature,"00"] {
                XCTAssertFalse(try verify(signature))
            }
        }
    }
    func testSignaturesBindEveryIdentityAndControlField() throws {
        let vectors = try vectors()
        for row in vectors.valid where row.name.hasSuffix("ordinary") {
            guard case .map(let original) = try DeterministicCBOR.decode(hex(row.hex), limits: limits),
                  case .map(let binding) = original[1] else { return XCTFail() }
            var mutations: [[UInt64: CBORValue]] = []
            for key in binding.keys {
                var b=binding; guard case .bytes(var data) = b[key] else { return XCTFail() }
                data[0] ^= 1; b[key] = .bytes(data); var c=original; c[1] = .map(b); mutations.append(c)
            }
            for key: UInt64 in [2,3,4,5,7,8] {
                var c=original
                switch c[key] {
                case .unsigned(let value): c[key] = .unsigned(value+1)
                case .bytes(var value): value[value.count-1] ^= 1; c[key] = .bytes(value)
                case .null: continue
                default: return XCTFail()
                }
                mutations.append(c)
            }
            for c in mutations {
                XCTAssertFalse(try GatewaySubmissionSignature.verify(signature: hex(row.signature), publicKey: hex(vectors.publicKey),
                    wireVersion: 1, kind: GatewaySubmissionKind(rawValue: row.kind)!, canonicalPayload: DeterministicCBOR.encode(.map(c), limits: limits),
                    payloadLimits: limits, inputLimits: limits))
            }
        }
    }
    func testVersionsBoundsAndOtherControlTypesFail() throws {
        for row in try vectors().valid {
            let bytes = hex(row.hex), kind = GatewaySubmissionKind(rawValue: row.kind)!
            for version: UInt64 in [0,2,.max] {
                XCTAssertThrowsError(try GatewaySubmissionSigningInput.make(wireVersion: version, kind: kind, canonicalPayload: bytes,
                    payloadLimits: limits, inputLimits: limits))
            }
            for bounded in [try CBORLimits(maxBytes: bytes.count-1,maxDepth:8,maxItems:128),
                            try CBORLimits(maxBytes:2048,maxDepth:1,maxItems:128),try CBORLimits(maxBytes:2048,maxDepth:8,maxItems:2)] {
                XCTAssertThrowsError(try GatewaySubmissionControl.decode(bytes, limits: bounded))
            }
            XCTAssertThrowsError(try GatewaySubmissionSigningInput.make(wireVersion: 1, kind: kind == .rotation ? .revocation : .rotation,
                canonicalPayload: bytes, payloadLimits: limits, inputLimits: limits))
            XCTAssertThrowsError(try GatewayTokenCandidate.decode(bytes, limits: limits))
            XCTAssertThrowsError(try GatewayMappingActivation.decode(bytes, limits: limits))
            XCTAssertThrowsError(try GatewayPhoneRevocation.decode(bytes, limits: limits))
            let value = try GatewaySubmissionControl.decode(bytes, limits: limits)
            XCTAssertEqual(String(reflecting: value), "GatewaySubmissionControl(redacted)")
            XCTAssertEqual(String(reflecting: value.binding), "GatewaySubmissionBinding(redacted)")
        }
    }
}
