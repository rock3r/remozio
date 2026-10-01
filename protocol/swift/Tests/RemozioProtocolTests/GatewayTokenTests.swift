import Foundation
import XCTest
@testable import RemozioProtocol

final class GatewayTokenTests: XCTestCase {
    private var limits: CBORLimits { get throws { try CBORLimits(maxBytes: 2048, maxDepth: 8, maxItems: 128) } }
    private struct Row: Decodable { let name: String; let hex: String }
    private struct Candidate: Decodable {
        let name: String; let hex: String; let revision: String; let issued: String; let expires: String
        let signingInput: String; let signature: String; let wrongPurposeSignature: String; let approvalSignature: String
    }
    private struct Vectors: Decodable {
        let bindings: [String: String]; let operationID: String; let publicKey: String; let otherPublicKey: String
        let validCandidates: [Candidate]; let validProofs: [Row]; let invalidCandidates: [Row]; let invalidProofs: [Row]
    }
    private func vectors() throws -> Vectors {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        return try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: root.appendingPathComponent("vectors/gateway-token-v1.json")))
    }
    private func values(_ binding: GatewayTokenBinding) -> [Data] {
        [binding.ownerID, binding.macID, binding.accountID, binding.gatewayID, binding.lifecycleEpoch, binding.phoneID,
         binding.enrollmentEpoch, binding.candidateID, binding.tokenDigest, binding.challenge, binding.enrollmentTag]
    }
    private func binding(_ values: [Data]) throws -> GatewayTokenBinding {
        try GatewayTokenBinding(ownerID: values[0], macID: values[1], accountID: values[2], gatewayID: values[3],
            lifecycleEpoch: values[4], phoneID: values[5], enrollmentEpoch: values[6], candidateID: values[7],
            tokenDigest: values[8], challenge: values[9], enrollmentTag: values[10])
    }
    private func hex(_ text: String) -> Data {
        Data(stride(from: 0, to: text.count, by: 2).map { offset in
            let start = text.index(text.startIndex, offsetBy: offset)
            return UInt8(text[start..<text.index(start, offsetBy: 2)], radix: 16)!
        })
    }

    func testSharedCandidatesAndProofsRetainEveryBinding() throws {
        let vectors = try vectors()
        XCTAssertEqual(vectors.validCandidates.count, 2); XCTAssertEqual(vectors.validProofs.count, 1)
        for row in vectors.validCandidates {
            let encoded = hex(row.hex), candidate = try GatewayTokenCandidate.decode(encoded, limits: limits)
            XCTAssertEqual(try candidate.encode(limits: limits), encoded)
            XCTAssertEqual(candidate.revision, UInt64(row.revision))
            XCTAssertEqual(candidate.issuedAtUnixMillis, UInt64(row.issued)); XCTAssertEqual(candidate.expiresAtUnixMillis, UInt64(row.expires))
            XCTAssertEqual(candidate.operationID, hex(vectors.operationID))
            for (i, value) in values(candidate.binding).enumerated() { XCTAssertEqual(value, hex(vectors.bindings[String(i)]!)) }
            for proofRow in vectors.validProofs {
                let proof = try GatewayTokenProof.decode(hex(proofRow.hex), limits: limits)
                XCTAssertEqual(proof.binding, candidate.binding)
                XCTAssertEqual(try proof.encode(limits: limits), hex(proofRow.hex))
            }
        }
    }

    func testSharedMalformedCandidatesAndProofsFail() throws {
        let vectors = try vectors()
        XCTAssertEqual(vectors.invalidCandidates.count, 69); XCTAssertEqual(vectors.invalidProofs.count, 57)
        for row in vectors.invalidCandidates { XCTAssertThrowsError(try GatewayTokenCandidate.decode(hex(row.hex), limits: limits), row.name) }
        for row in vectors.invalidProofs { XCTAssertThrowsError(try GatewayTokenProof.decode(hex(row.hex), limits: limits), row.name) }
    }

    func testSharedSignaturesRejectOtherKeysPurposesAndApprovalDomain() throws {
        let vectors = try vectors()
        for row in vectors.validCandidates {
            let payload = hex(row.hex)
            let input = try GatewayTokenCandidateSigningInput.make(wireVersion: 1, canonicalPayload: payload, payloadLimits: limits, inputLimits: limits)
            XCTAssertEqual(input, hex(row.signingInput))
            func verify(_ signature: String, key: String? = nil) throws -> Bool {
                try GatewayTokenCandidateSignature.verify(signature: hex(signature), publicKey: hex(key ?? vectors.publicKey), wireVersion: 1,
                    canonicalPayload: payload, payloadLimits: limits, inputLimits: limits)
            }
            XCTAssertTrue(try verify(row.signature)); XCTAssertFalse(try verify(row.signature, key: vectors.otherPublicKey))
            XCTAssertFalse(try verify(row.wrongPurposeSignature)); XCTAssertFalse(try verify(row.approvalSignature))
        }
    }

    func testSignatureBindsEveryControlFieldAndNestedIdentity() throws {
        let vectors = try vectors(), row = vectors.validCandidates[0]
        guard case let .map(original) = try DeterministicCBOR.decode(hex(row.hex), limits: limits), case let .map(originalBinding) = original[1] else { return XCTFail() }
        var mutations: [[UInt64: CBORValue]] = []
        for field in UInt64(0)...10 {
            var changed = original, nested = originalBinding
            guard case var .bytes(value) = nested[field] else { return XCTFail() }
            value[0] ^= 1; nested[field] = .bytes(value); changed[1] = .map(nested); mutations.append(changed)
        }
        for field in UInt64(2)...5 {
            var changed = original
            switch changed[field] {
            case let .unsigned(value): changed[field] = .unsigned(value + 1)
            case var .bytes(value): value[0] ^= 1; changed[field] = .bytes(value)
            default: return XCTFail()
            }
            mutations.append(changed)
        }
        for changed in mutations {
            let payload = try DeterministicCBOR.encode(.map(changed), limits: limits)
            XCTAssertFalse(try GatewayTokenCandidateSignature.verify(signature: hex(row.signature), publicKey: hex(vectors.publicKey), wireVersion: 1,
                canonicalPayload: payload, payloadLimits: limits, inputLimits: limits))
        }
    }

    func testBoundsApplyToPayloadAndSigningInput() throws {
        let vectors = try vectors(), row = vectors.validCandidates[0], bytes = hex(row.hex)
        let candidate = try GatewayTokenCandidate.decode(bytes, limits: limits)
        let exact = try CBORLimits(maxBytes: bytes.count, maxDepth: 8, maxItems: 128)
        XCTAssertEqual(try candidate.encode(limits: exact), bytes)
        let short = try CBORLimits(maxBytes: bytes.count - 1, maxDepth: 8, maxItems: 128)
        XCTAssertThrowsError(try candidate.encode(limits: short)); XCTAssertThrowsError(try GatewayTokenCandidate.decode(bytes, limits: short))
        let inputShort = try CBORLimits(maxBytes: hex(row.signingInput).count - 1, maxDepth: 8, maxItems: 128)
        XCTAssertThrowsError(try GatewayTokenCandidateSigningInput.make(wireVersion: 1, canonicalPayload: bytes, payloadLimits: limits, inputLimits: inputShort))
        let proofBytes = hex(vectors.validProofs[0].hex), proof = try GatewayTokenProof.decode(proofBytes, limits: limits)
        let proofShort = try CBORLimits(maxBytes: proofBytes.count - 1, maxDepth: 8, maxItems: 128)
        XCTAssertThrowsError(try proof.encode(limits: proofShort)); XCTAssertThrowsError(try GatewayTokenProof.decode(proofBytes, limits: proofShort))
    }

    func testVersionAndMessageShapeCannotFallBack() throws {
        let vectors = try vectors()
        for version: UInt64 in [0, 2, .max] {
            XCTAssertThrowsError(try GatewayTokenCandidateSigningInput.make(wireVersion: version, canonicalPayload: hex(vectors.validCandidates[0].hex), payloadLimits: limits, inputLimits: limits))
        }
        XCTAssertThrowsError(try GatewayTokenCandidateSigningInput.make(wireVersion: 1, canonicalPayload: hex(vectors.validProofs[0].hex), payloadLimits: limits, inputLimits: limits))
    }

    func testBindingsAreValuesAndDescriptionsAreRedacted() throws {
        let candidate = try GatewayTokenCandidate.decode(hex(vectors().validCandidates[0].hex), limits: limits)
        var copied = values(candidate.binding), first = copied[0]
        let reconstructed = try binding(copied)
        first[0] ^= 1; copied[0] = first
        XCTAssertEqual(reconstructed, candidate.binding); XCTAssertNotEqual(try binding(copied), candidate.binding)
        for i in copied.indices {
            var invalid = copied; invalid[i] = Data()
            XCTAssertThrowsError(try binding(invalid))
        }
        XCTAssertEqual(String(reflecting: candidate), "GatewayTokenCandidate(redacted)")
        XCTAssertEqual(String(reflecting: candidate.binding), "GatewayTokenBinding(redacted)")
        XCTAssertEqual(String(reflecting: GatewayTokenProof(binding: candidate.binding)), "GatewayTokenProof(redacted)")
    }
}
