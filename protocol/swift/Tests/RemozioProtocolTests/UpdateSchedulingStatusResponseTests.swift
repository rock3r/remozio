import Foundation
import XCTest
@testable import RemozioProtocol

private struct UpdateChannelRow: Decodable {
    let name: String; let hex: String; let signature: String?; let signingInput: String?
    let generation: String?; let revision: String?; let action: UInt64?; let kind: Int?
    let wrongVersionSignature: String?; let wrongTypeSignature: String?
    let wrongPurposeSignature: String?; let phoneControlDomainSignature: String?
}
private struct UpdateChannelVectors: Decodable {
    let publicKey: String?; let otherPublicKey: String?; let valid: [UpdateChannelRow]; let invalid: [UpdateChannelRow]
}
private func channelVectors(_ name: String) throws -> UpdateChannelVectors {
    let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        .deletingLastPathComponent().deletingLastPathComponent()
    return try JSONDecoder().decode(UpdateChannelVectors.self, from: Data(contentsOf: root.appendingPathComponent("vectors/" + name)))
}
private func channelHex(_ text: String) -> Data {
    Data(stride(from: 0, to: text.count, by: 2).map { offset in
        let start = text.index(text.startIndex, offsetBy: offset)
        return UInt8(text[start..<text.index(start, offsetBy: 2)], radix: 16)!
    })
}

final class UpdateSchedulingStatusResponseTests: XCTestCase {
    private var signingLimits: CBORLimits { get throws { try .init(maxBytes: 4096, maxDepth: 2, maxItems: 32) } }
    private func vectors() throws -> UpdateChannelVectors { try channelVectors("update-scheduling-status-v1.json") }
    private func verify(_ signature: Data, _ key: Data, _ payload: Data) throws -> Bool {
        try UpdateSchedulingStatusSignature.verify(signature: signature, authorityPublicKey: key,
            wireVersion: 1, canonicalPayload: payload, inputLimits: signingLimits)
    }
    func testSharedStatusClaimsPreserveAllUnsignedValuesAndExactBytes() throws {
        let v = try vectors(); XCTAssertEqual(v.valid.count, 6)
        for row in v.valid {
            let bytes = channelHex(row.hex), value = try UpdateSchedulingStatusResponse.decode(bytes)
            XCTAssertEqual(try value.encode(), bytes); XCTAssertEqual(value.generation, UInt64(row.generation!))
            XCTAssertEqual(value.revision, UInt64(row.revision!)); XCTAssertEqual(value.requestedAction?.rawValue, row.action)
            XCTAssertEqual(try UpdateSchedulingStatusSigningInput.make(wireVersion: 1, canonicalPayload: bytes,
                inputLimits: signingLimits), channelHex(row.signingInput!))
            XCTAssertTrue(try verify(channelHex(row.signature!), channelHex(v.publicKey!), bytes))
        }
    }
    func testMalformedSignedClaimsFailBeforeSignatureVerification() throws {
        let v = try vectors(); XCTAssertEqual(v.invalid.count, 54); var signed = 0
        for row in v.invalid {
            let bytes = channelHex(row.hex)
            XCTAssertThrowsError(try UpdateSchedulingStatusResponse.decode(bytes), row.name)
            XCTAssertThrowsError(try UpdateSchedulingStatusSigningInput.make(wireVersion: 1,
                canonicalPayload: bytes, inputLimits: signingLimits), row.name)
            if let signature = row.signature {
                signed += 1
                XCTAssertTrue(P256Verification.verify(signature: channelHex(signature), publicKey: channelHex(v.publicKey!), input: channelHex(row.signingInput!)))
                XCTAssertThrowsError(try verify(channelHex(signature), channelHex(v.publicKey!), bytes))
            }
        }
        XCTAssertEqual(signed, 6)
    }
    func testSignatureBindsEveryFieldTheRootKeyAndTheStatusDomain() throws {
        let v = try vectors(), key = channelHex(v.publicKey!)
        for row in v.valid {
            let bytes = channelHex(row.hex), signature = channelHex(row.signature!)
            XCTAssertFalse(try verify(signature, channelHex(v.otherPublicKey!), bytes))
            for wrong in [row.wrongVersionSignature, row.wrongTypeSignature, row.wrongPurposeSignature, row.phoneControlDomainSignature] {
                XCTAssertFalse(try verify(channelHex(wrong!), key, bytes))
            }
            guard case let .map(original) = try DeterministicCBOR.decode(bytes, limits: UpdateSchedulingStatusResponse.limits) else { return XCTFail() }
            for field in UInt64(1)...10 {
                var fields = original
                switch fields[field] {
                case var .bytes(value): value[0] ^= 1; fields[field] = .bytes(value)
                case let .unsigned(value): fields[field] = .unsigned(value == .max ? 1 : value + 1)
                case .null: fields[field] = field == 10 ? .bytes(Data(repeating: 5, count: 32)) : .unsigned(0)
                default: return XCTFail()
                }
                let changed = try DeterministicCBOR.encode(.map(fields), limits: UpdateSchedulingStatusResponse.limits)
                var rejected = false
                do { rejected = !(try verify(signature, key, changed)) } catch { rejected = true }
                XCTAssertTrue(rejected)
            }
        }
    }
    func testResourceLimitsWireVersionAndDescriptionsRemainStrict() throws {
        let row = try vectors().valid[0], bytes = channelHex(row.hex)
        let value = try UpdateSchedulingStatusResponse.decode(bytes)
        for wire: UInt64 in [0, 2, .max] {
            XCTAssertThrowsError(try UpdateSchedulingStatusSigningInput.make(wireVersion: wire,
                canonicalPayload: bytes, inputLimits: signingLimits))
        }
        XCTAssertThrowsError(try UpdateSchedulingStatusResponse.decode(Data(repeating: 0, count: 2049)))
        let short = try CBORLimits(maxBytes: channelHex(row.signingInput!).count - 1, maxDepth: 2, maxItems: 32)
        XCTAssertThrowsError(try UpdateSchedulingStatusSigningInput.make(wireVersion: 1, canonicalPayload: bytes, inputLimits: short))
        XCTAssertEqual(value.description, "UpdateSchedulingStatusResponse(redacted)")
        XCTAssertEqual(value.debugDescription, value.description)
    }
    func testObservationAndCommittedControlClaimsCannotBeInterchanged() throws {
        let rows = try vectors().valid.map { try UpdateSchedulingStatusResponse.decode(channelHex($0.hex)) }
        XCTAssertNil(rows[0].controlDigest); XCTAssertNil(rows[0].requestedAction); XCTAssertEqual(rows[0].revision, 0)
        for row in rows where row.controlDigest != nil {
            XCTAssertNotNil(row.requestedAction); XCTAssertGreaterThan(row.revision, 0)
        }
        let first = rows[0]
        XCTAssertThrowsError(try UpdateSchedulingStatusResponse(scope: first.scope, queryNonce: first.queryNonce,
            updateID: first.updateID, generation: 1, revision: 0, requestedAction: .deferUpdate))
        XCTAssertThrowsError(try UpdateSchedulingStatusResponse(scope: first.scope, queryNonce: first.queryNonce,
            updateID: first.updateID, generation: 1, revision: 1, requestedAction: nil))
    }
}
