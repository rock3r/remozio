import Foundation
import XCTest
@testable import RemozioProtocol

final class UpdateSchedulingTests: XCTestCase {
    private var limits: CBORLimits { get throws { try CBORLimits(maxBytes: 1024, maxDepth: 8, maxItems: 64) } }
    private struct Row: Decodable {
        let name: String; let hex: String; let signature: String?; let signingInput: String?
        let action: String?; let generation: String?; let revision: String?; let issued: String?; let expires: String?
        let wrongPurposeSignature: String?; let wrongTypeSignature: String?; let wrongVersionSignature: String?
        let approvalSignature: String?; let routingSignature: String?; let gatewaySignature: String?
    }
    private struct Vectors: Decodable { let valid: [Row]; let invalid: [Row]; let publicKey: String; let otherPublicKey: String }
    private func vectors() throws -> Vectors {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        return try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: root.appendingPathComponent("vectors/update-scheduling-v1.json")))
    }
    private func hex(_ text: String) -> Data {
        Data(stride(from: 0, to: text.count, by: 2).map { offset in
            let start = text.index(text.startIndex, offsetBy: offset)
            return UInt8(text[start..<text.index(start, offsetBy: 2)], radix: 16)!
        })
    }
    private func verify(_ signature: Data, _ key: Data, _ payload: Data) throws -> Bool {
        try UpdateSchedulingSignature.verify(signature: signature, publicKey: key, wireVersion: 1,
            canonicalPayload: payload, payloadLimits: limits, inputLimits: limits)
    }
    private func identityFields(_ value: UpdateSchedulingControl) -> [Data] {
        [value.macID, value.accountID, value.phoneID, value.enrollmentEpoch, value.operationID,
         value.challenge, value.keyID, value.updateID]
    }
    private func make(_ fields: [Data], generation: UInt64 = 7, issued: UInt64 = 1000, expires: UInt64 = 2000) throws -> UpdateSchedulingControl {
        try UpdateSchedulingControl(macID: fields[0], accountID: fields[1], phoneID: fields[2], enrollmentEpoch: fields[3],
            operationID: fields[4], challenge: fields[5], keyID: fields[6], updateID: fields[7], expectedGeneration: generation,
            expectedRevision: 12, issuedAtUnixMillis: issued, expiresAtUnixMillis: expires, action: .installWhenCurrentWorkFinishes)
    }

    func testSharedFieldsActionsAndUnsignedBoundariesRoundTrip() throws {
        let rows = try vectors().valid; XCTAssertEqual(rows.count, 5)
        var actions = Set<UInt64>()
        for row in rows {
            let bytes = hex(row.hex), value = try UpdateSchedulingControl.decode(bytes, limits: limits)
            XCTAssertEqual(try value.encode(limits: limits), bytes)
            XCTAssertEqual(value.action.rawValue, UInt64(row.action!)); actions.insert(value.action.rawValue)
            XCTAssertEqual(value.expectedGeneration, UInt64(row.generation!)); XCTAssertEqual(value.expectedRevision, UInt64(row.revision!))
            XCTAssertEqual(value.issuedAtUnixMillis, UInt64(row.issued!)); XCTAssertEqual(value.expiresAtUnixMillis, UInt64(row.expires!))
            for (i, field) in identityFields(value).enumerated() {
                XCTAssertEqual(field, Data(repeating: UInt8(i + 16), count: [5, 7].contains(i) ? 32 : 16))
            }
        }
        XCTAssertEqual(actions, Set(UpdateSchedulingAction.allCases.map(\.rawValue)))
    }

    func testMalformedControlsRejectEvenWhenTheirSignatureIsValid() throws {
        let vectors = try vectors(); XCTAssertEqual(vectors.invalid.count, 102)
        var signedInvalid = 0
        for row in vectors.invalid {
            let bytes = hex(row.hex)
            XCTAssertThrowsError(try UpdateSchedulingControl.decode(bytes, limits: limits), row.name)
            XCTAssertThrowsError(try UpdateSchedulingSigningInput.make(wireVersion: 1, canonicalPayload: bytes,
                payloadLimits: limits, inputLimits: limits), row.name)
            if let signature = row.signature {
                signedInvalid += 1
                XCTAssertTrue(P256Verification.verify(signature: hex(signature), publicKey: hex(vectors.publicKey), input: hex(row.signingInput!)))
                XCTAssertThrowsError(try verify(hex(signature), hex(vectors.publicKey), bytes), row.name)
            }
        }
        XCTAssertEqual(signedInvalid, 6)
    }

    func testSharedSignaturesSeparateKeysPurposesTypesVersionsAndDomains() throws {
        let vectors = try vectors()
        for row in vectors.valid {
            let bytes = hex(row.hex), signature = hex(row.signature!), key = hex(vectors.publicKey)
            XCTAssertEqual(try UpdateSchedulingSigningInput.make(wireVersion: 1, canonicalPayload: bytes,
                payloadLimits: limits, inputLimits: limits), hex(row.signingInput!))
            XCTAssertTrue(try verify(signature, key, bytes)); XCTAssertFalse(try verify(signature, hex(vectors.otherPublicKey), bytes))
            for wrong in [row.wrongPurposeSignature, row.wrongTypeSignature, row.wrongVersionSignature,
                          row.approvalSignature, row.routingSignature, row.gatewaySignature] {
                XCTAssertFalse(try verify(hex(wrong!), key, bytes))
            }
            XCTAssertFalse(try verify(Data([0]), key, bytes)); XCTAssertFalse(try verify(signature, Data([0]), bytes))
        }
    }

    func testSignatureBindsEveryMutableControlField() throws {
        let vectors = try vectors(), row = vectors.valid[0]
        guard case let .map(original) = try DeterministicCBOR.decode(hex(row.hex), limits: limits) else { return XCTFail() }
        for key in UInt64(1)...13 {
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

    func testResourceAndWireVersionBounds() throws {
        let row = try vectors().valid[0], bytes = hex(row.hex)
        XCTAssertEqual(try UpdateSchedulingControl.decode(bytes,
            limits: CBORLimits(maxBytes: bytes.count, maxDepth: 8, maxItems: 64)).encode(limits: limits), bytes)
        for bounds in [try CBORLimits(maxBytes: bytes.count - 1, maxDepth: 8, maxItems: 64),
                       try CBORLimits(maxBytes: 1024, maxDepth: 1, maxItems: 2)] {
            XCTAssertThrowsError(try UpdateSchedulingControl.decode(bytes, limits: bounds))
            XCTAssertThrowsError(try UpdateSchedulingSigningInput.make(wireVersion: 1, canonicalPayload: bytes,
                payloadLimits: bounds, inputLimits: limits))
        }
        for version: UInt64 in [0, 2, .max] {
            XCTAssertThrowsError(try UpdateSchedulingSigningInput.make(wireVersion: version, canonicalPayload: bytes,
                payloadLimits: limits, inputLimits: limits))
        }
        let short = try CBORLimits(maxBytes: hex(row.signingInput!).count - 1, maxDepth: 8, maxItems: 64)
        XCTAssertThrowsError(try UpdateSchedulingSigningInput.make(wireVersion: 1, canonicalPayload: bytes,
            payloadLimits: limits, inputLimits: short))
    }

    func testConstructorsRejectInvalidIdentitiesGenerationAndTime() throws {
        let value = try UpdateSchedulingControl.decode(hex(vectors().valid[0].hex), limits: limits)
        let fields = identityFields(value)
        for index in fields.indices {
            var invalid = fields; invalid[index] = Data()
            XCTAssertThrowsError(try make(invalid))
        }
        XCTAssertThrowsError(try make(fields, generation: 0))
        XCTAssertThrowsError(try make(fields, expires: 1000))
        XCTAssertThrowsError(try make(fields, expires: 999))
    }

    func testValueSemanticsAndDescriptions() throws {
        let original = try UpdateSchedulingControl.decode(hex(vectors().valid[0].hex), limits: limits)
        var fields = identityFields(original); let value = try make(fields)
        for index in fields.indices { fields[index][0] ^= 1 }
        XCTAssertEqual(try value.encode(limits: limits), try original.encode(limits: limits))
        var updateID = value.updateID; updateID[0] ^= 1
        XCTAssertNotEqual(updateID, value.updateID)
        XCTAssertEqual(String(describing: value), "UpdateSchedulingControl(redacted)")
        XCTAssertEqual(String(reflecting: value), "UpdateSchedulingControl(redacted)")
    }
}
