import Foundation
import XCTest
@testable import RemozioProtocol

final class PhoneRoutingTests: XCTestCase {
    private struct Row: Decodable {
        let name: String; let hex: String; let signature: String?; let signingInput: String?
        let wrongPurposeSignature: String?; let wrongTypeSignature: String?; let wrongVersionSignature: String?
        let approvalSignature: String?; let gatewaySignature: String?
    }
    private struct Vectors: Decodable {
        let publicKey: String; let otherPublicKey: String
        let responsesValid: [Row]; let responsesInvalid: [Row]; let framesValid: [Row]; let framesInvalid: [Row]
    }
    private var inputLimits: CBORLimits { get throws { try .init(maxBytes: 3200, maxDepth: 2, maxItems: 16) } }
    private func vectors() throws -> Vectors {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        return try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: root.appendingPathComponent("vectors/phone-routing-v1.json")))
    }
    private func hex(_ text: String) -> Data {
        Data(stride(from: 0, to: text.count, by: 2).map { offset in
            let start = text.index(text.startIndex, offsetBy: offset)
            return UInt8(text[start..<text.index(start, offsetBy: 2)], radix: 16)!
        })
    }
    private func verify(_ signature: Data, key: Data, body: Data) throws -> Bool {
        try RoutingStatusSignature.verify(signature: signature, publicKey: key, wireVersion: 1, canonicalPayload: body, inputLimits: inputLimits)
    }
    func testSharedResponseBytesAndHistoricalReceiptRemainDistinctFromCurrentState() throws {
        let rows = try vectors().responsesValid; XCTAssertEqual(rows.count, 17)
        for row in rows {
            let bytes = hex(row.hex), value = try RoutingStatusResponse.decode(bytes)
            XCTAssertEqual(try value.encode(), bytes, row.name)
            XCTAssertEqual(value.queryNonce, Data(repeating: 20, count: 32))
            if row.name == "applied-historical-present" {
                XCTAssertEqual(value.outcome, .applied); XCTAssertEqual(value.appliedRevision, 3)
                XCTAssertEqual(value.state.mode, .present); XCTAssertEqual(value.state.revision, 5)
            }
            if row.name == "unsigned-max" { XCTAssertEqual(value.state.revision, .max); XCTAssertEqual(value.sampledAtMilliseconds, .max) }
        }
    }
    func testSignedMalformedResponseClaimsRemainRejected() throws {
        let v = try vectors(); XCTAssertGreaterThan(v.responsesInvalid.count, 100)
        for row in v.responsesInvalid {
            let bytes = hex(row.hex)
            XCTAssertTrue(P256Verification.verify(signature: hex(row.signature!), publicKey: hex(v.publicKey), input: hex(row.signingInput!)), row.name)
            XCTAssertThrowsError(try RoutingStatusResponse.decode(bytes), row.name)
            XCTAssertThrowsError(try verify(hex(row.signature!), key: hex(v.publicKey), body: bytes), row.name)
        }
    }
    func testSignaturesSeparateKeysTypesPurposesVersionsAndDomains() throws {
        let v = try vectors()
        for row in v.responsesValid {
            let body = hex(row.hex), key = hex(v.publicKey)
            XCTAssertEqual(try RoutingStatusSigningInput.make(wireVersion: 1, canonicalPayload: body, inputLimits: inputLimits), hex(row.signingInput!))
            XCTAssertTrue(try verify(hex(row.signature!), key: key, body: body), row.name)
            XCTAssertFalse(try verify(hex(row.signature!), key: hex(v.otherPublicKey), body: body), row.name)
            for signature in [row.wrongPurposeSignature, row.wrongTypeSignature, row.wrongVersionSignature, row.approvalSignature, row.gatewaySignature] {
                XCTAssertFalse(try verify(hex(signature!), key: key, body: body), row.name)
            }
            XCTAssertFalse(try verify(Data(), key: key, body: body)); XCTAssertFalse(try verify(hex(row.signature!), key: Data(), body: body))
        }
    }
    func testSignatureRejectsEveryChangedBoundField() throws {
        let v = try vectors(), row = try XCTUnwrap(v.responsesValid.first { $0.name == "applied-historical-present" })
        guard case let .map(original) = try DeterministicCBOR.decode(hex(row.hex), limits: RoutingStatusResponse.limits) else { return XCTFail() }
        for key in UInt64(0)...16 {
            var changed = original
            switch changed[key] {
            case var .bytes(value): value[0] ^= 1; changed[key] = .bytes(value)
            case let .unsigned(value): changed[key] = .unsigned(value + 1)
            case .null: changed[key] = .bytes(Data())
            default: return XCTFail()
            }
            let bytes = try DeterministicCBOR.encode(.map(changed), limits: RoutingStatusResponse.limits)
            XCTAssertFalse((try? verify(hex(row.signature!), key: hex(v.publicKey), body: bytes)) ?? false, "field \(key)")
        }
    }
    func testFramesRoundTripAndRejectMalformedOrMismatchedNestedNonce() throws {
        let v = try vectors(); XCTAssertEqual(v.framesValid.count, 23); XCTAssertGreaterThan(v.framesInvalid.count, 15)
        for row in v.framesValid {
            let bytes = hex(row.hex), frame = try PhoneRoutingFrame.decode(bytes)
            XCTAssertEqual(try frame.encode(), bytes, row.name)
            XCTAssertEqual(String(reflecting: frame), "PhoneRoutingFrame(redacted)")
        }
        for row in v.framesInvalid { XCTAssertThrowsError(try PhoneRoutingFrame.decode(hex(row.hex)), row.name) }
    }
    func testVersionAndSigningResourceLimits() throws {
        let row = try vectors().responsesValid[0], body = hex(row.hex)
        for version: UInt64 in [0, 2, .max] {
            XCTAssertThrowsError(try RoutingStatusSigningInput.make(wireVersion: version, canonicalPayload: body, inputLimits: inputLimits))
        }
        XCTAssertThrowsError(try RoutingStatusSigningInput.make(wireVersion: 1, canonicalPayload: body,
            inputLimits: .init(maxBytes: hex(row.signingInput!).count - 1, maxDepth: 2, maxItems: 16)))
        XCTAssertThrowsError(try RoutingStatusSigningInput.make(wireVersion: 1, canonicalPayload: body,
            inputLimits: .init(maxBytes: 3200, maxDepth: 1, maxItems: 2)))
    }
    func testDescriptionsAndValueCopiesDoNotExposeMutablePayloadOwnership() throws {
        let v = try RoutingStatusResponse.decode(hex(vectors().responsesValid[0].hex))
        var nonce = v.queryNonce; nonce[0] ^= 1
        var epoch = v.clockEpoch; epoch[0] ^= 1
        XCTAssertNotEqual(v.queryNonce, nonce); XCTAssertNotEqual(v.clockEpoch, epoch)
        XCTAssertEqual(String(reflecting: v), "RoutingStatusResponse(redacted)")
        XCTAssertEqual(String(reflecting: v.state), "RoutingStatusState(redacted)")
    }
}
