import Foundation
import XCTest
@testable import RemozioProtocol

final class SigningInputTests: XCTestCase {
    private var limits: CBORLimits { get throws { try CBORLimits(maxBytes: 1024, maxDepth: 8, maxItems: 64) } }

    func testSharedVectorsPreserveExactPayloadBytes() throws {
        struct Vector: Decodable { let type: UInt64; let purpose: UInt64; let payload: String; let input: String }
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let rows = try JSONDecoder().decode([Vector].self, from: Data(contentsOf: root.appendingPathComponent("vectors/signing-input-v1.json")))
        XCTAssertEqual(rows.count, 10)
        var transcripts = Set<Data>()
        for row in rows {
            let input = try SigningInput.make(wireVersion: 1,
                messageType: XCTUnwrap(ApprovalMessageType(rawValue: row.type)),
                purpose: XCTUnwrap(SigningPurpose(rawValue: row.purpose)),
                canonicalPayload: hex(row.payload), payloadLimits: limits, inputLimits: limits)
            XCTAssertEqual(input, hex(row.input))
            XCTAssertTrue(transcripts.insert(input).inserted)
            guard case let .map(fields) = try DeterministicCBOR.decode(input, limits: limits) else { return XCTFail() }
            XCTAssertEqual(fields[4], .bytes(hex(row.payload)))
        }
    }

    func testUnsupportedVersionsAndCrossPurposeSubstitution() throws {
        for version in [UInt64(0), 2, UInt64.max] {
            XCTAssertThrowsError(try make(version: version)) { XCTAssertEqual($0 as? SigningInputError, .unsupportedVersion) }
        }
        for type in ApprovalMessageType.allCases {
            for purpose in SigningPurpose.allCases {
                let allowed = type == .request && purpose == .issuedRequest || type == .status && purpose == .status ||
                    type == .decision && [.cancellation, .oneTimeUI, .biometricAuthorization].contains(purpose)
                if allowed { continue }
                XCTAssertThrowsError(try make(type: type, purpose: purpose)) {
                    XCTAssertEqual($0 as? SigningInputError, .incompatiblePurpose)
                }
            }
        }
    }

    func testInvalidPayloadAndIndependentBudgets() throws {
        for bytes in ["", "a1001800", "a100", "a0a0", "a200000001"] {
            XCTAssertThrowsError(try make(body: hex(bytes)))
        }
        XCTAssertThrowsError(try make(body: hex("80"))) { XCTAssertEqual($0 as? SigningInputError, .payloadMustBeMap) }
        let tiny = try CBORLimits(maxBytes: 1, maxDepth: 8, maxItems: 64)
        XCTAssertThrowsError(try SigningInput.make(wireVersion: 1, messageType: .request, purpose: .issuedRequest,
            canonicalPayload: hex("a10000"), payloadLimits: tiny, inputLimits: limits))
        XCTAssertThrowsError(try SigningInput.make(wireVersion: 1, messageType: .request, purpose: .issuedRequest,
            canonicalPayload: hex("a0"), payloadLimits: limits, inputLimits: tiny))
    }

    private func make(version: UInt64 = 1, type: ApprovalMessageType = .request,
                      purpose: SigningPurpose = .issuedRequest, body: Data = Data([0xa0])) throws -> Data {
        try SigningInput.make(wireVersion: version, messageType: type, purpose: purpose,
            canonicalPayload: body, payloadLimits: limits, inputLimits: limits)
    }

    private func hex(_ text: String) -> Data {
        let chars = Array(text)
        return Data(stride(from: 0, to: chars.count, by: 2).map { UInt8(String(chars[$0...$0 + 1]), radix: 16)! })
    }
}
