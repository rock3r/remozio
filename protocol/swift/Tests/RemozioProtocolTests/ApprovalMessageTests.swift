import Foundation
import XCTest
@testable import RemozioProtocol

final class ApprovalMessageTests: XCTestCase {
    func testExactOpaqueBytesAndSignatureUseSharedWireEncoding() throws {
        let message = try ApprovalMessage(wireVersion: 1, type: .request, purpose: .issuedRequest,
            body: Data([1, 2, 3]), signature: Data(repeating: 0xaa, count: 64))
        let encoded = try message.encode(maximumBodyBytes: 3)
        XCTAssertEqual(encoded.map { String(format: "%02x", $0) }.joined(),
            "a600010101020103010443010203055840" + String(repeating: "aa", count: 64))
        let decoded = try ApprovalMessage.decode(encoded, maximumBodyBytes: 3)
        XCTAssertEqual(message.body, decoded.body); XCTAssertEqual(message.signature, decoded.signature)
        XCTAssertEqual(decoded.description, "ApprovalMessage(redacted)")
    }
    func testOnlyDefinedSigningDomainsAndWireVersionsAreCarried() throws {
        for type in ApprovalMessageType.allCases { for purpose in SigningPurpose.allCases {
            let valid: Bool
            switch (type, purpose) {
            case (.request, .issuedRequest), (.status, .status), (.decision, .cancellation),
                 (.decision, .oneTimeUI), (.decision, .biometricAuthorization): valid = true
            default: valid = false
            }
            let result = try? ApprovalMessage(wireVersion: 1, type: type, purpose: purpose,
                body: Data([1]), signature: Data(count: 64)).encode(maximumBodyBytes: 1)
            XCTAssertEqual(result != nil, valid)
        } }
        XCTAssertThrowsError(try ApprovalMessage(wireVersion: 2, type: .request, purpose: .issuedRequest,
            body: Data([1]), signature: Data(count: 64)))
    }
    func testMalformedUnsupportedAndOversizedCarriersFail() throws {
        let message = try ApprovalMessage(wireVersion: 1, type: .request, purpose: .issuedRequest,
            body: Data([1]), signature: Data(count: 64))
        let encoded = try message.encode(maximumBodyBytes: 1)
        let limits = try CBORLimits(maxBytes: 256, maxDepth: 2, maxItems: 20)
        guard case let .map(fields) = try DeterministicCBOR.decode(encoded, limits: limits) else { return XCTFail() }
        let changes: [(UInt64, CBORValue)] = [(0, .unsigned(2)), (1, .unsigned(2)), (2, .unsigned(99)), (3, .unsigned(99)),
            (3, .unsigned(5)), (4, .bytes(Data())), (4, .bytes(Data(count: 2))), (5, .bytes(Data(count: 63))), (6, .unsigned(1))]
        for (key, value) in changes {
            var changed = fields; changed[key] = value
            let bytes = try DeterministicCBOR.encode(.map(changed), limits: limits)
            XCTAssertThrowsError(try ApprovalMessage.decode(bytes, maximumBodyBytes: 1))
        }
        XCTAssertThrowsError(try ApprovalMessage.decode(encoded + Data([0]), maximumBodyBytes: 1))
        XCTAssertThrowsError(try ApprovalMessage.decode(encoded, maximumBodyBytes: Int.max))
        XCTAssertThrowsError(try message.encode(maximumBodyBytes: 0))
    }
}
