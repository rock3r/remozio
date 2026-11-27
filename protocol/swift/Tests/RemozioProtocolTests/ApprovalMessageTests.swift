import Foundation
import XCTest
@testable import RemozioProtocol

final class ApprovalMessageTests: XCTestCase {
    func testExactOpaqueBytesAndSignatureUseSharedWireEncoding() throws {
        let message = try ApprovalMessage(wireVersion: 1, type: .request, purpose: .issuedRequest,
            body: Data([1, 2, 3]), signature: Data(repeating: 0xaa, count: 64))
        let rows = try CommandCarrierVectors.load().approvalMessage.valid
        XCTAssertEqual(rows.count, 1)
        let row = try XCTUnwrap(rows.first)
        let encoded = try row.bytes()
        XCTAssertEqual(try message.encode(maximumBodyBytes: 3), encoded, row.name)
        let decoded = try ApprovalMessage.decode(encoded, maximumBodyBytes: 3)
        XCTAssertEqual(decoded.wireVersion, message.wireVersion)
        XCTAssertEqual(decoded.type, message.type)
        XCTAssertEqual(decoded.purpose, message.purpose)
        XCTAssertEqual(decoded.body, message.body)
        XCTAssertEqual(decoded.signature, message.signature)
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
        let rows = try CommandCarrierVectors.load().approvalMessage.invalid
        XCTAssertEqual(rows.count, 10)
        for row in rows {
            let bytes = try row.bytes()
            XCTAssertThrowsError(try ApprovalMessage.decode(bytes, maximumBodyBytes: 1), row.name)
        }
        XCTAssertThrowsError(try ApprovalMessage.decode(encoded, maximumBodyBytes: Int.max))
        XCTAssertThrowsError(try message.encode(maximumBodyBytes: 0))
    }
}
