#if os(Linux)
import Crypto
#else
import CryptoKit
#endif
import Foundation
import XCTest
@testable import RemozioProtocol

final class PhoneRepairNoticeFrameTests: XCTestCase {
    private func scope(epoch: UInt8 = 4) throws -> ChannelScope {
        try .init(macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16),
            phoneID: Data(repeating: 3, count: 16), enrollmentEpoch: Data(repeating: epoch, count: 16))
    }

    func testCanonicalNoticeAuthenticatesScopeAndReason() throws {
        let selected = try scope()
        let decision = P256.Signing.PrivateKey()
        let signature = try decision.signature(for: PhoneRepairNoticeFrame.signingInput(scope: selected,
            reason: .biometricChanged)).rawRepresentation
        let frame = try PhoneRepairNoticeFrame(scope: selected, reason: .biometricChanged, signature: signature)
        let bytes = try frame.encode()
        let decoded = try PhoneRepairNoticeFrame.decode(bytes)
        XCTAssertEqual(try decoded.encode(), bytes)
        XCTAssertEqual(decoded.scope, selected)
        XCTAssertEqual(decoded.reason, .biometricChanged)
        XCTAssertTrue(try decoded.verify(decisionPublicKey: decision.publicKey.x963Representation))
        XCTAssertFalse(try decoded.verify(decisionPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation))
        for altered in [try PhoneRepairNoticeFrame(scope: scope(epoch: 5), reason: .biometricChanged, signature: signature),
                        try PhoneRepairNoticeFrame(scope: selected, reason: .legacyPolicy, signature: signature)] {
            XCTAssertFalse(try altered.verify(decisionPublicKey: decision.publicKey.x963Representation))
        }
    }

    func testSharedRepairNoticeVectors() throws {
        let vectors = try CommandCarrierVectors.load().phoneRepairNotice
        let key = try XCTUnwrap(vectors.decisionKey.first).bytes()
        let reasons: [PhoneRepairNoticeFrame.Reason] = [.legacyPolicy, .biometricChanged]
        XCTAssertEqual(vectors.valid.count, reasons.count)
        XCTAssertEqual(vectors.signingInput.count, reasons.count)
        let expectedScope = try scope()
        for (index, reason) in reasons.enumerated() {
            let bytes = try vectors.valid[index].bytes()
            let frame = try PhoneRepairNoticeFrame.decode(bytes)
            XCTAssertEqual(try frame.encode(), bytes)
            XCTAssertEqual(frame.scope, expectedScope)
            XCTAssertEqual(frame.reason, reason)
            XCTAssertEqual(try PhoneRepairNoticeFrame.signingInput(scope: expectedScope, reason: reason),
                try vectors.signingInput[index].bytes())
            XCTAssertTrue(try frame.verify(decisionPublicKey: key))
        }
        for vector in vectors.invalid {
            XCTAssertThrowsError(try PhoneRepairNoticeFrame.decode(vector.bytes()), vector.name)
        }
    }
}
