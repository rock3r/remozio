import CryptoKit
import Foundation
import Security
import XCTest
@testable import RemozioCore

final class PinnedTLSPeerTests: XCTestCase {
    private func fixture(_ name: String) throws -> Data {
        try Data(contentsOf: XCTUnwrap(Bundle.module.url(forResource: name, withExtension: nil, subdirectory: "Fixtures/tls")))
    }

    private func interval(_ data: Data) throws -> (Date, Date) {
        let certificate = try XCTUnwrap(SecCertificateCreateWithData(nil, data as CFData))
        let before = try XCTUnwrap(SecCertificateCopyNotValidBeforeDate(certificate))
        let after = try XCTUnwrap(SecCertificateCopyNotValidAfterDate(certificate))
        return (Date(timeIntervalSinceReferenceDate: CFDateGetAbsoluteTime(before)),
                Date(timeIntervalSinceReferenceDate: CFDateGetAbsoluteTime(after)))
    }

    func testCertificateRenewalKeepsTheEnrolledKey() throws {
        let peer = try PinnedTLSPeer(subjectPublicKeyInfo: fixture("peer.spki"))
        let original = try fixture("peer.der")
        let renewed = try fixture("renewed.der")
        XCTAssertNotEqual(original, renewed)
        for data in [original, renewed] {
            let (before, _) = try interval(data)
            XCTAssertTrue(peer.accepts(certificate: data, at: before.addingTimeInterval(1)))
        }
    }

    func testValidityBoundariesAreInclusiveAndRejectInvalidTime() throws {
        let peer = try PinnedTLSPeer(subjectPublicKeyInfo: fixture("peer.spki"))
        let data = try fixture("peer.der")
        let (before, after) = try interval(data)
        XCTAssertTrue(peer.accepts(certificate: data, at: before))
        XCTAssertTrue(peer.accepts(certificate: data, at: after))
        for date in [before.addingTimeInterval(-1), after.addingTimeInterval(1),
                     Date(timeIntervalSinceReferenceDate: .nan), Date(timeIntervalSinceReferenceDate: .infinity)] {
            XCTAssertFalse(peer.accepts(certificate: data, at: date))
        }
    }

    func testRejectsOtherKeysAndMalformedCertificates() throws {
        let peer = try PinnedTLSPeer(subjectPublicKeyInfo: fixture("peer.spki"))
        for name in ["wrong.der", "rsa.der"] {
            let data = try fixture(name)
            let (before, _) = try interval(data)
            XCTAssertFalse(peer.accepts(certificate: data, at: before.addingTimeInterval(1)))
        }
        for data in [Data(), Data([0x30, 0]), Data(repeating: 0, count: 8_193), try fixture("peer.der").prefix(40)] {
            XCTAssertFalse(peer.accepts(certificate: data))
        }
    }

    func testRejectsNoncanonicalAndWrongCurvePins() throws {
        let pin = try fixture("peer.spki")
        let badPins = [Data(), pin + Data([0]), Data(pin.dropLast()), Data(repeating: 0, count: 91),
                       P384.Signing.PrivateKey().publicKey.derRepresentation]
        for data in badPins { XCTAssertThrowsError(try PinnedTLSPeer(subjectPublicKeyInfo: data)) }
    }

    func testTrustAdapterUsesTheLeafRatherThanAnIntermediate() throws {
        let peer = try PinnedTLSPeer(subjectPublicKeyInfo: fixture("peer.spki"))
        let data = try fixture("peer.der")
        let right = try XCTUnwrap(SecCertificateCreateWithData(nil, data as CFData))
        let wrong = try XCTUnwrap(SecCertificateCreateWithData(nil, fixture("wrong.der") as CFData))
        let (before, _) = try interval(data)
        for (chain, accepted) in [([right, wrong], true), ([wrong, right], false)] {
            var trust: SecTrust?
            XCTAssertEqual(SecTrustCreateWithCertificates(chain as CFArray, SecPolicyCreateBasicX509(), &trust), errSecSuccess)
            XCTAssertEqual(peer.accepts(try XCTUnwrap(trust), at: before.addingTimeInterval(1)), accepted)
        }
    }
}
