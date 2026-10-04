import CryptoKit
import Foundation
import Security
import XCTest
import RemozioProtocol
@testable import RemozioCore

final class DirectPeerSnapshotTests: XCTestCase {
    private func fixture(_ name: String) throws -> Data {
        try Data(contentsOf: XCTUnwrap(Bundle.module.url(forResource: name, withExtension: nil, subdirectory: "Fixtures/tls")))
    }
    private func peer(_ name: String, phone: UInt8, mac: UInt8 = 1, account: UInt8 = 2) throws -> DirectApprovalPeer {
        let certificate = try XCTUnwrap(SecCertificateCreateWithData(nil, fixture(name) as CFData))
        let key = try XCTUnwrap(SecCertificateCopyKey(certificate))
        let point = try XCTUnwrap(SecKeyCopyExternalRepresentation(key, nil) as Data?)
        return try DirectApprovalPeer(scope: ChannelScope(macID: Data(repeating: mac, count: 16), accountID: Data(repeating: account, count: 16),
            phoneID: Data(repeating: phone, count: 16), enrollmentEpoch: Data(repeating: 4, count: 16)),
            transportPublicKey: P256.Signing.PublicKey(x963Representation: point).derRepresentation,
            requests: [], auditVersions: [], maximumPayloadBytes: 1024)
    }
    private func startDate(_ name: String) throws -> Date {
        let certificate = try XCTUnwrap(SecCertificateCreateWithData(nil, fixture(name) as CFData))
        return Date(timeIntervalSinceReferenceDate: CFDateGetAbsoluteTime(try XCTUnwrap(SecCertificateCopyNotValidBeforeDate(certificate))))
    }
    func testMultiplePhonesResolveOnlyTheirEnrolledScopesAndRenewalKeepsScope() throws {
        let first = try peer("peer.der", phone: 3), second = try peer("wrong.der", phone: 5)
        let snapshot = try DirectPeerSnapshot([first, second])
        for name in ["peer.der", "renewed.der"] {
            XCTAssertEqual(snapshot.peer(certificate: try fixture(name), at: try startDate(name))?.scope, first.scope)
        }
        XCTAssertEqual(snapshot.peer(certificate: try fixture("wrong.der"), at: try startDate("wrong.der"))?.scope, second.scope)
        XCTAssertEqual(snapshot.serviceName, "Remozio-" + String(repeating: "01", count: 16))
    }
    func testMissingPeerInvalidCertificateAndExpiredPinAreRejected() throws {
        let snapshot = try DirectPeerSnapshot([peer("peer.der", phone: 3)])
        for name in ["wrong.der", "rsa.der"] {
            XCTAssertNil(snapshot.peer(certificate: try fixture(name), at: try startDate(name)))
        }
        XCTAssertNil(snapshot.peer(certificate: Data(repeating: 0, count: 8193)))
        XCTAssertNil(snapshot.peer(certificate: Data([0x30, 0])))
        XCTAssertNil(snapshot.peer(certificate: try fixture("peer.der"), at: try startDate("peer.der").addingTimeInterval(-1)))
        XCTAssertNil(snapshot.peer(certificate: try fixture("peer.der"), at: Date(timeIntervalSinceReferenceDate: .nan)))
    }
    func testAmbiguousKeysPhonesAndMixedAuthoritiesAreRejected() throws {
        let first = try peer("peer.der", phone: 3)
        XCTAssertThrowsError(try DirectPeerSnapshot([]))
        for second in [try peer("peer.der", phone: 5), try peer("wrong.der", phone: 3),
                       try peer("wrong.der", phone: 5, mac: 9), try peer("wrong.der", phone: 5, account: 9)] {
            XCTAssertThrowsError(try DirectPeerSnapshot([first, second]))
        }
        XCTAssertThrowsError(try DirectPeerSnapshot(Array(repeating: first, count: 1025)))
    }
}
