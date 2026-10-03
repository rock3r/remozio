import Foundation
import XCTest
@testable import RemozioProtocol

final class ChannelNegotiationTests: XCTestCase {
    private struct Row: Decodable { let name: String; let hex: String }
    private struct Vectors: Decodable {
        let phone: String; let mac: String; let sessionID: String; let tamperedMacOffers: [String]
        let phoneConfirmation: String; let macConfirmation: String; let invalid: [Row]
    }
    private func vectors() throws -> Vectors {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        return try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: root.appendingPathComponent("vectors/channel-negotiation-v1.json")))
    }
    private func hex(_ value: String) -> Data {
        Data(stride(from: 0, to: value.count, by: 2).map { offset in
            let start = value.index(value.startIndex, offsetBy: offset)
            return UInt8(value[start..<value.index(start, offsetBy: 2)], radix: 16)!
        })
    }
    private func pair() throws -> (ChannelNegotiation, ChannelNegotiation) {
        let v = try vectors()
        let phone = try ChannelNegotiation(local: ChannelOffer.decode(hex(v.phone)), trustedMinimum: 1)
        let mac = try ChannelNegotiation(local: ChannelOffer.decode(hex(v.mac)), trustedMinimum: 1)
        let p = try phone.offer(), m = try mac.offer()
        try phone.receiveOffer(m); try mac.receiveOffer(p)
        return (phone, mac)
    }
    func testSharedOffersAndOpaqueFutureKindsRoundTrip() throws {
        let v = try vectors()
        for bytes in [hex(v.phone), hex(v.mac)] { XCTAssertEqual(try ChannelOffer.decode(bytes).encode(), bytes) }
        XCTAssertEqual(try ChannelOffer.decode(hex(v.phone)).requests[1].kind, 99)
        XCTAssertTrue(try ChannelOffer.decode(hex(v.mac)).auditVersions.isEmpty)
    }
    func testSharedTranscriptAndConfirmationsAgree() throws {
        let v = try vectors(), (phone, mac) = try pair()
        XCTAssertThrowsError(try phone.confirmed()); XCTAssertThrowsError(try mac.confirmed())
        let p = try phone.confirmation(); XCTAssertEqual(p, hex(v.phoneConfirmation))
        try mac.receiveConfirmation(p); XCTAssertThrowsError(try mac.confirmed())
        let m = try mac.confirmation(); XCTAssertEqual(m, hex(v.macConfirmation))
        try phone.receiveConfirmation(m)
        for owner in [phone, mac] {
            XCTAssertEqual(try owner.confirmed().envelopeVersion, 3)
            XCTAssertEqual(try owner.confirmed().sessionID, hex(v.sessionID))
            owner.close(); XCTAssertThrowsError(try owner.confirmed())
        }
    }
    func testMalformedAndNoncanonicalOffersFail() throws {
        for row in try vectors().invalid { XCTAssertThrowsError(try ChannelOffer.decode(hex(row.hex)), row.name) }
        XCTAssertThrowsError(try ChannelOffer.decode(Data(repeating: 0, count: 65_537)))
    }
    func testReflectionWrongScopeAndReusedNonceCloseTheOwner() throws {
        let v = try vectors(), local = try ChannelOffer.decode(hex(v.phone)), remote = try ChannelOffer.decode(hex(v.mac))
        let zero = Data(repeating: 0, count: 16)
        let wrongScope = try ChannelScope(macID: zero, accountID: zero, phoneID: zero, enrollmentEpoch: zero)
        let bad = [local,
            try ChannelOffer(role: remote.role, scope: wrongScope, nonce: remote.nonce, envelopeVersions: remote.envelopeVersions,
                requests: remote.requests, auditVersions: remote.auditVersions),
            try ChannelOffer(role: remote.role, scope: remote.scope, nonce: local.nonce, envelopeVersions: remote.envelopeVersions,
                requests: remote.requests, auditVersions: remote.auditVersions)]
        for value in bad {
            let owner = try ChannelNegotiation(local: local, trustedMinimum: 1); _ = try owner.offer()
            XCTAssertThrowsError(try owner.receiveOffer(value.encode()))
            XCTAssertThrowsError(try owner.receiveOffer(remote.encode()))
        }
    }
    func testWrongConfirmationAndCrossSessionReplayFailClosed() throws {
        let v = try vectors()
        var changed = hex(v.macConfirmation); changed[changed.count - 1] ^= 1
        for wrong in [hex(v.phoneConfirmation), changed, Data(repeating: 0, count: 129)] {
            let (phone, _) = try pair(); _ = try phone.confirmation()
            XCTAssertThrowsError(try phone.receiveConfirmation(wrong))
            XCTAssertThrowsError(try phone.receiveConfirmation(hex(v.macConfirmation)))
        }
        let local = try ChannelOffer.decode(hex(v.phone))
        let fresh = try ChannelOffer(role: local.role, scope: local.scope, nonce: Data(repeating: 8, count: 32),
            envelopeVersions: local.envelopeVersions, requests: local.requests, auditVersions: local.auditVersions)
        let owner = try ChannelNegotiation(local: fresh, trustedMinimum: 1)
        _ = try owner.offer(); try owner.receiveOffer(hex(v.mac)); _ = try owner.confirmation()
        XCTAssertThrowsError(try owner.receiveConfirmation(hex(v.macConfirmation)))
    }
    func testOrderingDuplicatesAndLocalFloorAreEnforced() throws {
        let v = try vectors(), (phone, mac) = try pair()
        XCTAssertThrowsError(try mac.confirmation()); XCTAssertThrowsError(try mac.receiveConfirmation(phone.confirmation()))
        let (p2, _) = try pair(); XCTAssertThrowsError(try p2.receiveOffer(hex(v.mac))); XCTAssertThrowsError(try p2.confirmation())
        let p3 = try ChannelNegotiation(local: ChannelOffer.decode(hex(v.phone)), trustedMinimum: 4); _ = try p3.offer()
        XCTAssertThrowsError(try p3.receiveOffer(hex(v.mac))); XCTAssertThrowsError(try p3.confirmation())
        let p4 = try ChannelNegotiation(local: ChannelOffer.decode(hex(v.phone)), trustedMinimum: 1)
        XCTAssertThrowsError(try p4.receiveOffer(hex(v.mac))); XCTAssertThrowsError(try p4.offer())
    }
    func testAlteredCapabilitiesCannotProduceMatchingConfirmation() throws {
        let v = try vectors()
        for changed in v.tamperedMacOffers {
            let phone = try ChannelNegotiation(local: ChannelOffer.decode(hex(v.phone)), trustedMinimum: 1)
            let mac = try ChannelNegotiation(local: ChannelOffer.decode(hex(v.mac)), trustedMinimum: 1)
            let p = try phone.offer(); _ = try mac.offer()
            try phone.receiveOffer(hex(changed)); try mac.receiveOffer(p)
            XCTAssertThrowsError(try mac.receiveConfirmation(phone.confirmation()))
            XCTAssertThrowsError(try mac.confirmed())
        }
    }
    func testValueSemanticsAndDescriptions() throws {
        let base = try ChannelOffer.decode(hex(vectors().phone))
        var nonce = base.nonce, versions: Set<UInt64> = [1]
        let value = try ChannelOffer(role: base.role, scope: base.scope, nonce: nonce, envelopeVersions: versions,
            requests: base.requests, auditVersions: [])
        nonce[0] ^= 1; versions.removeAll()
        XCTAssertEqual(value.nonce, base.nonce); XCTAssertEqual(value.envelopeVersions, [1])
        XCTAssertEqual(value.description, "ChannelOffer(redacted)")
    }
}
