import CryptoKit
import Foundation
import XCTest
import RemozioProtocol
@testable import RemozioCore

final class AuthorityTrustCodecTests: XCTestCase {
    private let mac = Data(repeating: 1, count: 16)
    private let account = Data(repeating: 2, count: 16)
    private let epoch = Data(repeating: 3, count: 16)
    private let revision = UUID(uuidString: "00112233-4455-6677-8899-AABBCCDDEEFF")!
    private func peer(_ phone: UInt8 = 4, key: Data? = nil, features: Set<UInt64> = [1, 9]) throws -> DirectApprovalPeer {
        try DirectApprovalPeer(scope: ChannelScope(macID: mac, accountID: account, phoneID: Data(repeating: phone, count: 16), enrollmentEpoch: epoch),
            transportPublicKey: key ?? P256.Signing.PrivateKey().publicKey.derRepresentation,
            requests: [ChannelRequestCapability(kind: 99, wireVersion: 2, schemaVersion: 3, features: features)],
            auditVersions: [1, 2], minimumEnvelopeVersion: 2, maximumPayloadBytes: 262_144)
    }
    private func snapshot(_ peers: [DirectApprovalPeer]) -> DirectApprovalTrust {
        DirectApprovalTrust(macID: mac, accountID: account, revision: revision, peers: peers)
    }
    private func decode(_ bytes: Data) throws -> DirectApprovalTrust {
        try AuthorityTrustCodec.decodeSnapshot(bytes, expectedMacID: mac, expectedAccountID: account)
    }
    private func modified(_ bytes: Data, _ body: (inout [UInt64: CBORValue]) -> Void) throws -> Data {
        let limits = try CBORLimits(maxBytes: 2_000_000, maxDepth: 10, maxItems: 200_000)
        guard case .map(var fields) = try DeterministicCBOR.decode(bytes, limits: limits) else { fatalError() }
        body(&fields)
        return try DeterministicCBOR.encode(.map(fields), limits: limits)
    }
    func testRoundTripPreservesAllTrustFieldsAndCanonicalOrder() throws {
        let a = try peer(8), b = try peer(4)
        let bytes = try AuthorityTrustCodec.encodeSnapshot(snapshot([a, b]))
        XCTAssertEqual(bytes, try AuthorityTrustCodec.encodeSnapshot(snapshot([b, a])))
        let decoded = try decode(bytes)
        XCTAssertEqual(decoded.macID, mac); XCTAssertEqual(decoded.accountID, account); XCTAssertEqual(decoded.revision, revision)
        XCTAssertEqual(decoded.peers.map(\.scope.phoneID), [b.scope.phoneID, a.scope.phoneID])
        let first = try XCTUnwrap(decoded.peers.first)
        XCTAssertEqual(first.transportPublicKey, b.transportPublicKey); XCTAssertEqual(first.scope, b.scope)
        XCTAssertEqual(first.minimumEnvelopeVersion, 2); XCTAssertEqual(first.maximumPayloadBytes, 262_144)
        XCTAssertEqual(first.auditVersions, [1, 2]); XCTAssertEqual(first.requests.count, 1)
        XCTAssertEqual(first.requests[0].kind, 99); XCTAssertEqual(first.requests[0].wireVersion, 2)
        XCTAssertEqual(first.requests[0].schemaVersion, 3); XCTAssertEqual(first.requests[0].features, [1, 9])
        XCTAssertTrue(try decode(AuthorityTrustCodec.encodeSnapshot(snapshot([]))).peers.isEmpty)
    }
    func testBindingRoundTripExcludesCapabilitiesAndRejectsWrongScope() throws {
        let p = try peer(features: Set(0..<64))
        let binding = AuthorityPeerBinding(peer: p, revision: revision)
        let bytes = try AuthorityTrustCodec.encodeBinding(binding)
        XCTAssertLessThan(bytes.count, 300)
        let result = try AuthorityTrustCodec.decodeBinding(bytes, expectedMacID: mac, expectedAccountID: account)
        XCTAssertEqual(result.scope, p.scope); XCTAssertEqual(result.transportPublicKey, p.transportPublicKey)
        XCTAssertEqual(result.revision, revision)
        XCTAssertThrowsError(try AuthorityTrustCodec.decodeBinding(bytes, expectedMacID: account, expectedAccountID: account))
        XCTAssertThrowsError(try AuthorityTrustCodec.decodeBinding(modified(bytes) { $0[0] = .unsigned(2) }, expectedMacID: mac, expectedAccountID: account))
        XCTAssertThrowsError(try AuthorityTrustCodec.decodeBinding(modified(bytes) { $0[2] = .bytes(Data([1])) }, expectedMacID: mac, expectedAccountID: account))
        XCTAssertThrowsError(try AuthorityTrustCodec.decodeBinding(modified(bytes) { $0[3] = .bytes(Data(count: 15)) }, expectedMacID: mac, expectedAccountID: account))
    }
    func testSnapshotRejectsVersionFieldsScopeAndTrailingData() throws {
        let bytes = try AuthorityTrustCodec.encodeSnapshot(snapshot([peer()]))
        for alteration: ([UInt64: CBORValue]) -> [UInt64: CBORValue] in [
            { var f = $0; f[0] = .unsigned(2); return f },
            { var f = $0; f[5] = .null; return f },
            { var f = $0; f.removeValue(forKey: 3); return f },
            { var f = $0; f[3] = .bytes(Data(count: 15)); return f },
        ] { XCTAssertThrowsError(try decode(modified(bytes) { $0 = alteration($0) })) }
        XCTAssertThrowsError(try AuthorityTrustCodec.decodeSnapshot(bytes, expectedMacID: mac, expectedAccountID: mac))
        XCTAssertThrowsError(try decode(bytes + Data([0])))
        XCTAssertThrowsError(try decode(Data(bytes.dropLast())))
    }
    func testDuplicatePhonesKeysAndNoncanonicalRowsAreRejected() throws {
        let a = try peer(), b = try peer(5)
        XCTAssertThrowsError(try AuthorityTrustCodec.encodeSnapshot(snapshot([a, a])))
        XCTAssertThrowsError(try AuthorityTrustCodec.encodeSnapshot(snapshot([a, peer(5, key: a.transportPublicKey)])))
        let bytes = try AuthorityTrustCodec.encodeSnapshot(snapshot([a, b]))
        XCTAssertThrowsError(try decode(modified(bytes) { fields in
            guard case .array(let rows) = fields[4] else { return }; fields[4] = .array(rows.reversed())
        }))
        XCTAssertThrowsError(try decode(modified(bytes) { fields in
            guard case .array(let rows) = fields[4] else { return }; fields[4] = .array([rows[0], rows[0]])
        }))
    }
    func testEncodingOversizeSnapshotThrowsInsteadOfTruncating() throws {
        let capabilities = try (0..<64).map { kind in
            try ChannelRequestCapability(kind: UInt64(kind), wireVersion: 1, schemaVersion: 1,
                features: Set((0..<64).map { UInt64.max - UInt64($0) }))
        }
        let peers = try (0..<40).map { phone -> DirectApprovalPeer in
            let original = try peer(UInt8(phone))
            return try DirectApprovalPeer(scope: original.scope, transportPublicKey: original.transportPublicKey,
                requests: capabilities, auditVersions: [], maximumPayloadBytes: 262_144)
        }
        XCTAssertThrowsError(try AuthorityTrustCodec.encodeSnapshot(snapshot(peers)))
        XCTAssertEqual(peers.count, 40)
    }
    func testOversizeAndMalformedCapabilitiesFailWithoutPartialSnapshot() throws {
        XCTAssertThrowsError(try decode(Data(count: AuthorityXPCChannel.maximumSnapshotBytes + 1)))
        XCTAssertThrowsError(try AuthorityTrustCodec.decodeBinding(Data(count: AuthorityXPCChannel.maximumBindingBytes + 1), expectedMacID: mac, expectedAccountID: account))
        let bytes = try AuthorityTrustCodec.encodeSnapshot(snapshot([peer()]))
        for replacement in [CBORValue.unsigned(0), .unsigned(UInt64.max)] {
            XCTAssertThrowsError(try decode(modified(bytes) { fields in
                guard case .array(let rows) = fields[4], case .array(var cells) = rows[0] else { return }
                cells[6] = replacement; fields[4] = .array([.array(cells)])
            }))
        }
        XCTAssertThrowsError(try decode(modified(bytes) { fields in
            guard case .array(let rows) = fields[4], case .array(var cells) = rows[0] else { return }
            cells[4] = .array([.unsigned(1), .unsigned(1)]); fields[4] = .array([.array(cells)])
        }))
    }
}
