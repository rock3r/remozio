import Foundation
import RemozioProtocol

public enum AuthorityTrustCodecError: Error { case invalidMessage }

/// Transport admission metadata. This is never an approval or an execution permit.
public struct AuthorityPeerBinding: Sendable {
    public let scope: ChannelScope
    public let transportPublicKey: Data
    public let revision: UUID
    public init(peer: DirectApprovalPeer, revision: UUID) {
        scope = peer.scope; transportPublicKey = peer.transportPublicKey; self.revision = revision
    }
    init(scope: ChannelScope, transportPublicKey: Data, revision: UUID) throws {
        _ = try PinnedTLSPeer(subjectPublicKeyInfo: transportPublicKey)
        self.scope = scope; self.transportPublicKey = transportPublicKey; self.revision = revision
    }
}

/// Versioned local IPC data. Decode only on an authenticated authority connection, with locally trusted scope IDs.
public enum AuthorityTrustCodec {
    public static func encodeSnapshot(_ trust: DirectApprovalTrust) throws -> Data {
        try validate(trust, mac: trust.macID, account: trust.accountID)
        let peers = trust.peers.sorted { $0.scope.phoneID.lexicographicallyPrecedes($1.scope.phoneID) }
        return try DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(trust.macID), 2: .bytes(trust.accountID),
            3: .bytes(uuidBytes(trust.revision)), 4: .array(peers.map(peerValue)),
        ]), limits: snapshotLimits())
    }
    public static func decodeSnapshot(_ bytes: Data, expectedMacID: Data, expectedAccountID: Data) throws -> DirectApprovalTrust {
        let fields = try map(DeterministicCBOR.decode(bytes, limits: snapshotLimits()), keys: 5)
        guard fields[0] == .unsigned(1), case .array(let rows) = fields[4], rows.count <= 1024 else { throw invalid }
        let mac = try data(fields[1]), account = try data(fields[2])
        guard mac == expectedMacID, account == expectedAccountID else { throw invalid }
        let trust = try DirectApprovalTrust(macID: mac, accountID: account, revision: uuid(data(fields[3])),
            peers: rows.map { try peer($0, mac: mac, account: account) })
        try validate(trust, mac: expectedMacID, account: expectedAccountID)
        guard try encodeSnapshot(trust) == bytes else { throw invalid }
        return trust
    }
    public static func encodeBinding(_ binding: AuthorityPeerBinding) throws -> Data {
        try DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: scopeValue(binding.scope), 2: .bytes(binding.transportPublicKey),
            3: .bytes(uuidBytes(binding.revision)),
        ]), limits: bindingLimits())
    }
    public static func decodeBinding(_ bytes: Data, expectedMacID: Data, expectedAccountID: Data) throws -> AuthorityPeerBinding {
        let fields = try map(DeterministicCBOR.decode(bytes, limits: bindingLimits()), keys: 4)
        guard fields[0] == .unsigned(1), case .array(let scope) = fields[1], scope.count == 4 else { throw invalid }
        let parsed = try ChannelScope(macID: data(scope[0]), accountID: data(scope[1]), phoneID: data(scope[2]), enrollmentEpoch: data(scope[3]))
        guard parsed.macID == expectedMacID, parsed.accountID == expectedAccountID else { throw invalid }
        let result = try AuthorityPeerBinding(scope: parsed, transportPublicKey: data(fields[2]), revision: uuid(data(fields[3])))
        guard try encodeBinding(result) == bytes else { throw invalid }
        return result
    }
    private static var invalid: AuthorityTrustCodecError { .invalidMessage }
    private static func snapshotLimits() throws -> CBORLimits {
        try CBORLimits(maxBytes: AuthorityXPCChannel.maximumSnapshotBytes, maxDepth: 8, maxItems: 131_072)
    }
    private static func bindingLimits() throws -> CBORLimits {
        try CBORLimits(maxBytes: AuthorityXPCChannel.maximumBindingBytes, maxDepth: 3, maxItems: 16)
    }
    private static func validate(_ trust: DirectApprovalTrust, mac: Data, account: Data) throws {
        guard mac.count == 16, account.count == 16, trust.macID == mac, trust.accountID == account,
              trust.peers.count <= 1024, trust.peers.allSatisfy({ $0.scope.macID == mac && $0.scope.accountID == account }) else { throw invalid }
        if !trust.peers.isEmpty { _ = try DirectPeerSnapshot(trust.peers) }
    }
    private static func scopeValue(_ scope: ChannelScope) -> CBORValue {
        .array([scope.macID, scope.accountID, scope.phoneID, scope.enrollmentEpoch].map(CBORValue.bytes))
    }
    private static func peerValue(_ peer: DirectApprovalPeer) -> CBORValue {
        let requests = peer.requests.sorted { [$0.kind, $0.wireVersion, $0.schemaVersion].lexicographicallyPrecedes([$1.kind, $1.wireVersion, $1.schemaVersion]) }
        return .array([.bytes(peer.scope.phoneID), .bytes(peer.scope.enrollmentEpoch), .bytes(peer.transportPublicKey),
            .array(requests.map { .array([.unsigned($0.kind), .unsigned($0.wireVersion), .unsigned($0.schemaVersion), numbers($0.features)]) }),
            numbers(peer.auditVersions), .unsigned(peer.minimumEnvelopeVersion), .unsigned(UInt64(peer.maximumPayloadBytes))])
    }
    private static func peer(_ row: CBORValue, mac: Data, account: Data) throws -> DirectApprovalPeer {
        guard case .array(let values) = row, values.count == 7, case .array(let requests) = values[3], requests.count <= 64,
              case .unsigned(let floor) = values[5], case .unsigned(let maximum) = values[6], maximum <= 16_777_216 else { throw invalid }
        let capabilities = try requests.map { value -> ChannelRequestCapability in
            guard case .array(let cells) = value, cells.count == 4,
                  case .unsigned(let kind) = cells[0], case .unsigned(let wire) = cells[1], case .unsigned(let schema) = cells[2] else { throw invalid }
            return try ChannelRequestCapability(kind: kind, wireVersion: wire, schemaVersion: schema, features: numberSet(cells[3], maximum: 64))
        }
        return try DirectApprovalPeer(scope: ChannelScope(macID: mac, accountID: account, phoneID: data(values[0]), enrollmentEpoch: data(values[1])),
            transportPublicKey: data(values[2]), requests: capabilities, auditVersions: numberSet(values[4], maximum: 16),
            minimumEnvelopeVersion: floor, maximumPayloadBytes: Int(maximum))
    }
    private static func map(_ value: CBORValue, keys: Int) throws -> [UInt64: CBORValue] {
        guard case .map(let fields) = value, Set(fields.keys) == Set((0..<keys).map(UInt64.init)) else { throw invalid }
        return fields
    }
    private static func data(_ value: CBORValue?) throws -> Data {
        guard case .bytes(let bytes) = value else { throw invalid }; return bytes
    }
    private static func numbers(_ values: Set<UInt64>) -> CBORValue { .array(values.sorted().map(CBORValue.unsigned)) }
    private static func numberSet(_ value: CBORValue, maximum: Int) throws -> Set<UInt64> {
        guard case .array(let values) = value, values.count <= maximum else { throw invalid }
        let numbers = try values.map { value -> UInt64 in guard case .unsigned(let number) = value else { throw invalid }; return number }
        guard numbers == numbers.sorted(), Set(numbers).count == numbers.count else { throw invalid }
        return Set(numbers)
    }
    private static func uuidBytes(_ value: UUID) -> Data { withUnsafeBytes(of: value.uuid) { Data($0) } }
    private static func uuid(_ bytes: Data) throws -> UUID {
        guard bytes.count == 16 else { throw invalid }
        var value = UUID().uuid
        _ = withUnsafeMutableBytes(of: &value) { bytes.copyBytes(to: $0) }
        return UUID(uuid: value)
    }
}
