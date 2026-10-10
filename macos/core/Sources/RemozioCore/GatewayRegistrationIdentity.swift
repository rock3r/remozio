import CryptoKit
import Foundation
import RemozioProtocol

/// Pinned by protected administrator setup. Constructing this value does not authenticate that setup.
public struct GatewayRegistrationIdentity: Equatable, Sendable {
    public let ownerID: Data
    public let macID: Data
    public let accountID: Data
    public let gatewayID: Data
    public let lifecycleEpoch: Data
    public let rootPublicKey: Data
    public init(ownerID: Data, macID: Data, accountID: Data, gatewayID: Data, lifecycleEpoch: Data, rootPublicKey: Data) throws {
        guard [ownerID, macID, accountID, gatewayID, lifecycleEpoch].allSatisfy({ $0.count == 16 }),
              rootPublicKey.count == 65, rootPublicKey.first == 4,
              (try? P256.Signing.PublicKey(x963Representation: rootPublicKey)) != nil else { throw GatewayDatabaseError.invalidConfiguration }
        self.ownerID = ownerID; self.macID = macID; self.accountID = accountID; self.gatewayID = gatewayID
        self.lifecycleEpoch = lifecycleEpoch; self.rootPublicKey = rootPublicKey
    }
    func matches(_ trust: GatewayCandidateTrust) -> Bool {
        ownerID == trust.ownerID && macID == trust.macID && accountID == trust.accountID && gatewayID == trust.gatewayID &&
            lifecycleEpoch == trust.lifecycleEpoch && rootPublicKey == trust.rootPublicKey
    }
    func matches(_ binding: GatewayTokenBinding) -> Bool {
        ownerID == binding.ownerID && macID == binding.macID && accountID == binding.accountID &&
            gatewayID == binding.gatewayID && lifecycleEpoch == binding.lifecycleEpoch
    }
    func encode() throws -> Data {
        let fields = [ownerID, macID, accountID, gatewayID, lifecycleEpoch, rootPublicKey]
        return try DeterministicCBOR.encode(.map(Dictionary(uniqueKeysWithValues: fields.enumerated().map {
            (UInt64($0.offset), CBORValue.bytes($0.element))
        })), limits: CBORLimits(maxBytes: 512, maxDepth: 2, maxItems: 16))
    }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes,
                limits: CBORLimits(maxBytes: 512, maxDepth: 2, maxItems: 16)),
              Set(fields.keys) == Set(UInt64(0)...5) else { throw GatewayServiceError.invalidMessage }
        func blob(_ key: UInt64) throws -> Data {
            guard case .bytes(let value) = fields[key] else { throw GatewayServiceError.invalidMessage }; return value
        }
        return try Self(ownerID: blob(0), macID: blob(1), accountID: blob(2), gatewayID: blob(3), lifecycleEpoch: blob(4), rootPublicKey: blob(5))
    }
}
