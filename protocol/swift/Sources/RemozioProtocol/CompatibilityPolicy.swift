import Foundation

public struct RequestContract: Hashable, Sendable {
    public let requestKind: RequestKind
    public let wireVersion: UInt64
    public let schemaVersion: UInt64

    public init(requestKind: RequestKind, wireVersion: UInt64, schemaVersion: UInt64) throws {
        guard wireVersion > 0, schemaVersion > 0 else { throw CompatibilityError.invalidPolicy }
        self.requestKind = requestKind
        self.wireVersion = wireVersion
        self.schemaVersion = schemaVersion
    }

}

public struct ContractCapabilities: Sendable {
    public let contracts: [RequestContract: Set<UInt64>]
    public init(contracts: [RequestContract: Set<UInt64>]) { self.contracts = contracts }
}

public struct ContractSelection: Equatable, Sendable {
    public let contract: RequestContract
    public let eligibleEnrollments: Set<UUID>
}

public enum CompatibilityError: String, Error, Equatable {
    case invalidPolicy, noSafeEnvelopeVersion, noCompatiblePhones
}

/// Selection over already-authenticated capabilities; this does not authenticate a handshake.
public enum CompatibilityPolicy {
    public static func envelopeVersion(
        local: Set<UInt64>, peer: Set<UInt64>, trustedMinimum: UInt64
    ) throws -> UInt64 {
        guard trustedMinimum > 0 else { throw CompatibilityError.invalidPolicy }
        guard let selected = local.intersection(peer).filter({ $0 >= trustedMinimum }).max() else {
            throw CompatibilityError.noSafeEnvelopeVersion
        }
        return selected
    }

    public static func requestContract(
        requestKind: RequestKind,
        authority: ContractCapabilities,
        authorizedEnrollments: [UUID: ContractCapabilities],
        trustedAllowedContracts: Set<RequestContract>,
        requiredFeatures: Set<UInt64>
    ) throws -> ContractSelection {
        var best: ContractSelection?
        for (contract, features) in authority.contracts {
            guard contract.requestKind == requestKind, trustedAllowedContracts.contains(contract), requiredFeatures.isSubset(of: features) else { continue }
            let eligible = Set(authorizedEnrollments.compactMap { enrollment, capabilities in
                guard let features = capabilities.contracts[contract], requiredFeatures.isSubset(of: features) else { return nil as UUID? }
                return enrollment
            })
            guard !eligible.isEmpty else { continue }
            if best == nil || eligible.count > best!.eligibleEnrollments.count ||
                (eligible.count == best!.eligibleEnrollments.count && (contract.wireVersion, contract.schemaVersion) > (best!.contract.wireVersion, best!.contract.schemaVersion)) {
                best = ContractSelection(contract: contract, eligibleEnrollments: eligible)
            }
        }
        guard let best else { throw CompatibilityError.noCompatiblePhones }
        return best
    }
}
