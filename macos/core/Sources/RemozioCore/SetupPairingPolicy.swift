import Foundation
import RemozioProtocol

/// The protected Setup owner selects the pairing policy before it reserves the account.
public enum SetupPairingPolicy: Equatable, Sendable {
    case disabled
    case v2WithDecisionProof(lanScope: PairingLANScope?)

    // An absent field preserves the original format. Null explicitly selects enabled loopback.
    var enabledScope: CBORValue? {
        switch self {
        case .disabled: nil
        case .v2WithDecisionProof(let scope): scope?.cborValue ?? .null
        }
    }

    static func decodeEnabledScope(_ value: CBORValue) throws -> Self {
        if value == .null { return .v2WithDecisionProof(lanScope: nil) }
        return try .v2WithDecisionProof(lanScope: PairingLANScope.decode(value))
    }

    func configuration(transportPublicKey: Data) throws -> AuthorityPairingSetupConfiguration {
        switch self {
        case .disabled:
            try .init(transportPublicKey: transportPublicKey)
        case .v2WithDecisionProof(let scope):
            try .init(transportPublicKey: transportPublicKey, v2ActivationEnabled: true, lanScope: scope,
                      decisionProofRequired: true)
        }
    }
}
