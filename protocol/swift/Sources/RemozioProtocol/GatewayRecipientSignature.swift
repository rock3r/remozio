import Foundation

public enum GatewayRecipientSigningInput {
    public static func make(wireVersion: UInt64, kind: GatewayRecipientKind, canonicalPayload: Data,
                            payloadLimits: CBORLimits, inputLimits: CBORLimits) throws -> Data {
        guard wireVersion == 1 else { throw SigningInputError.unsupportedVersion }
        switch kind {
        case .activation: _ = try GatewayMappingActivation.decode(canonicalPayload, limits: payloadLimits)
        case .phoneRevocation: _ = try GatewayPhoneRevocation.decode(canonicalPayload, limits: payloadLimits)
        }
        return try DeterministicCBOR.encode(.map([0: .text("dev.remozio.gateway"), 1: .unsigned(wireVersion),
            2: .unsigned(kind.rawValue), 3: .unsigned(kind.rawValue), 4: .bytes(canonicalPayload)]), limits: inputLimits)
    }
}

/// The expected operation is explicit. Select the root key from protected registration, never from control fields.
public enum GatewayRecipientSignature {
    public static func verify(signature: Data, publicKey: Data, wireVersion: UInt64, kind: GatewayRecipientKind,
                              canonicalPayload: Data, payloadLimits: CBORLimits, inputLimits: CBORLimits) throws -> Bool {
        let input = try GatewayRecipientSigningInput.make(wireVersion: wireVersion, kind: kind, canonicalPayload: canonicalPayload,
            payloadLimits: payloadLimits, inputLimits: inputLimits)
        return P256Verification.verify(signature: signature, publicKey: publicKey, input: input)
    }
}
