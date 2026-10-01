import Foundation

/// This domain permits a token-possession probe, never recipient activation or an approval action.
public enum GatewayTokenCandidateSigningInput {
    public static func make(wireVersion: UInt64, canonicalPayload: Data,
                            payloadLimits: CBORLimits, inputLimits: CBORLimits) throws -> Data {
        guard wireVersion == 1 else { throw SigningInputError.unsupportedVersion }
        _ = try GatewayTokenCandidate.decode(canonicalPayload, limits: payloadLimits)
        return try DeterministicCBOR.encode(.map([
            0: .text("dev.remozio.gateway"), 1: .unsigned(wireVersion),
            2: .unsigned(1), 3: .unsigned(1), 4: .bytes(canonicalPayload),
        ]), limits: inputLimits)
    }
}

/// Select the root key from authenticated gateway registration, never from the incoming candidate.
public enum GatewayTokenCandidateSignature {
    public static func verify(signature: Data, publicKey: Data, wireVersion: UInt64, canonicalPayload: Data,
                              payloadLimits: CBORLimits, inputLimits: CBORLimits) throws -> Bool {
        let input = try GatewayTokenCandidateSigningInput.make(wireVersion: wireVersion, canonicalPayload: canonicalPayload,
            payloadLimits: payloadLimits, inputLimits: inputLimits)
        return P256Verification.verify(signature: signature, publicKey: publicKey, input: input)
    }
}
