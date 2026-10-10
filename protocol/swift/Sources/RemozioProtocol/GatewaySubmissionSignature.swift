import Foundation

public enum GatewaySubmissionSigningInput {
    public static func make(wireVersion: UInt64, kind: GatewaySubmissionKind, canonicalPayload: Data,
                            payloadLimits: CBORLimits, inputLimits: CBORLimits) throws -> Data {
        guard wireVersion == 1 else { throw SigningInputError.unsupportedVersion }
        let control = try GatewaySubmissionControl.decode(canonicalPayload, limits: payloadLimits)
        guard control.kind == kind else { throw GatewayTokenError.invalidControl }
        return try DeterministicCBOR.encode(.map([0: .text("dev.remozio.gateway"), 1: .unsigned(wireVersion),
            2: .unsigned(kind.rawValue), 3: .unsigned(kind.rawValue), 4: .bytes(canonicalPayload)]), limits: inputLimits)
    }
}

/// Select the Root key from protected registration. A submission credential cannot sign its own replacement or revocation.
public enum GatewaySubmissionSignature {
    public static func verify(signature: Data, publicKey: Data, wireVersion: UInt64, kind: GatewaySubmissionKind,
                              canonicalPayload: Data, payloadLimits: CBORLimits, inputLimits: CBORLimits) throws -> Bool {
        let input = try GatewaySubmissionSigningInput.make(wireVersion: wireVersion, kind: kind, canonicalPayload: canonicalPayload,
            payloadLimits: payloadLimits, inputLimits: inputLimits)
        return P256Verification.verify(signature: signature, publicKey: publicKey, input: input)
    }
}
