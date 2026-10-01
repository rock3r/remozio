import Foundation

/// History-only signature input. Parsing a batch and checking its expected scope are separate obligations.
public enum AuditHistoryStatusSigningInput {
    public static func make(wireVersion: UInt64, canonicalPayload: Data,
                            payloadLimits: CBORLimits, inputLimits: CBORLimits) throws -> Data {
        guard wireVersion == 1 else { throw SigningInputError.unsupportedVersion }
        guard case .map = try DeterministicCBOR.decode(canonicalPayload, limits: payloadLimits) else {
            throw SigningInputError.payloadMustBeMap
        }
        return try DeterministicCBOR.encode(.map([
            0: .text("dev.remozio.audit"), 1: .unsigned(wireVersion),
            2: .unsigned(2), 3: .unsigned(2), 4: .bytes(canonicalPayload),
        ]), limits: inputLimits)
    }
}

/// Uses the authority key selected from trusted enrollment, never a key from the batch.
public enum AuditHistoryStatusSignature {
    public static func verify(signature: Data, publicKey: Data, wireVersion: UInt64, canonicalPayload: Data,
                              payloadLimits: CBORLimits, inputLimits: CBORLimits) throws -> Bool {
        let input = try AuditHistoryStatusSigningInput.make(wireVersion: wireVersion, canonicalPayload: canonicalPayload,
            payloadLimits: payloadLimits, inputLimits: inputLimits)
        return P256Verification.verify(signature: signature, publicKey: publicKey, input: input)
    }
}
