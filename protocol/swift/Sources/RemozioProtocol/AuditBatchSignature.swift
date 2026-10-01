import Foundation

/// Audit-only signature input. Parsing a batch and checking its expected scope are separate obligations.
public enum AuditBatchSigningInput {
    public static func make(wireVersion: UInt64, canonicalPayload: Data,
                            payloadLimits: CBORLimits, inputLimits: CBORLimits) throws -> Data {
        guard wireVersion == 1 else { throw SigningInputError.unsupportedVersion }
        guard case .map = try DeterministicCBOR.decode(canonicalPayload, limits: payloadLimits) else {
            throw SigningInputError.payloadMustBeMap
        }
        return try DeterministicCBOR.encode(.map([
            0: .text("dev.remozio.audit"), 1: .unsigned(wireVersion),
            2: .unsigned(1), 3: .unsigned(1), 4: .bytes(canonicalPayload),
        ]), limits: inputLimits)
    }
}

/// Uses the authority key selected from trusted enrollment, never a key from the batch.
public enum AuditBatchSignature {
    public static func verify(signature: Data, publicKey: Data, wireVersion: UInt64, canonicalPayload: Data,
                              payloadLimits: CBORLimits, inputLimits: CBORLimits) throws -> Bool {
        let input = try AuditBatchSigningInput.make(wireVersion: wireVersion, canonicalPayload: canonicalPayload,
            payloadLimits: payloadLimits, inputLimits: inputLimits)
        return P256Verification.verify(signature: signature, publicKey: publicKey, input: input)
    }
}
