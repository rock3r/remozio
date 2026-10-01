import CryptoKit
import Foundation

/// Verify with the public key and context selected from trusted enrollment and retained request state.
public enum ApprovalSignature {
    public static func verify(
        signature: Data,
        publicKey: Data,
        wireVersion: UInt64,
        messageType: ApprovalMessageType,
        purpose: SigningPurpose,
        canonicalPayload: Data,
        payloadLimits: CBORLimits,
        inputLimits: CBORLimits
    ) throws -> Bool {
        let input = try SigningInput.make(wireVersion: wireVersion, messageType: messageType, purpose: purpose,
            canonicalPayload: canonicalPayload, payloadLimits: payloadLimits, inputLimits: inputLimits)
        guard signature.count == 64, publicKey.count == 65, publicKey.first == 4 else { return false }
        guard let key = try? P256.Signing.PublicKey(x963Representation: publicKey),
              let value = try? P256.Signing.ECDSASignature(rawRepresentation: signature) else { return false }
        return key.isValidSignature(value, for: input)
    }
}
