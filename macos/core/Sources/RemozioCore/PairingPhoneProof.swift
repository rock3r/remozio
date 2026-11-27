import Foundation
import RemozioProtocol

/// Two separate proof purposes. No proof object grants enrollment authority.
struct PairingPhoneProof: Equatable, Sendable {
    let biometric: Data
    let decision: Data?

    init(biometric: Data, decision: Data? = nil) throws {
        guard biometric.count == 64, decision.map({ $0.count == 64 }) ?? true else {
            throw PairingEnrollmentError.invalidProof
        }
        self.biometric = biometric; self.decision = decision
    }

    func verify(in transcript: PairingTranscript, requiresDecisionProof: Bool) throws {
        guard requiresDecisionProof == (decision != nil),
              try transcript.verify(signature: biometric, publicKey: transcript.biometricKey.publicKey, purpose: .phoneBiometric) else {
            throw PairingEnrollmentError.invalidProof
        }
        if let decision, try !transcript.verify(signature: decision, publicKey: transcript.decisionKey.publicKey, purpose: .phoneDecision) {
            throw PairingEnrollmentError.invalidProof
        }
    }
}
