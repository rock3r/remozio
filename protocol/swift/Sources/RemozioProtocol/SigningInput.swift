import Foundation

public enum ApprovalMessageType: UInt64, CaseIterable, Sendable {
    case request = 1, decision = 2, status = 3
}

public enum SigningPurpose: UInt64, CaseIterable, Sendable {
    case issuedRequest = 1, cancellation = 2, oneTimeUI = 3, biometricAuthorization = 4, status = 5
}

public enum SigningInputError: String, Error, Equatable {
    case unsupportedVersion, incompatiblePurpose, payloadMustBeMap
}

/// Constructs signature input only. Verification must use the context expected by retained state.
public enum SigningInput {
    public static func make(
        wireVersion: UInt64,
        messageType: ApprovalMessageType,
        purpose: SigningPurpose,
        canonicalPayload: Data,
        payloadLimits: CBORLimits,
        inputLimits: CBORLimits
    ) throws -> Data {
        guard wireVersion == 1 else { throw SigningInputError.unsupportedVersion }
        switch (messageType, purpose) {
        case (.request, .issuedRequest), (.decision, .cancellation), (.decision, .oneTimeUI),
             (.decision, .biometricAuthorization), (.status, .status): break
        default: throw SigningInputError.incompatiblePurpose
        }
        guard case .map = try DeterministicCBOR.decode(canonicalPayload, limits: payloadLimits) else {
            throw SigningInputError.payloadMustBeMap
        }
        return try DeterministicCBOR.encode(.map([
            0: .text("dev.remozio.approval"),
            1: .unsigned(wireVersion),
            2: .unsigned(messageType.rawValue),
            3: .unsigned(purpose.rawValue),
            4: .bytes(canonicalPayload),
        ]), limits: inputLimits)
    }
}
