import CryptoKit
import Foundation
import RemozioProtocol

public enum GatewayWakeSubmissionError: Error, Equatable {
    case invalidMessage, unsupportedVersion, wrongScope, invalidSignature, unavailableCredential, unknownDelivery
}

/// Transport possession proof for one Root-registered opaque delivery. It contains no recipient or deadline.
public struct GatewayWakeSubmission: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let binding: GatewaySubmissionBinding
    public let credentialID: Data
    public let deliveryID: Data
    public let challenge: Data
    public var description: String { "GatewayWakeSubmission(redacted)" }
    public var debugDescription: String { description }

    public init(binding: GatewaySubmissionBinding, credentialID: Data, deliveryID: Data, challenge: Data) throws {
        guard credentialID.count == 16, deliveryID.count == 16, challenge.count == 32 else {
            throw GatewayWakeSubmissionError.invalidMessage
        }
        self.binding = binding; self.credentialID = credentialID; self.deliveryID = deliveryID; self.challenge = challenge
    }

    public func encode() throws -> Data {
        try DeterministicCBOR.encode(.map([0: .unsigned(1),
            1: .array([binding.ownerID, binding.macID, binding.accountID, binding.gatewayID, binding.lifecycleEpoch].map(CBORValue.bytes)),
            2: .bytes(credentialID), 3: .bytes(deliveryID), 4: .bytes(challenge)]), limits: Self.limits)
    }

    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits),
              Set(fields.keys) == Set(UInt64(0)...4), case .unsigned(let version) = fields[0] else {
            throw GatewayWakeSubmissionError.invalidMessage
        }
        guard version == 1 else { throw GatewayWakeSubmissionError.unsupportedVersion }
        guard case .array(let scope) = fields[1], scope.count == 5,
              case .bytes(let credential) = fields[2], case .bytes(let delivery) = fields[3], case .bytes(let challenge) = fields[4] else {
            throw GatewayWakeSubmissionError.invalidMessage
        }
        let ids = try scope.map { value -> Data in
            guard case .bytes(let id) = value, id.count == 16 else { throw GatewayWakeSubmissionError.invalidMessage }
            return id
        }
        let value = try Self(binding: GatewaySubmissionBinding(ownerID: ids[0], macID: ids[1], accountID: ids[2],
            gatewayID: ids[3], lifecycleEpoch: ids[4]), credentialID: credential, deliveryID: delivery, challenge: challenge)
        guard try value.encode() == bytes else { throw GatewayWakeSubmissionError.invalidMessage }
        return value
    }

    public func signingInput(wireVersion: UInt64 = 1) throws -> Data {
        guard wireVersion == 1 else { throw GatewayWakeSubmissionError.unsupportedVersion }
        return try DeterministicCBOR.encode(.map([0: .text("dev.remozio.gateway.wake"), 1: .unsigned(wireVersion),
            2: .unsigned(1), 3: .bytes(encode())]), limits: CBORLimits(maxBytes: 1024, maxDepth: 1, maxItems: 12))
    }

    /// The endpoint supplies its live challenge. The coordinator supplies current protected credential evidence.
    func authenticate(signature: Data, expectedChallenge: Data, registration: GatewayRegistrationIdentity,
                      credential: GatewayActiveSubmissionCredential) throws {
        guard expectedChallenge.count == 32, challenge == expectedChallenge else { throw GatewayWakeSubmissionError.invalidMessage }
        let scope = credential.receipt.control.binding
        guard binding == scope, scope.ownerID == registration.ownerID, scope.macID == registration.macID,
              scope.accountID == registration.accountID, scope.gatewayID == registration.gatewayID,
              scope.lifecycleEpoch == registration.lifecycleEpoch else { throw GatewayWakeSubmissionError.wrongScope }
        guard credentialID == credential.credentialID else { throw GatewayWakeSubmissionError.unavailableCredential }
        guard signature.count == 64,
              let key = try? P256.Signing.PublicKey(x963Representation: credential.publicKey),
              let signature = try? P256.Signing.ECDSASignature(rawRepresentation: signature),
              try key.isValidSignature(signature, for: signingInput()) else { throw GatewayWakeSubmissionError.invalidSignature }
    }

    static var limits: CBORLimits { get throws { try CBORLimits(maxBytes: 512, maxDepth: 2, maxItems: 24) } }
}
