import Foundation
import RemozioProtocol

/// A historical signed operation. Reading a receipt does not authorize delivery or restore an enrollment.
public struct GatewayRecipientReceipt: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    let control: GatewayStoredRecipient
    public let canonicalPayload: Data
    public let signature: Data
    public var kind: GatewayRecipientKind { control.kind }
    public var revision: UInt64 { control.revision }
    public var operationID: Data { control.operationID }
    public var phoneID: Data { control.phoneID }
    public var enrollmentEpoch: Data { control.enrollmentEpoch }
    public var description: String { "GatewayRecipientReceipt(redacted)" }
    public var debugDescription: String { description }
}

public struct GatewayRecipientApplication: Sendable {
    public let receipt: GatewayRecipientReceipt
    public let inserted: Bool
}

/// Verified stored mapping evidence. A provider send still requires current authority and a separate dispatch permit.
public struct GatewayActiveMapping: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let activation: GatewayMappingActivation
    public let receipt: GatewayRecipientReceipt
    let registrationToken: String
    public var description: String { "GatewayActiveMapping(redacted)" }
    public var debugDescription: String { description }
}

enum GatewayStoredRecipient: Sendable {
    case activation(GatewayMappingActivation)
    case revocation(GatewayPhoneRevocation)
    var kind: GatewayRecipientKind { switch self { case .activation: .activation; case .revocation: .phoneRevocation } }
    var revision: UInt64 { switch self { case .activation(let v): v.revision; case .revocation(let v): v.revision } }
    var operationID: Data { switch self { case .activation(let v): v.operationID; case .revocation(let v): v.operationID } }
    var issued: UInt64 { switch self { case .activation(let v): v.issuedAtUnixMillis; case .revocation(let v): v.issuedAtUnixMillis } }
    var expires: UInt64 { switch self { case .activation(let v): v.expiresAtUnixMillis; case .revocation(let v): v.expiresAtUnixMillis } }
    var phoneID: Data { switch self { case .activation(let v): v.binding.phoneID; case .revocation(let v): v.binding.phoneID } }
    var enrollmentEpoch: Data { switch self { case .activation(let v): v.binding.enrollmentEpoch; case .revocation(let v): v.binding.enrollmentEpoch } }
    func matches(_ identity: GatewayRegistrationIdentity) -> Bool {
        switch self {
        case .activation(let v): return identity.matches(v.binding)
        case .revocation(let v):
            let b = v.binding
            return b.ownerID == identity.ownerID && b.macID == identity.macID && b.accountID == identity.accountID &&
                b.gatewayID == identity.gatewayID && b.lifecycleEpoch == identity.lifecycleEpoch
        }
    }
    static func decode(_ data: Data, kind: GatewayRecipientKind, limits: CBORLimits) throws -> Self {
        switch kind {
        case .activation: .activation(try GatewayMappingActivation.decode(data, limits: limits))
        case .phoneRevocation: .revocation(try GatewayPhoneRevocation.decode(data, limits: limits))
        }
    }
}
