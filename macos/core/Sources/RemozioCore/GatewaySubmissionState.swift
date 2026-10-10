import Foundation
import RemozioProtocol

/// Historical Root evidence. This receipt does not authorize a wake or restore a retired credential.
public struct GatewaySubmissionReceipt: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let control: GatewaySubmissionControl
    public let canonicalPayload: Data
    public let signature: Data
    public var description: String { "GatewaySubmissionReceipt(redacted)" }
    public var debugDescription: String { description }
}

public struct GatewaySubmissionApplication: Sendable {
    public let receipt: GatewaySubmissionReceipt
    public let inserted: Bool
}

/// Current credential evidence. Each submission must still recheck this state and its independent wake authority.
public struct GatewayActiveSubmissionCredential: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let receipt: GatewaySubmissionReceipt
    public var credentialID: Data { receipt.control.credentialID }
    public var publicKey: Data { receipt.control.publicKey! }
    public var description: String { "GatewayActiveSubmissionCredential(redacted)" }
    public var debugDescription: String { description }
}
