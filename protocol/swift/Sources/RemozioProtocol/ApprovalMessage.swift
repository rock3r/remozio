import Foundation

/// Routing claims and exact signed bytes. Parsing this carrier does not authenticate its contents.
public struct ApprovalMessage: Sendable, CustomStringConvertible {
    public static let overheadBytes = 128
    public let wireVersion: UInt64
    public let type: ApprovalMessageType
    public let purpose: SigningPurpose
    public let body: Data
    public let signature: Data
    public init(wireVersion: UInt64, type: ApprovalMessageType, purpose: SigningPurpose, body: Data, signature: Data) throws {
        guard wireVersion == 1, !body.isEmpty, signature.count == 64 else { throw ChannelNegotiationError.rejected }
        switch (type, purpose) {
        case (.request, .issuedRequest), (.status, .status), (.decision, .cancellation),
             (.decision, .oneTimeUI), (.decision, .biometricAuthorization): break
        default: throw SigningInputError.incompatiblePurpose
        }
        self.wireVersion = wireVersion; self.type = type; self.purpose = purpose; self.body = body; self.signature = signature
    }
    public var description: String { "ApprovalMessage(redacted)" }
    public func encode(maximumBodyBytes: Int) throws -> Data {
        guard body.count <= maximumBodyBytes else { throw ChannelNegotiationError.rejected }
        return try DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .unsigned(wireVersion), 2: .unsigned(type.rawValue), 3: .unsigned(purpose.rawValue),
            4: .bytes(body), 5: .bytes(signature),
        ]), limits: Self.limits(maximumBodyBytes))
    }
    public static func decode(_ bytes: Data, maximumBodyBytes: Int) throws -> ApprovalMessage {
        guard case let .map(fields) = try DeterministicCBOR.decode(bytes, limits: limits(maximumBodyBytes)),
              Set(fields.keys) == Set(0...UInt64(5)), fields[0] == .unsigned(1),
              case let .unsigned(wire) = fields[1], case let .unsigned(typeTag) = fields[2],
              let type = ApprovalMessageType(rawValue: typeTag), case let .unsigned(purposeTag) = fields[3],
              let purpose = SigningPurpose(rawValue: purposeTag), case let .bytes(body) = fields[4],
              case let .bytes(signature) = fields[5], body.count <= maximumBodyBytes else { throw ChannelNegotiationError.rejected }
        return try ApprovalMessage(wireVersion: wire, type: type, purpose: purpose, body: body, signature: signature)
    }
    private static func limits(_ maximum: Int) throws -> CBORLimits {
        guard (1...(16_777_216 - overheadBytes)).contains(maximum) else { throw ChannelNegotiationError.rejected }
        return try CBORLimits(maxBytes: maximum + overheadBytes, maxDepth: 2, maxItems: 16)
    }
}
