import Foundation

/// A phone report for Setup. Only the enrolled decision key can authenticate it.
public struct PhoneRepairNoticeFrame: Sendable, CustomStringConvertible {
    public enum Reason: UInt64, Sendable {
        case legacyPolicy = 1
        case biometricChanged = 2
    }

    /// Reserved for matching live command capabilities.
    public static let capability: UInt64 = 130
    public static let maximumBytes = 256

    public let scope: ChannelScope
    public let reason: Reason
    public let signature: Data

    public init(scope: ChannelScope, reason: Reason, signature: Data) throws {
        guard signature.count == 64 else { throw ChannelNegotiationError.rejected }
        self.scope = scope
        self.reason = reason
        self.signature = signature
    }

    public var description: String { "PhoneRepairNoticeFrame(redacted)" }

    public static func signingInput(scope: ChannelScope, reason: Reason) throws -> Data {
        try DeterministicCBOR.encode(.map([
            0: .text("dev.remozio.phone-repair-notice"),
            1: .unsigned(1),
            2: fields(scope),
            3: .unsigned(reason.rawValue)
        ]), limits: limits)
    }

    public func verify(decisionPublicKey: Data) throws -> Bool {
        try P256Verification.verify(signature: signature, publicKey: decisionPublicKey,
            input: Self.signingInput(scope: scope, reason: reason))
    }

    public func encode() throws -> Data {
        try DeterministicCBOR.encode(.map([
            0: .unsigned(1),
            1: .text("phone-repair-notice"),
            2: Self.fields(scope),
            3: .unsigned(reason.rawValue),
            4: .bytes(signature)
        ]), limits: Self.limits)
    }

    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits),
              Set(fields.keys) == Set(UInt64(0)...4), fields[0] == .unsigned(1),
              fields[1] == .text("phone-repair-notice"),
              case .array(let values) = fields[2], values.count == 4,
              case .bytes(let mac) = values[0], case .bytes(let account) = values[1],
              case .bytes(let phone) = values[2], case .bytes(let epoch) = values[3],
              case .unsigned(let tag) = fields[3], let reason = Reason(rawValue: tag),
              case .bytes(let signature) = fields[4] else { throw ChannelNegotiationError.rejected }
        let frame = try Self(scope: .init(macID: mac, accountID: account, phoneID: phone, enrollmentEpoch: epoch),
            reason: reason, signature: signature)
        guard try frame.encode() == bytes else { throw ChannelNegotiationError.rejected }
        return frame
    }

    private static func fields(_ scope: ChannelScope) -> CBORValue {
        .array([scope.macID, scope.accountID, scope.phoneID, scope.enrollmentEpoch].map(CBORValue.bytes))
    }

    private static let limits = try! CBORLimits(maxBytes: maximumBytes, maxDepth: 2, maxItems: 16)
}
