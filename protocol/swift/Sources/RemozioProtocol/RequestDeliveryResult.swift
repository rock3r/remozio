import Foundation

/// An advisory capture refusal on the live enrolled connection. It carries no request state.
public struct RequestDeliveryResult: Equatable, Sendable, CustomStringConvertible {
    public enum Reason: UInt64, Sendable { case unreadableCapture = 1, captureLimit = 2 }

    /// Negotiated only in the live command offer. This is separate from issued request requirements.
    public static let capability: UInt64 = 128
    public static let maximumBytes = 128
    public let requestID: Data
    public let requestDigest: Data
    public let reason: Reason

    public init(requestID: Data, requestDigest: Data, reason: Reason) throws {
        guard requestID.count == 16, requestDigest.count == 32 else { throw ChannelNegotiationError.rejected }
        self.requestID = requestID
        self.requestDigest = requestDigest
        self.reason = reason
    }

    public var description: String { "RequestDeliveryResult(redacted)" }

    public func encode() throws -> Data {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("request-delivery-result"),
            2: .bytes(requestID), 3: .bytes(requestDigest), 4: .unsigned(reason.rawValue)]), limits: Self.limits)
    }

    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits),
              Set(fields.keys) == Set(UInt64(0)...4), fields[0] == .unsigned(1),
              fields[1] == .text("request-delivery-result"), case .bytes(let id) = fields[2],
              case .bytes(let digest) = fields[3], case .unsigned(let tag) = fields[4],
              let reason = Reason(rawValue: tag) else { throw ChannelNegotiationError.rejected }
        let result = try Self(requestID: id, requestDigest: digest, reason: reason)
        guard try result.encode() == bytes else { throw ChannelNegotiationError.rejected }
        return result
    }

    private static let limits = try! CBORLimits(maxBytes: maximumBytes, maxDepth: 1, maxItems: 11)
}
