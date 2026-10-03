import Foundation

/// Opaque application bytes. The consumer still verifies the exact message contract and authority.
public struct SessionEnvelope: Sendable, CustomStringConvertible {
    public let sessionID: Data
    public let sequence: UInt64
    public let payload: Data
    public init(sessionID: Data, sequence: UInt64, payload: Data) throws {
        guard sessionID.count == 32, !payload.isEmpty else { throw ChannelNegotiationError.rejected }
        self.sessionID = sessionID; self.sequence = sequence; self.payload = payload
    }
    public var description: String { "SessionEnvelope(redacted)" }
    public func encode(maximumPayloadBytes: Int) throws -> Data {
        guard payload.count <= maximumPayloadBytes else { throw ChannelNegotiationError.rejected }
        return try DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(sessionID), 2: .unsigned(sequence), 3: .bytes(payload),
        ]), limits: Self.limits(maximumPayloadBytes))
    }
    public static func decode(_ bytes: Data, maximumPayloadBytes: Int) throws -> SessionEnvelope {
        guard case let .map(fields) = try DeterministicCBOR.decode(bytes, limits: limits(maximumPayloadBytes)),
              Set(fields.keys) == Set(0...UInt64(3)), fields[0] == .unsigned(1),
              case let .bytes(session) = fields[1], case let .unsigned(sequence) = fields[2],
              case let .bytes(payload) = fields[3], payload.count <= maximumPayloadBytes else { throw ChannelNegotiationError.rejected }
        return try SessionEnvelope(sessionID: session, sequence: sequence, payload: payload)
    }
    private static func limits(_ maximum: Int) throws -> CBORLimits {
        guard (1...16_777_216).contains(maximum) else { throw ChannelNegotiationError.rejected }
        return try CBORLimits(maxBytes: maximum + 64, maxDepth: 2, maxItems: 12)
    }
}
