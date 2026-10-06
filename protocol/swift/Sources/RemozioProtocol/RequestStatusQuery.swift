import Foundation

/// A read-only query inside an authenticated session. Only a signed status can establish the result.
public struct RequestStatusQuery: Equatable, Sendable {
    public static let maximumBytes = 64
    public let requestID: Data
    public init(requestID: Data) throws {
        guard requestID.count == 16 else { throw ChannelNegotiationError.rejected }
        self.requestID = requestID
    }
    public func encode() throws -> Data {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("request-state"), 2: .bytes(requestID)]), limits: Self.limits())
    }
    public static func decode(_ bytes: Data) throws -> RequestStatusQuery {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits()),
              Set(fields.keys) == Set(UInt64(0)...2), fields[0] == .unsigned(1),
              fields[1] == .text("request-state"), case .bytes(let requestID) = fields[2] else {
            throw ChannelNegotiationError.rejected
        }
        return try RequestStatusQuery(requestID: requestID)
    }
    private static func limits() throws -> CBORLimits {
        try CBORLimits(maxBytes: maximumBytes, maxDepth: 1, maxItems: 7)
    }
}
