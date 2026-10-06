import Foundation
import RemozioProtocol

/// A bounded authenticated-IPC query. A decision retains its phone signature; this container grants no authority.
public enum AuthorityRequestExchange {
    public static let maximumFrameBytes = 4096
    public static let maximumQueryBytes = 4352
    public struct Query: Sendable {
        public let requestID: Data
        public let decisionFrame: Data?
    }
    public static func encode(requestID: Data, decisionFrame: Data? = nil) throws -> Data {
        guard requestID.count == 16, decisionFrame == nil || (!decisionFrame!.isEmpty && decisionFrame!.count <= maximumFrameBytes) else {
            throw AuthorityXPCError.invalidMessage
        }
        return try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(requestID),
            2: decisionFrame.map(CBORValue.bytes) ?? .null]), limits: queryLimits())
    }
    public static func decode(_ bytes: Data) throws -> Query {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: queryLimits()),
              Set(fields.keys) == Set(UInt64(0)...2), fields[0] == .unsigned(1),
              case .bytes(let requestID) = fields[1] else { throw AuthorityXPCError.invalidMessage }
        let decision: Data?
        if fields[2] == .null { decision = nil }
        else if case .bytes(let frame) = fields[2] { decision = frame }
        else { throw AuthorityXPCError.invalidMessage }
        guard try encode(requestID: requestID, decisionFrame: decision) == bytes else { throw AuthorityXPCError.invalidMessage }
        return Query(requestID: requestID, decisionFrame: decision)
    }
    /// Checks routing and status structure, not the authority signature. The phone authenticates the exact signed body.
    static func validateResponse(_ bytes: Data, binding: AuthorityPeerBinding, requestID: Data) throws {
        guard !bytes.isEmpty, bytes.count <= maximumFrameBytes else { throw AuthorityXPCError.invalidMessage }
        let message = try ApprovalMessage.decode(bytes, maximumBodyBytes: maximumFrameBytes - ApprovalMessage.overheadBytes)
        let limits = try CBORLimits(maxBytes: maximumFrameBytes, maxDepth: 4, maxItems: 64)
        let status = try RequestStatusPayload.decode(message.body, limits: limits)
        guard message.type == .status, message.purpose == .status, status.macID == binding.scope.macID,
              status.accountID == binding.scope.accountID, status.requestID == requestID else {
            throw AuthorityXPCError.invalidMessage
        }
    }
    private static func queryLimits() throws -> CBORLimits {
        try CBORLimits(maxBytes: maximumQueryBytes, maxDepth: 2, maxItems: 8)
    }
}
