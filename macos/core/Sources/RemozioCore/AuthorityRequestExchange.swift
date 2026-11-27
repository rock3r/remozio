import CryptoKit
import Foundation
import RemozioProtocol

/// A bounded authenticated IPC query. A decision retains its phone signature.
public enum AuthorityRequestExchange {
    public static let version: UInt64 = 2
    public static let maximumFrameBytes = 4096
    public static let maximumQueryBytes = 4352

    public struct Query: Sendable {
        public let requestID: Data
        public let decisionFrame: Data?
        public let refusalAttempt: DecisionRefusalFrame.Attempt?
    }

    public static func encode(requestID: Data, decisionFrame: Data? = nil,
                              refusalAttempt: DecisionRefusalFrame.Attempt? = nil) throws -> Data {
        guard requestID.count == 16, refusalAttempt == nil || decisionFrame != nil,
              decisionFrame == nil || (!decisionFrame!.isEmpty && decisionFrame!.count <= maximumFrameBytes) else {
            throw AuthorityXPCError.invalidMessage
        }
        return try DeterministicCBOR.encode(.map([0: .unsigned(version), 1: .bytes(requestID),
            2: decisionFrame.map(CBORValue.bytes) ?? .null,
            3: refusalAttempt.map { .array([.bytes($0.sessionID), .unsigned($0.sequence)]) } ?? .null]), limits: queryLimits)
    }

    public static func decode(_ bytes: Data) throws -> Query {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: queryLimits),
              Set(fields.keys) == Set(UInt64(0)...3), fields[0] == .unsigned(version),
              case .bytes(let requestID) = fields[1] else { throw AuthorityXPCError.invalidMessage }
        let decision: Data?
        if fields[2] == .null { decision = nil }
        else if case .bytes(let frame) = fields[2] { decision = frame }
        else { throw AuthorityXPCError.invalidMessage }
        let attempt: DecisionRefusalFrame.Attempt?
        if fields[3] == .null { attempt = nil }
        else if case .array(let values) = fields[3], values.count == 2,
                case .bytes(let session) = values[0], case .unsigned(let sequence) = values[1] {
            attempt = try .init(sessionID: session, sequence: sequence)
        } else { throw AuthorityXPCError.invalidMessage }
        guard try encode(requestID: requestID, decisionFrame: decision, refusalAttempt: attempt) == bytes else {
            throw AuthorityXPCError.invalidMessage
        }
        return Query(requestID: requestID, decisionFrame: decision, refusalAttempt: attempt)
    }

    /// Checks routing and correlation. The phone authenticates the authority signature.
    static func validateResponse(_ bytes: Data, binding: AuthorityPeerBinding, requestID: Data,
                                 decisionFrame: Data?, refusalAttempt: DecisionRefusalFrame.Attempt?) throws {
        guard !bytes.isEmpty, bytes.count <= maximumFrameBytes else { throw AuthorityXPCError.invalidMessage }
        let limits = try CBORLimits(maxBytes: maximumFrameBytes, maxDepth: 4, maxItems: 64)
        if let refusalAttempt, let decisionFrame, let refusal = try? DecisionRefusalFrame.decode(bytes) {
            let response = refusal.payload
            let decision = try ApprovalMessage.decode(decisionFrame, maximumBodyBytes: maximumFrameBytes - ApprovalMessage.overheadBytes)
            let claim = try DecisionPayload.decode(decision.body, limits: limits)
            guard decision.type == .decision, response.scope == binding.scope, response.attempt == refusalAttempt,
                  claim.macID == binding.scope.macID, claim.accountID == binding.scope.accountID,
                  claim.phoneID == binding.scope.phoneID, claim.requestID == requestID,
                  response.requestID == requestID, response.requestDigest == claim.requestDigest,
                  response.decisionFrameDigest == Data(SHA256.hash(data: decisionFrame)) else {
                throw AuthorityXPCError.invalidMessage
            }
            return
        }
        let message = try ApprovalMessage.decode(bytes, maximumBodyBytes: maximumFrameBytes - ApprovalMessage.overheadBytes)
        let status = try RequestStatusPayload.decode(message.body, limits: limits)
        guard message.type == .status, message.purpose == .status, status.macID == binding.scope.macID,
              status.accountID == binding.scope.accountID, status.requestID == requestID else {
            throw AuthorityXPCError.invalidMessage
        }
    }

    private static let queryLimits = try! CBORLimits(maxBytes: maximumQueryBytes, maxDepth: 2, maxItems: 11)
}
