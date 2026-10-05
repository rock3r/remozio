import Foundation
import RemozioProtocol

/// A bounded routing check, not signature or capture validation. Android still verifies the authority endorsement.
enum AuthorityRequestFrame {
    static let maximumBytes = 16_777_216
    static func validate(_ bytes: Data, binding: AuthorityPeerBinding, requestID: Data) throws {
        guard requestID.count == 16, !bytes.isEmpty, bytes.count <= maximumBytes else { throw AuthorityXPCError.invalidMessage }
        let message = try ApprovalMessage.decode(bytes, maximumBodyBytes: maximumBytes - ApprovalMessage.overheadBytes)
        let limits = try CBORLimits(maxBytes: maximumBytes, maxDepth: 32, maxItems: 262_144)
        guard message.type == .request, message.purpose == .issuedRequest,
              case .map(let body) = try DeterministicCBOR.decode(message.body, limits: limits),
              Set(body.keys) == Set(UInt64(0)...12), body[0] == .unsigned(1),
              body[1] == .bytes(binding.scope.macID), body[2] == .bytes(binding.scope.accountID),
              body[3] == .bytes(requestID) else { throw AuthorityXPCError.invalidMessage }
    }
}
