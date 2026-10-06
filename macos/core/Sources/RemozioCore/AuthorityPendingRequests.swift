import Foundation
import RemozioProtocol

/// Scoped discovery hints. An empty list does not confirm any request outcome.
enum AuthorityPendingRequests {
    static let maximumBytes = 131_072
    static let maximumRequests = 4096
    private static func limits() throws -> CBORLimits {
        try CBORLimits(maxBytes: maximumBytes, maxDepth: 3, maxItems: 8192)
    }
    static func encode(_ ids: [Data], binding: AuthorityPeerBinding) throws -> Data {
        guard ids.count <= maximumRequests, ids.allSatisfy({ $0.count == 16 }), Set(ids).count == ids.count else {
            throw AuthorityXPCError.invalidMessage
        }
        return try DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(AuthorityTrustCodec.encodeBinding(binding)),
            2: .array(ids.sorted { $0.lexicographicallyPrecedes($1) }.map(CBORValue.bytes)),
        ]), limits: limits())
    }
    static func decode(_ bytes: Data, binding: AuthorityPeerBinding) throws -> [Data] {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits()),
              Set(fields.keys) == Set([UInt64(0), 1, 2]), fields[0] == .unsigned(1),
              fields[1] == .bytes(try AuthorityTrustCodec.encodeBinding(binding)),
              case .array(let values) = fields[2], values.count <= maximumRequests else {
            throw AuthorityXPCError.invalidMessage
        }
        let ids = try values.map { value -> Data in
            guard case .bytes(let id) = value, id.count == 16 else { throw AuthorityXPCError.invalidMessage }
            return id
        }
        guard try encode(ids, binding: binding) == bytes else { throw AuthorityXPCError.invalidMessage }
        return ids
    }
}
