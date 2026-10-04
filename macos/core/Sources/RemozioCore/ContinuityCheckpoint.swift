import Foundation
import RemozioProtocol

public enum ContinuityStoreError: Error, Equatable {
    case invalidCheckpoint, incompatibleStore, wrongScope, staleState, recoveryRequired, closed, unavailable
    case storage(Int32)
}

/// A retained boundary, never permission to dispatch. Digests must come from the authority's canonical state encoder.
public struct ContinuityCheckpoint: Equatable, Sendable {
    public let generation: UInt64
    public let authorityDigest: Data
    public let ledgerDigest: Data
    public let journalEpoch: Data
    public let journalHead: UInt64

    public init(generation: UInt64, authorityDigest: Data, ledgerDigest: Data, journalEpoch: Data, journalHead: UInt64) throws {
        guard generation > 0, authorityDigest.count == 32, ledgerDigest.count == 32, journalEpoch.count == 16 else {
            throw ContinuityStoreError.invalidCheckpoint
        }
        self.generation = generation; self.authorityDigest = authorityDigest; self.ledgerDigest = ledgerDigest
        self.journalEpoch = journalEpoch; self.journalHead = journalHead
    }

    var bytes: Data {
        get throws {
            try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .unsigned(generation),
                2: .bytes(authorityDigest), 3: .bytes(ledgerDigest), 4: .bytes(journalEpoch), 5: .unsigned(journalHead)]),
                limits: Self.limits())
        }
    }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits()),
              Set(fields.keys) == Set((0...5).map(UInt64.init)), fields[0] == .unsigned(1),
              case .unsigned(let generation) = fields[1], case .bytes(let authority) = fields[2],
              case .bytes(let ledger) = fields[3], case .bytes(let epoch) = fields[4],
              case .unsigned(let head) = fields[5] else { throw ContinuityStoreError.invalidCheckpoint }
        let value = try Self(generation: generation, authorityDigest: authority, ledgerDigest: ledger,
                             journalEpoch: epoch, journalHead: head)
        guard try value.bytes == bytes else { throw ContinuityStoreError.invalidCheckpoint }
        return value
    }
    private static func limits() throws -> CBORLimits { try CBORLimits(maxBytes: 256, maxDepth: 2, maxItems: 16) }
}

/// Pending contains both possible journal boundaries. Startup must reconcile them without dispatching or replaying an action.
public struct ContinuityState: Equatable, Sendable {
    public let committed: ContinuityCheckpoint
    public let pending: ContinuityCheckpoint?
    public let recoveryRequired: Bool
    init(committed: ContinuityCheckpoint, pending: ContinuityCheckpoint?, recoveryRequired: Bool) throws {
        if let pending {
            guard committed.generation < UInt64.max, pending.generation == committed.generation + 1 else {
                throw ContinuityStoreError.invalidCheckpoint
            }
        }
        self.committed = committed; self.pending = pending; self.recoveryRequired = recoveryRequired
    }
}
