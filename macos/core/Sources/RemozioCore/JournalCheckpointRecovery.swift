import Foundation

/// Storage reconciliation only. Every result still requires the host's admission and outcome-recovery gates.
enum JournalCheckpointRecovery {
    enum Result: Equatable {
        case unchanged(ContinuityCheckpoint)
        case finalized(ContinuityCheckpoint)
        case discarded(ContinuityCheckpoint)
        case historyDiscontinuity(ContinuityState)
        case repairRequired
    }

    /// Confine both exclusively owned stores to the same serialization boundary throughout this call.
    /// No callback, retained request, permit, or execution result is reconstructed by recovery.
    static func reconcile(journal: JournalDatabase, continuity: ContinuityStore) throws -> Result {
        let state = try continuity.read()
        guard !state.recoveryRequired else { return .repairRequired }
        return try journal.read { transaction in
            let digests = try transaction.continuityDigests()
            func matches(_ checkpoint: ContinuityCheckpoint) throws -> Bool {
                guard checkpoint.authorityDigest == digests.authority, checkpoint.ledgerDigest == digests.ledger,
                      let epoch = try transaction.epoch(checkpoint.journalEpoch) else { return false }
                return epoch.head == checkpoint.journalHead
            }
            // Prefer the candidate when both describe identical bytes, as with a no-op transaction.
            if let pending = state.pending, try matches(pending) {
                try continuity.finalize(expected: state)
                return .finalized(pending)
            }
            if try matches(state.committed) {
                if state.pending != nil {
                    try continuity.discardPreparation(expected: state)
                    return .discarded(state.committed)
                }
                return .unchanged(state.committed)
            }
            if state.committed.authorityDigest == digests.authority || state.pending?.authorityDigest == digests.authority {
                // Preserve all evidence. A separate recovery step must record the gap and unresolved outcomes.
                return .historyDiscontinuity(state)
            }
            // Storage errors propagate instead of being converted into a persistent repair condition.
            try continuity.requireRecovery()
            return .repairRequired
        }
    }
}
