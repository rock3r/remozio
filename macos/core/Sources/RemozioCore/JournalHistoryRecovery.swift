import Foundation
import RemozioProtocol
import Security

/// Storage recovery only. The host must validate external authority and keep action admission closed.
enum JournalHistoryRecovery {
    enum Failure: Error { case changedHistory, missingEvidence, invalidEpoch }

    /// Reconcile history and retain each interrupted attempt before replacing it.
    /// The caller must hold exclusive ownership and validate external authority before calling.
    static func recover(journal: JournalDatabase, continuity: ContinuityStore,
                        macID: Data, accountID: Data) throws -> ContinuityCheckpoint {
        if try continuity.historyRecovery() == nil {
            switch try JournalCheckpointRecovery.reconcile(journal: journal, continuity: continuity) {
            case let .unchanged(checkpoint), let .finalized(checkpoint), let .discarded(checkpoint):
                return checkpoint
            case .repairRequired:
                throw ContinuityStoreError.recoveryRequired
            case let .historyDiscontinuity(previous):
                try journal.read { transaction in
                    try requireInstalledPolicy(transaction)
                    let digests = try transaction.continuityDigests()
                    let intent = try HistoryRecoveryIntent(previous: previous, authorityDigest: digests.authority,
                        ledgerDigest: digests.ledger, recoveryEpoch: freshEpoch(transaction, continuity: continuity))
                    try continuity.prepareHistoryRecovery(intent)
                }
            }
        }
        do {
            return try resume(journal: journal, continuity: continuity, macID: macID, accountID: accountID)
        } catch Failure.changedHistory {
            try journal.read { transaction in
                guard let intent = try continuity.historyRecovery() else { throw Failure.missingEvidence }
                let candidate = try continuity.historyRecoveryCandidate()
                let digests = try transaction.continuityDigests()
                guard digests.authority == intent.authorityDigest else {
                    try continuity.requireRecovery()
                    throw ContinuityStoreError.recoveryRequired
                }
                try requireInstalledPolicy(transaction)
                // Matching bytes with missing evidence are not a new history-loss boundary.
                guard digests.ledger != intent.ledgerDigest, digests.ledger != candidate?.ledgerDigest else {
                    throw Failure.changedHistory
                }
                let replacement = try HistoryRecoveryIntent(previous: intent.previous, authorityDigest: digests.authority,
                    ledgerDigest: digests.ledger, recoveryEpoch: freshEpoch(transaction, continuity: continuity))
                try continuity.supersedeHistoryRecovery(expected: intent, expectedCandidate: candidate, replacement: replacement)
            }
            return try resume(journal: journal, continuity: continuity, macID: macID, accountID: accountID)
        }
    }

    private static func freshEpoch(_ transaction: JournalTransaction, continuity: ContinuityStore) throws -> Data {
        var epoch = Data(count: 16)
        guard epoch.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!) }) == errSecSuccess,
              try transaction.epoch(epoch) == nil, try transaction.historyRecovery(epoch: epoch) == nil,
              try continuity.supersededHistoryRecovery(epoch: epoch) == nil else { throw Failure.invalidEpoch }
        return epoch
    }

    private static func requireInstalledPolicy(_ transaction: JournalTransaction) throws {
        guard let entry = try transaction.codePolicy()?.policy.entries.first(where: { $0.role == .authority }) else {
            throw AuthoritySelfValidationError.unconfigured
        }
        _ = try AuthoritySelfValidation.requirement(for: entry)
    }

    /// Resume one retained recovery attempt under exclusive ownership of both stores.
    /// Requires installed authority code policy; schema-12 stores must complete installation before preparing recovery.
    /// No writer escapes: ordinary startup must create its own fresh epoch after this returns.
    static func resume(journal: JournalDatabase, continuity: ContinuityStore,
                       macID: Data, accountID: Data) throws -> ContinuityCheckpoint {
        guard let intent = try continuity.historyRecovery() else { throw Failure.missingEvidence }
        let retainedCandidate = try continuity.historyRecoveryCandidate()
        let observed = try journal.read { try $0.continuityDigests() }
        guard observed.authority == intent.authorityDigest else {
            try continuity.requireRecovery()
            throw ContinuityStoreError.recoveryRequired
        }
        try journal.read { try requireInstalledPolicy($0) }
        if let retainedCandidate, try journal.read({ try matches(retainedCandidate, intent: intent, transaction: $0) }) {
            try continuity.finalizeHistoryRecovery(expected: intent, candidate: retainedCandidate)
            return retainedCandidate
        }
        guard observed.ledger == intent.ledgerDigest else { throw Failure.changedHistory }
        let candidate = try journal.write { transaction in
            let before = try transaction.continuityDigests()
            guard before.authority == intent.authorityDigest, before.ledger == intent.ledgerDigest else {
                throw Failure.changedHistory
            }
            guard try transaction.epoch(intent.recoveryEpoch) == nil,
                  try transaction.historyRecovery(epoch: intent.recoveryEpoch) == nil else { throw Failure.invalidEpoch }
            let limits = try CBORLimits(maxBytes: 16_384, maxDepth: 8, maxItems: 512)
            let descriptor = try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
                0: .unsigned(1), 1: .bytes(macID), 2: .bytes(accountID), 3: .bytes(intent.recoveryEpoch),
                4: .unsigned(intent.authorityGeneration), 5: .unsigned(AuditEpochCause.recovery.rawValue),
                6: .null, 7: .null, 8: .null
            ]), limits: limits), limits: limits)
            let writer = try transaction.createEpoch(descriptor)
            try transaction.recordHistoryRecovery(intent)
            // Deterministic metadata permits the exact transaction to be reconstructed after rollback.
            let gap = try AuditEventMetadata(eventID: intent.recoveryEpoch, macID: macID, accountID: accountID,
                journalEpoch: intent.recoveryEpoch, sequence: 1, requestID: nil, eventTimeMs: nil,
                authorityReceiptTimeMs: nil, kind: .recovery, category: .authority, action: nil,
                decisionPhoneID: nil, authentication: .system, outcome: .unresolved, reason: .outcomeUnavailable,
                droppedEventCount: nil, peerDeviceID: nil).encode(limits: limits)
            try transaction.append(gap, writer: writer, expectedHead: 0)
            let candidate = try CheckpointedJournal.checkpoint(transaction: transaction, epoch: intent.recoveryEpoch,
                generation: intent.checkpointGeneration, authorityGeneration: intent.authorityGeneration)
            try continuity.prepareHistoryRecoveryCandidate(expected: intent, candidate: candidate)
            return candidate
        }
        guard try journal.read({ try matches(candidate, intent: intent, transaction: $0) }) else { throw Failure.changedHistory }
        try continuity.finalizeHistoryRecovery(expected: intent, candidate: candidate)
        return candidate
    }

    private static func matches(_ candidate: ContinuityCheckpoint, intent: HistoryRecoveryIntent,
                                transaction: JournalTransaction) throws -> Bool {
        let digests = try transaction.continuityDigests()
        guard candidate.authorityDigest == digests.authority, candidate.ledgerDigest == digests.ledger,
              let epoch = try transaction.epoch(candidate.journalEpoch), epoch.head == candidate.journalHead,
              try transaction.historyRecovery(epoch: intent.recoveryEpoch) == intent else { return false }
        return true
    }
}
