import Foundation

/// Internal commit primitive. The host must supply exclusive ownership and complete startup recovery first.
/// A returned value proves storage completion only, never permission to dispatch an action.
final class CheckpointedJournal {
    enum Failure: Error, Equatable {
        case retired, reentrant, unresolvedPreparation, boundaryMismatch, generationExhausted, missingEpoch
    }
    private let journal: JournalDatabase
    private let continuity: ContinuityStore
    private(set) var retired = false
    private var active = false

    /// Both connections remain confined to the caller's synchronous serialization boundary.
    init(journal: JournalDatabase, continuity: ContinuityStore) {
        self.journal = journal
        self.continuity = continuity
    }

    /// The callback may mutate the journal only. It must not publish results or cause external effects.
    /// `epoch` identifies the resulting audit epoch, including when the callback creates a fresh epoch.
    func write<Value>(epoch: Data, recoverRejectedBody: Bool = false, _ body: (JournalTransaction) throws -> Value) throws -> Value {
        guard !retired else { throw Failure.retired }
        guard !active else { throw Failure.reentrant }
        active = true
        defer { active = false }
        var original: ContinuityState?
        var bodyRejected = false
        do {
            let before = try continuity.read()
            original = before
            guard !before.recoveryRequired else { throw ContinuityStoreError.recoveryRequired }
            guard before.pending == nil else { throw Failure.unresolvedPreparation }
            guard before.committed.generation < UInt64.max else { throw Failure.generationExhausted }
            let (value, candidate) = try journal.write { transaction in
                guard try Self.matches(before.committed, transaction: transaction) else { throw Failure.boundaryMismatch }
                let value: Value
                do { value = try body(transaction) }
                catch { bodyRejected = true; throw error }
                guard let boundary = try transaction.epoch(epoch) else { throw Failure.missingEpoch }
                let digests = try transaction.continuityDigests()
                let candidate = try before.committed.successor(authorityDigest: digests.authority,
                    ledgerDigest: digests.ledger, journalEpoch: epoch, journalHead: boundary.head)
                // SQLite has not committed the journal. Its rollback journal protects the old boundary.
                try continuity.prepare(expected: before.committed, candidate: candidate)
                return (value, candidate)
            }
            // Read the durable journal again. Never finalize using only the tentative callback's result.
            guard try journal.read({ try Self.matches(candidate, transaction: $0) }) else { throw Failure.boundaryMismatch }
            let prepared = try ContinuityState(committed: before.committed, pending: candidate, recoveryRequired: false)
            try continuity.finalize(expected: prepared)
            return value
        } catch {
            // A failed call never releases its result. Recovery must inspect both stores independently.
            retired = true
            if recoverRejectedBody, bodyRejected, let original {
                // Only a proved rollback can preserve a writer after a rejected request.
                do {
                    let current = try continuity.read()
                    if current == original, !current.recoveryRequired, current.pending == nil,
                       try journal.read({ try Self.matches(current.committed, transaction: $0) }) {
                        retired = false
                    }
                } catch { /* Preserve the original failure and retire uncertain storage. */ }
            }
            throw error
        }
    }

    /// Validates the independent checkpoint in the same journal transaction as the caller's read.
    func read<Value>(_ body: (JournalTransaction) throws -> Value) throws -> Value {
        guard !retired else { throw Failure.retired }
        guard !active else { throw Failure.reentrant }
        active = true
        defer { active = false }
        let checkpoint: ContinuityState
        do {
            checkpoint = try continuity.read()
            guard !checkpoint.recoveryRequired else { throw ContinuityStoreError.recoveryRequired }
            guard checkpoint.pending == nil else { throw Failure.unresolvedPreparation }
        } catch { retired = true; throw error }
        return try journal.read { transaction in
            do {
                guard try Self.matches(checkpoint.committed, transaction: transaction) else { throw Failure.boundaryMismatch }
            } catch { retired = true; throw error }
            return try body(transaction)
        }
    }

    static func checkpoint(transaction: JournalTransaction, epoch: Data, generation: UInt64,
                           authorityGeneration: UInt64? = nil) throws -> ContinuityCheckpoint {
        guard let boundary = try transaction.epoch(epoch) else { throw Failure.missingEpoch }
        let digests = try transaction.continuityDigests()
        return try ContinuityCheckpoint(generation: generation, authorityDigest: digests.authority,
            ledgerDigest: digests.ledger, journalEpoch: epoch, journalHead: boundary.head, authorityGeneration: authorityGeneration)
    }

    private static func matches(_ checkpoint: ContinuityCheckpoint, transaction: JournalTransaction) throws -> Bool {
        guard let boundary = try transaction.epoch(checkpoint.journalEpoch), boundary.head == checkpoint.journalHead else { return false }
        let digests = try transaction.continuityDigests()
        return digests.authority == checkpoint.authorityDigest && digests.ledger == checkpoint.ledgerDigest
    }
}
