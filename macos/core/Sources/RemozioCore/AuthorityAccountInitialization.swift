import Darwin
import Foundation
import RemozioProtocol

/// Root setup composition. The host must verify administrator consent, signed code and protected account scope first.
/// Serialize this operation with the machine store. Its result grants no service or command admission.
public enum AuthorityAccountInitialization {
    public static func resume(machine: PreparationIntentStore, expected: AuthorityInitializationIntent) throws -> AuthorityInitializationIntent {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let limits = try CBORLimits(maxBytes: 16_777_216, maxDepth: 32, maxItems: 262_144)
        let journalDirectory = (expected.journalPath as NSString).deletingLastPathComponent
        let continuityDirectory = (expected.continuityPath as NSString).deletingLastPathComponent
        return try resume(machine: machine, expected: expected,
            prepareJournal: { _ = try SetupDatabaseFileProvisioning.prepare(directoryPath: journalDirectory, kind: .journal) },
            openJournal: { initialize, initial in
                try JournalDatabase.open(directoryPath: journalDirectory, macID: expected.macID, accountID: expected.accountID,
                    recordLimits: limits, descriptorLimits: limits, decisionLimits: limits,
                    maximumConsumptions: 1_000_000, busyMilliseconds: 5000, initialize: initialize,
                    initialAuthority: initialize ? initial : nil)
            },
            prepareContinuity: { _ = try SetupDatabaseFileProvisioning.prepare(directoryPath: continuityDirectory, kind: .continuity) },
            openContinuity: { checkpoint in
                try ContinuityStore.open(directoryPath: continuityDirectory, macID: expected.macID,
                    accountID: expected.accountID, initialize: checkpoint)
            })
    }

    enum Stage: CaseIterable { case journalProvisioned, journalOpened, checkpointCaptured, continuityProvisioned, continuityOpened, completed }
    /// Same-owner controls use actual protected leases, provisioners and SQLite stores.
    /// Product callers cannot replace these factories or inject fault hooks.
    static func resume(machine: PreparationIntentStore, expected: AuthorityInitializationIntent,
                       prepareJournal: () throws -> Void,
                       openJournal: (Bool, AuthorityJournalInitialization) throws -> JournalDatabase,
                       prepareContinuity: () throws -> Void,
                       openContinuity: (ContinuityCheckpoint?) throws -> ContinuityStore,
                       didStage: (Stage) throws -> Void = { _ in }) throws -> AuthorityInitializationIntent {
        try machine.validateInitialization(expected)
        // Completion is retained setup progress, not current health. Never reinitialize a completed account.
        if expected.complete { return expected }
        let initial = try expected.initialAuthority
        var progress = expected
        var journal: JournalDatabase?
        var continuity: ContinuityStore?
        do {
            if progress.checkpoint == nil {
                try machine.validateInitialization(progress)
                try prepareJournal(); try didStage(.journalProvisioned)
            }
            try machine.validateInitialization(progress)
            do { journal = try openJournal(false, initial) }
            catch JournalDatabaseError.incompatibleStore {
                // A captured checkpoint proves the journal committed. Its loss cannot authorize initialization.
                guard progress.checkpoint == nil else { throw AuthorityInitializationError.invalidBoundary }
                try machine.validateInitialization(progress)
                journal = try openJournal(true, initial)
            }
            let liveJournal = try required(journal)
            try didStage(.journalOpened)
            progress = try machine.captureInitialization(expected: progress, initial: initial, journal: liveJournal)
            try didStage(.checkpointCaptured)
            let checkpoint = try required(progress.checkpoint)
            try machine.validateInitialization(progress)
            try prepareContinuity(); try didStage(.continuityProvisioned)
            try machine.validateInitialization(progress)
            do { continuity = try openContinuity(nil) }
            catch ContinuityStoreError.incompatibleStore {
                try machine.validateInitialization(progress)
                continuity = try openContinuity(checkpoint)
            }
            let liveContinuity = try required(continuity)
            try didStage(.continuityOpened)
            progress = try machine.completeInitialization(expected: progress, journal: liveJournal, continuity: liveContinuity)
            try didStage(.completed)
            liveContinuity.close(); continuity = nil
            try liveJournal.close(); journal = nil
            return progress
        } catch {
            continuity?.close(); try? journal?.close()
            throw error
        }
    }
    private static func required<T>(_ value: T?) throws -> T {
        guard let value else { throw AuthorityInitializationError.invalidBoundary }; return value
    }
}
