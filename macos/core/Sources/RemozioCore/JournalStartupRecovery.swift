import Foundation
import RemozioProtocol

/// Confined startup sequence. The host must validate external authority state and keep admission closed.
final class JournalStartupRecovery {
    enum Failure: Error { case alreadyStarted, invalidBounds, invalidEpoch, incomplete }
    enum Progress {
        case historyDiscontinuity(ContinuityState)
        case repairRequired
        case recovering
        case complete
    }
    private enum State { case idle, recovering, complete, retired }
    private let journal: JournalDatabase
    private let continuity: ContinuityStore
    private let maximumRecords: Int
    private let maximumBytes: Int
    private var state = State.idle
    private var commits: CheckpointedJournal?
    private var writer: AuditEpochWriter?
    private var cursor: Data?
    private var head: UInt64 = 0

    init(journal: JournalDatabase, continuity: ContinuityStore, maximumRecords: Int, maximumBytes: Int) throws {
        guard (1...256).contains(maximumRecords), (1...67_108_864).contains(maximumBytes) else { throw Failure.invalidBounds }
        self.journal = journal; self.continuity = continuity
        self.maximumRecords = maximumRecords; self.maximumBytes = maximumBytes
    }

    /// Supply a fresh descriptor bound to current trust. No writer escapes before every recovery batch commits.
    func start(descriptor: AuditEpochDescriptor) throws -> Progress {
        guard case .idle = state else { throw Failure.alreadyStarted }
        state = .retired
        switch try JournalCheckpointRecovery.reconcile(journal: journal, continuity: continuity) {
        case .repairRequired: return .repairRequired
        case .historyDiscontinuity(let evidence): return .historyDiscontinuity(evidence)
        case .unchanged, .finalized, .discarded: break
        }
        guard descriptor.cause == .restart || descriptor.cause == .recovery,
              try journal.read({ try $0.epoch(descriptor.epoch) }) == nil else { throw Failure.invalidEpoch }
        let commits = CheckpointedJournal(journal: journal, continuity: continuity)
        let writer = try commits.write(epoch: descriptor.epoch) { try $0.createEpoch(descriptor) }
        self.commits = commits; self.writer = writer
        state = .recovering
        return .recovering
    }

    /// Advance only after the batch and its independent checkpoint are durable. Never retry an old action.
    func advance() throws -> Progress {
        guard case .recovering = state, let commits, let writer else { throw Failure.incomplete }
        state = .retired
        let batch = try commits.write(epoch: writer.epoch) {
            try $0.reconcileInterruptedConsumptions(afterRequestID: cursor, maximumRecords: maximumRecords,
                maximumBytes: maximumBytes, writer: writer, expectedHead: head)
        }
        cursor = batch.nextRequestID; head = batch.journalHead
        state = cursor == nil ? .complete : .recovering
        return cursor == nil ? .complete : .recovering
    }

    /// Storage completion only. Other admission gates and the live dispatch barrier remain the host's responsibility.
    func completedWriter() throws -> AuditEpochWriter {
        guard case .complete = state, let writer else { throw Failure.incomplete }
        return writer
    }
}
