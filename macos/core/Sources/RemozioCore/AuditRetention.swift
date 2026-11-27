import CryptoKit
import Foundation
import RemozioProtocol

/// Audit row retention only. Consumption receipts, outcomes and replay reservations stay in the journal.
enum AuditRetention {
    /// The planner can reject an otherwise intact journal before any retention write.
    enum PlanningFailure: String, Error {
        case rowCountOverflow, missingActiveEpoch, cyclicLineage
    }

    struct Policy {
        let targetRows: UInt64
        let triggerRows: UInt64
        let maximumRowsPerBatch: UInt64

        init(targetRows: UInt64 = 100_000, triggerRows: UInt64 = 110_000, maximumRowsPerBatch: UInt64) throws {
            guard targetRows > 0, triggerRows > targetRows, maximumRowsPerBatch > 0 else {
                throw AuditReplyError.invalidBounds
            }
            self.targetRows = targetRows
            self.triggerRows = triggerRows
            self.maximumRowsPerBatch = maximumRowsPerBatch
        }
    }

    struct Result: Equatable, Sendable {
        let retainedRows: UInt64
        let prunedRows: UInt64
        /// Extra rows that another batch can remove in the same maintenance pass.
        let remainingEligibleExcess: UInt64
        /// Extra rows that must stay because an anchor or an unverified epoch protects them.
        let protectedExcess: UInt64
    }

    struct Prefix {
        let epoch: Data
        let head: UInt64
        let through: UInt64
    }

    struct Plan {
        let prefixes: [Prefix]
        let result: Result
    }

    static func rowCount(_ epochs: [AuditEpochRead]) throws -> UInt64 {
        try epochs.reduce(UInt64(0)) { count, epoch in
            let (next, overflow) = count.addingReportingOverflow(epoch.head - epoch.retainedAfter)
            guard !overflow else { throw PlanningFailure.rowCountOverflow }
            return next
        }
    }

    static func plan(transaction: JournalTransaction, activeEpoch: Data, policy: Policy, continuing: Bool) throws -> Plan {
        let epochs = try transaction.auditEpochs()
        let byID = Dictionary(uniqueKeysWithValues: epochs.map { ($0.descriptor.epoch, $0) })
        guard let active = byID[activeEpoch] else { throw PlanningFailure.missingActiveEpoch }
        let total = try rowCount(epochs)
        guard total > policy.targetRows, continuing || total >= policy.triggerRows else {
            return Plan(prefixes: [], result: Result(retainedRows: total, prunedRows: 0,
                                                    remainingEligibleExcess: 0, protectedExcess: 0))
        }

        var protected = [Data: UInt64]()
        func protect(_ epoch: Data, _ sequence: UInt64) {
            guard let boundary = byID[epoch], sequence > boundary.retainedAfter, sequence <= boundary.head else { return }
            protected[epoch] = min(sequence, protected[epoch] ?? sequence)
        }
        protect(activeEpoch, active.head)
        for epoch in epochs {
            let descriptor = epoch.descriptor
            if let previous = descriptor.previousEpoch, let sequence = descriptor.previousSequence {
                protect(previous, sequence)
            }
            if let recovery = try transaction.historyRecovery(epoch: descriptor.epoch) {
                protect(descriptor.epoch, 1)
                protect(recovery.previous.committed.journalEpoch, recovery.previous.committed.journalHead)
                if let pending = recovery.previous.pending { protect(pending.journalEpoch, pending.journalHead) }
            }
        }

        // Only the verified predecessor chain supplies an order for destructive retention.
        let lineage = try verifiedLineage(from: active, epochs: byID, transaction: transaction)
        let excess = total - policy.targetRows
        var desired = min(excess, policy.maximumRowsPerBatch)
        var available = UInt64(0)
        var prefixes = [Prefix]()
        for epoch in lineage.reversed() {
            let id = epoch.descriptor.epoch
            let limit = protected[id].map { $0 - 1 } ?? epoch.head
            let eligible = limit - epoch.retainedAfter
            available += eligible
            let count = min(eligible, desired)
            if count > 0 {
                prefixes.append(Prefix(epoch: id, head: epoch.head, through: epoch.retainedAfter + count))
                desired -= count
            }
        }
        let pruned = min(excess, policy.maximumRowsPerBatch) - desired
        let eligibleExcess = min(excess, available)
        return Plan(prefixes: prefixes, result: Result(retainedRows: total - pruned, prunedRows: pruned,
                    remainingEligibleExcess: eligibleExcess - pruned, protectedExcess: excess - eligibleExcess))
    }

    private static func verifiedLineage(from active: AuditEpochRead, epochs: [Data: AuditEpochRead],
                                        transaction: JournalTransaction) throws -> [AuditEpochRead] {
        var lineage = [active]
        var visited: Set<Data> = [active.descriptor.epoch]
        var descriptor = active.descriptor
        while let previous = descriptor.previousEpoch, let predecessor = epochs[previous],
              let sequence = descriptor.previousSequence, sequence == predecessor.head,
              try verifiesPredecessor(descriptor, epoch: predecessor, sequence: sequence, transaction: transaction) {
            guard visited.insert(previous).inserted else { throw PlanningFailure.cyclicLineage }
            lineage.append(predecessor)
            descriptor = predecessor.descriptor
        }
        return lineage
    }

    private static func verifiesPredecessor(_ descriptor: AuditEpochDescriptor, epoch: AuditEpochRead,
                                            sequence: UInt64, transaction: JournalTransaction) throws -> Bool {
        if sequence == 0 { return true }
        guard sequence > epoch.retainedAfter, let digest = descriptor.previousEventDigest else { return false }
        let page = try transaction.page(epoch: epoch.descriptor.epoch, after: sequence - 1, maximumRecords: 1,
                                        maximumBytes: Int.max)
        guard let record = page.canonicalRecords.first else { throw AuditJournalError.corruptData }
        return Data(SHA256.hash(data: record)) == digest
    }
}
