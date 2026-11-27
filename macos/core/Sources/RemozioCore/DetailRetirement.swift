import Foundation
import RemozioProtocol

/// Bounded, archive-free retirement. The authority owns scheduling and excludes live work.
enum DetailRetirement {
    struct Policy {
        let target: Int
        let trigger: Int
        let maximumRecords: Int

        init(target: Int = 100_000, trigger: Int = 800_000, maximumRecords: Int) throws {
            guard target >= 0, trigger > target, (1...50_000).contains(maximumRecords) else {
                throw JournalDatabaseError.invalidConfiguration
            }
            self.target = target
            self.trigger = trigger
            self.maximumRecords = maximumRecords
        }
    }

    struct Result: Sendable {
        let observed: Int
        let retiredReceipts: Int
        let retiredSubmissions: Int
        let protectedScanned: Int
        let continuing: Bool
        let nextRequest: Data?
        let liveCountTime: Duration
        let planning: Duration
        let mutation: Duration
    }

    struct IdleBatch: Sendable {
        let result: Result
        let lockHold: Duration
        var fixedCost: Duration { lockHold - result.planning - result.mutation }
    }

    struct Plan {
        let liveCount: Int
        var observations: [(Data, ReplayDetailJournal.Mark)] = []
        var deletions: [Data] = []
        var protected = 0
        var nextRequest: Data?
    }

    static func plan(_ transaction: JournalTransaction, storage: ReplayDetailJournal, checkpoint: ContinuityCheckpoint,
                     live: Int, policy: Policy, protecting: Set<Data>, after: Data?, continuing: Bool) throws -> Plan {
        var plan = Plan(liveCount: live)
        guard live > policy.target, continuing || live >= policy.trigger else { return plan }
        var scanned = 0
        var cursor = after
        let limit = min(live - policy.target, policy.maximumRecords)
        repeat {
            let page = try transaction.consumptionOutcomes(afterRequestID: cursor,
                maximumRecords: min(256, policy.maximumRecords - scanned), maximumBytes: 67_108_864)
            for outcome in page.outcomes {
                let decision = outcome.receipt.decision
                cursor = decision.requestID
                scanned += 1
                switch outcome.phase {
                case .declined, .cancelled, .succeeded, .failed:
                    guard !protecting.contains(decision.requestID) else { plan.protected += 1; continue }
                    let mark = ReplayDetailJournal.Mark(revision: outcome.revision, generation: checkpoint.generation,
                                                        epoch: checkpoint.journalEpoch)
                    if try storage.observed(decision.requestID, before: mark) {
                        plan.deletions.append(decision.requestID)
                    } else {
                        plan.observations.append((decision.requestID, mark))
                    }
                    if plan.deletions.count + plan.observations.count == limit {
                        plan.nextRequest = plan.observations.isEmpty ? cursor : after
                        return plan
                    }
                default: plan.protected += 1
                }
            }
            cursor = page.nextRequestID
        } while cursor != nil && scanned < policy.maximumRecords
        plan.nextRequest = plan.observations.isEmpty ? cursor : after
        return plan
    }
}
