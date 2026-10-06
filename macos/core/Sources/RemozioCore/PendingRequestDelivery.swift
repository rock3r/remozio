import Foundation
import RemozioProtocol

/// One consistent protected-journal read. The authority must refresh it before each delivery evaluation.
public struct RequestDeliveryTrust: Sendable {
    public let approval: ApprovalTrustSnapshot
    public let enrollments: [StoredApprovalEnrollment]
    init(approval: ApprovalTrustSnapshot, enrollments: [StoredApprovalEnrollment]) {
        self.approval = approval; self.enrollments = enrollments
    }
}

public struct DeliveryRecipient: Hashable, Sendable {
    public let phoneID: Data
    public let enrollmentEpoch: Data
    init(_ enrollment: StoredApprovalEnrollment) {
        phoneID = enrollment.approval.phoneID; enrollmentEpoch = enrollment.epoch
    }
}

/// An opaque queue identity, not an authorization or a push payload. Retry with this identity to deduplicate transport work.
public struct PhoneRequestDelivery: Equatable, Sendable {
    public let id: UUID
    public let recipient: DeliveryRecipient
    public let requestID: Data
    public let admittedAt: AuthorityMoment
    public let deadlineMilliseconds: UInt64
}

public enum DeliveryClosure: Equatable, Sendable {
    case requestChanged, invalidClock, incompatibleAuthority, requestPhase(RequestPhase), expired
}

public struct RequestDeliveryUpdate: Sendable {
    public let routing: PresenceRouting
    public let active: [PhoneRequestDelivery]
    public let dispatched: [PhoneRequestDelivery]
    public let newlyEnqueued: [PhoneRequestDelivery]
    public let withdrawn: [PhoneRequestDelivery]
    public let closure: DeliveryClosure?
    public let capacityLimitedRecipients: [DeliveryRecipient]
}

public struct RequestDeliveryDispatch: Sendable {
    public let delivery: PhoneRequestDelivery?
    public let update: RequestDeliveryUpdate
}

public enum PendingDeliveryError: Error, Equatable { case invalidRequest, invalidCapacity }

/// Own one instance per admitted request and serialize it with request lifecycle and enrollment changes.
/// Enqueue must synchronously accept local queue ownership, never await network delivery or reenter this instance.
public final class PendingRequestDelivery {
    private let original: RetainedApprovalRequest
    private let maximumRecipients: Int
    private var lastTime: UInt64
    private var closure: DeliveryClosure?
    private struct Entry {
        let delivery: PhoneRequestDelivery
        var enqueued = false
        var dispatched = false
        var retired = false
    }
    private var entries: [DeliveryRecipient: Entry] = [:]

    public init(request: RetainedApprovalRequest, maximumRecipients: Int = 1024) throws {
        guard request.phase == .queued || request.phase == .presented else { throw PendingDeliveryError.invalidRequest }
        guard (1...1024).contains(maximumRecipients) else { throw PendingDeliveryError.invalidCapacity }
        original = request; self.maximumRecipients = maximumRecipients; lastTime = request.admittedAt.milliseconds
    }

    /// Supply the current authority-owned request after checking its target. A vanished target must no longer be pending.
    /// The callback's true result transfers notification retries to the queue; presence changes never enqueue it again.
    public func reconcile(current: RetainedApprovalRequest, routing: PresenceRouting, trust: RequestDeliveryTrust,
                          now: AuthorityMoment, enqueue: (PhoneRequestDelivery) -> Bool) -> RequestDeliveryUpdate {
        if closure == nil {
            if current.payload != original.payload || current.admittedAt != original.admittedAt ||
                current.deadlineMilliseconds != original.deadlineMilliseconds {
                closure = .requestChanged
            } else if now.epoch != original.admittedAt.epoch || now.milliseconds < lastTime {
                closure = .invalidClock
            } else if current.phase != .queued && current.phase != .presented {
                closure = .requestPhase(current.phase)
            } else if now.milliseconds >= original.deadlineMilliseconds {
                closure = .expired
            } else if !authoritySupports(trust.approval) {
                closure = .incompatibleAuthority
            }
        }
        lastTime = max(lastTime, now.milliseconds)
        let eligible = closure == nil ? eligibleRecipients(trust) : []
        let eligibleSet = Set(eligible)
        var withdrawn: [PhoneRequestDelivery] = []
        for recipient in Array(entries.keys) where !eligibleSet.contains(recipient) {
            guard var entry = entries[recipient], !entry.retired else { continue }
            if entry.enqueued { withdrawn.append(entry.delivery) }
            entry.retired = true
            entries[recipient] = entry
        }
        var added: [PhoneRequestDelivery] = []
        var capacityLimited: [DeliveryRecipient] = []
        if closure == nil && routing.destination == .phones {
            for recipient in eligible {
                if entries[recipient] == nil && entries.count >= maximumRecipients {
                    capacityLimited.append(recipient)
                    continue
                }
                if entries[recipient] == nil {
                    entries[recipient] = Entry(delivery: PhoneRequestDelivery(id: UUID(), recipient: recipient,
                        requestID: original.payload.requestID, admittedAt: original.admittedAt,
                        deadlineMilliseconds: original.deadlineMilliseconds))
                }
                guard var entry = entries[recipient], !entry.enqueued, !entry.retired else { continue }
                if enqueue(entry.delivery) {
                    entry.enqueued = true
                    added.append(entry.delivery)
                    entries[recipient] = entry
                }
            }
        }
        let active = entries.values.filter { $0.enqueued && !$0.retired }.map(\.delivery)
        return RequestDeliveryUpdate(routing: routing, active: sorted(active), dispatched: dispatched(), newlyEnqueued: sorted(added),
            withdrawn: sorted(withdrawn), closure: closure, capacityLimitedRecipients: capacityLimited)
    }

    private init(copying other: PendingRequestDelivery) {
        original = other.original; maximumRecipients = other.maximumRecipients
        lastTime = other.lastTime; closure = other.closure; entries = other.entries
    }

    /// Inspect eligibility without changing notification queue state or consuming withdrawals.
    /// Previously dispatched recipients remain discoverable while presence routes new requests locally.
    func discover(current: RetainedApprovalRequest, routing: PresenceRouting, trust: RequestDeliveryTrust,
                  now: AuthorityMoment) -> Set<DeliveryRecipient> {
        let snapshot = PendingRequestDelivery(copying: self)
        _ = snapshot.reconcile(current: current, routing: routing, trust: trust, now: now) { _ in false }
        return Set(snapshot.entries.values.filter {
            !$0.retired && (routing.destination == .phones || $0.dispatched)
        }.map(\.delivery.recipient))
    }

    /// Recheck immediately before the first transport write, with no intervening await or authority-state change.
    /// A nil delivery means do not start. Always apply update, including its withdrawals, even when delivery is nil.
    /// The queue owns bounded retries of a started delivery, using the same identity and current reconciliation state.
    public func beginDelivery(id: UUID, current: RetainedApprovalRequest, routing: PresenceRouting,
                              trust: RequestDeliveryTrust, now: AuthorityMoment) -> RequestDeliveryDispatch {
        handoff(id: id, current: current, routing: routing, trust: trust, now: now) { _ in true }
    }

    /// Recheck and synchronously transfer ownership. False means no bytes or work were accepted, so the same identity may retry.
    /// The callback must not await, reenter this controller, or change authority state. Acceptance is not provider or phone receipt.
    public func handoff(id: UUID, current: RetainedApprovalRequest, routing: PresenceRouting,
                        trust: RequestDeliveryTrust, now: AuthorityMoment,
                        accept: (PhoneRequestDelivery) -> Bool) -> RequestDeliveryDispatch {
        let update = reconcile(current: current, routing: routing, trust: trust, now: now) { _ in false }
        guard closure == nil, routing.destination == .phones,
              let recipient = entries.first(where: { $0.value.delivery.id == id })?.key,
              var entry = entries[recipient], entry.enqueued, !entry.retired, !entry.dispatched else {
            return RequestDeliveryDispatch(delivery: nil, update: update)
        }
        guard accept(entry.delivery) else { return RequestDeliveryDispatch(delivery: nil, update: update) }
        entry.dispatched = true
        entries[recipient] = entry
        return RequestDeliveryDispatch(delivery: entry.delivery, update: RequestDeliveryUpdate(
            routing: update.routing, active: update.active, dispatched: dispatched(), newlyEnqueued: update.newlyEnqueued,
            withdrawn: update.withdrawn, closure: update.closure, capacityLimitedRecipients: update.capacityLimitedRecipients))
    }

    /// Called by the serialized request owner after a request leaves its pending phase.
    func close(current: ApprovalRequestState, routing: PresenceRouting, now: AuthorityMoment) -> RequestDeliveryUpdate {
        if closure == nil {
            let payload = original.payload
            if current.requestID != payload.requestID || current.macID != payload.macID || current.accountID != payload.accountID ||
                current.challenge != payload.challenge || current.firstObservedAt != original.admittedAt ||
                current.deadlineMilliseconds != original.deadlineMilliseconds { closure = .requestChanged }
            else if now.epoch != original.admittedAt.epoch || now.milliseconds < lastTime { closure = .invalidClock }
            else { closure = .requestPhase(current.phase) }
        }
        lastTime = max(lastTime, now.milliseconds)
        var withdrawn: [PhoneRequestDelivery] = []
        for recipient in Array(entries.keys) {
            guard var entry = entries[recipient], !entry.retired else { continue }
            if entry.enqueued { withdrawn.append(entry.delivery) }
            entry.retired = true; entries[recipient] = entry
        }
        return RequestDeliveryUpdate(routing: routing, active: [], dispatched: [], newlyEnqueued: [],
            withdrawn: sorted(withdrawn), closure: closure, capacityLimitedRecipients: [])
    }

    private func dispatched() -> [PhoneRequestDelivery] {
        sorted(entries.values.filter { $0.enqueued && $0.dispatched && !$0.retired }.map(\.delivery))
    }

    private func authoritySupports(_ trust: ApprovalTrustSnapshot) -> Bool {
        let request = original.payload
        guard request.macID == trust.macID, request.accountID == trust.accountID,
              trust.allowedContracts.contains(request.contract),
              let features = trust.authorityCapabilities.contracts[request.contract] else { return false }
        return request.requiredFeatures.isSubset(of: features)
    }

    private func eligibleRecipients(_ trust: RequestDeliveryTrust) -> [DeliveryRecipient] {
        let request = original.payload
        return trust.enrollments.compactMap { stored in
            guard stored.approval.active,
                  let enrollment = trust.approval.enrollments.first(where: { $0.phoneID == stored.approval.phoneID }),
                  enrollment.active, let features = enrollment.capabilities.contracts[request.contract],
                  request.requiredFeatures.isSubset(of: features) else { return nil }
            return DeliveryRecipient(stored)
        }.sorted { lhs, rhs in
            lhs.phoneID == rhs.phoneID ? lhs.enrollmentEpoch.lexicographicallyPrecedes(rhs.enrollmentEpoch) :
                lhs.phoneID.lexicographicallyPrecedes(rhs.phoneID)
        }
    }

    private func sorted(_ values: [PhoneRequestDelivery]) -> [PhoneRequestDelivery] {
        values.sorted { $0.id.uuidString < $1.id.uuidString }
    }
}
