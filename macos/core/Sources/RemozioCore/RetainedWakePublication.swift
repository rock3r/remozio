import Foundation

/// Root-owned publication work. Registration grants authority only through the authenticated gateway control channel.
public struct RetainedWakePublicationSnapshot: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let registrations: [PhoneRequestDelivery]
    public let withdrawals: [PhoneRequestDelivery]
    public let readyDeliveryIDs: [UUID]
    public let capacityLimitedRecipients: Int
    public var description: String { "RetainedWakePublicationSnapshot(redacted)" }
    public var debugDescription: String { description }
}

/// Serialized with the request owner. Wake state never marks a signed request frame as dispatched.
final class RetainedWakePublication {
    private struct Controller {
        let delivery: PendingRequestDelivery
        var routing: PresenceRouting
    }
    private let maximumDeliveries: Int
    private var controllers: [Data: Controller] = [:]
    private var deliveries: [UUID: PhoneRequestDelivery] = [:]
    private var registered: Set<UUID> = []
    private var withdrawals: [UUID: PhoneRequestDelivery] = [:]
    private var closed = false

    init(maximumDeliveries: Int) { self.maximumDeliveries = maximumDeliveries }

    func reconcile(_ request: RetainedApprovalRequest, trust: RequestDeliveryTrust,
                   routing: PresenceRouting, now: AuthorityMoment) throws -> Int {
        guard !closed else { throw ApprovalCoordinatorError.unavailable }
        let id = request.payload.requestID
        if controllers[id] == nil {
            controllers[id] = try Controller(delivery: PendingRequestDelivery(request: request), routing: routing)
        }
        guard var controller = controllers[id] else { throw ApprovalCoordinatorError.unavailable }
        controller.routing = routing; controllers[id] = controller
        var limited = 0
        let update = controller.delivery.reconcile(current: request, routing: routing, trust: trust, now: now) { delivery in
            if let existing = deliveries[delivery.id] { return existing == delivery }
            guard withdrawals[delivery.id] == nil, deliveries.count + withdrawals.count < maximumDeliveries else {
                limited += 1; return false
            }
            deliveries[delivery.id] = delivery
            return true
        }
        retainWithdrawals(update.withdrawn)
        return limited + update.capacityLimitedRecipients.count
    }

    /// Retain cleanup before the request owner releases its pending capture or terminal entry.
    func retire(_ state: ApprovalRequestState, now: AuthorityMoment) {
        guard let controller = controllers.removeValue(forKey: state.requestID) else { return }
        let update = controller.delivery.close(current: state, routing: controller.routing, now: now)
        retainWithdrawals(update.withdrawn)
    }
    private func retainWithdrawals(_ values: [PhoneRequestDelivery]) {
        for delivery in values {
            deliveries.removeValue(forKey: delivery.id); registered.remove(delivery.id)
            withdrawals[delivery.id] = delivery
        }
    }
    /// The owner refreshes request, enrollment, presence, and time before accepting this acknowledgment.
    func acknowledgeRegistration(_ delivery: PhoneRequestDelivery) -> Bool {
        guard deliveries[delivery.id] == delivery else { return false }
        registered.insert(delivery.id)
        return true
    }
    func acknowledgeWithdrawal(_ delivery: PhoneRequestDelivery) -> Bool {
        guard withdrawals[delivery.id] == delivery else { return false }
        withdrawals.removeValue(forKey: delivery.id)
        return true
    }
    func snapshot(routing: PresenceRouting, capacityLimitedRecipients: Int) throws -> RetainedWakePublicationSnapshot {
        guard !closed else { throw ApprovalCoordinatorError.unavailable }
        return RetainedWakePublicationSnapshot(
            registrations: deliveries.values.filter { !registered.contains($0.id) }.sorted { $0.id.uuidString < $1.id.uuidString },
            withdrawals: withdrawals.values.sorted { $0.id.uuidString < $1.id.uuidString },
            readyDeliveryIDs: routing.destination == .phones ? registered.sorted { $0.uuidString < $1.uuidString } : [],
            capacityLimitedRecipients: capacityLimitedRecipients)
    }
    /// Root channel loss retires the gateway lease. No transient grant or acknowledgment is restored after restart.
    func close() {
        closed = true
        controllers.removeAll(); deliveries.removeAll(); registered.removeAll(); withdrawals.removeAll()
    }
}
