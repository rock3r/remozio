import Foundation
import RemozioProtocol
import Synchronization

public enum AuthorityWakeHintError: Error, Equatable { case invalidMessage, unavailable }

/// Local transport hints contain only the pinned gateway scope and opaque Root grants.
public struct AuthorityWakeHints: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public static let maximumDeliveries = 1024
    public let binding: GatewaySubmissionBinding
    public let deliveryIDs: [UUID]
    public var description: String { "AuthorityWakeHints(redacted)" }
    public var debugDescription: String { description }
    public init(binding: GatewaySubmissionBinding, deliveryIDs: [UUID]) throws {
        guard deliveryIDs.count <= Self.maximumDeliveries, Set(deliveryIDs).count == deliveryIDs.count else {
            throw AuthorityWakeHintError.invalidMessage
        }
        self.binding = binding; self.deliveryIDs = deliveryIDs.sorted { $0.uuidString < $1.uuidString }
    }
    public func encode() throws -> Data {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(binding.ownerID), 2: .bytes(binding.macID),
            3: .bytes(binding.accountID), 4: .bytes(binding.gatewayID), 5: .bytes(binding.lifecycleEpoch),
            6: .array(deliveryIDs.map { .bytes(GatewayHostSnapshot.bytes($0)) })]), limits: Self.limits)
    }
    public static func decode(_ bytes: Data, expectedBinding: GatewaySubmissionBinding) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits),
              Set(fields.keys) == Set(UInt64(0)...6), fields[0] == .unsigned(1), case .array(let ids) = fields[6] else {
            throw AuthorityWakeHintError.invalidMessage
        }
        let scope = [expectedBinding.ownerID, expectedBinding.macID, expectedBinding.accountID,
                     expectedBinding.gatewayID, expectedBinding.lifecycleEpoch]
        for (i, value) in scope.enumerated() where fields[UInt64(i + 1)] != .bytes(value) {
            throw AuthorityWakeHintError.invalidMessage
        }
        let result = try Self(binding: expectedBinding, deliveryIDs: ids.map {
            guard case .bytes(let id) = $0 else { throw AuthorityWakeHintError.invalidMessage }
            return try GatewayHostSnapshot.uuid(id)
        })
        guard try result.encode() == bytes else { throw AuthorityWakeHintError.invalidMessage }
        return result
    }
    private static var limits: CBORLimits { get throws { try .init(maxBytes: 20_000, maxDepth: 2, maxItems: 1040) } }
}

/// Synchronous endpoint access. Lease publication never holds this lock while acquiring the journal lock.
/// The feed rechecks its generation after the journal read, so shutdown or a new synchronization cannot publish stale hints.
public final class AuthorityWakeHintFeed: Sendable {
    private struct Lease: Equatable, Sendable {
        let epoch: UUID
        let deadline: UInt64
        let revision: UUID
        let phoneRouting: Bool
    }
    private struct State { var generation: UInt64 = 0; var lease: Lease?; var closed = false }
    private let state = Mutex(State())
    private let journal: AuthorityJournal
    public let binding: GatewaySubmissionBinding
    private let clock: @Sendable () throws -> AuthorityMoment
    private let routing: @Sendable (ApprovalRequestCoordinator, AuthorityMoment) throws -> PresenceRouting
    private let receiptTime: @Sendable () -> UInt64?
    init(journal: AuthorityJournal, registration: GatewayRegistrationIdentity,
         clock: @escaping @Sendable () throws -> AuthorityMoment, routing: @escaping @Sendable (ApprovalRequestCoordinator, AuthorityMoment) throws -> PresenceRouting,
         receiptTime: @escaping @Sendable () -> UInt64?) throws {
        self.journal = journal; self.clock = clock; self.routing = routing; self.receiptTime = receiptTime
        binding = try GatewaySubmissionBinding(ownerID: registration.ownerID, macID: registration.macID,
            accountID: registration.accountID, gatewayID: registration.gatewayID, lifecycleEpoch: registration.lifecycleEpoch)
    }
    func pause() { state.withLock { $0.generation &+= 1; $0.lease = nil } }
    func publish(epoch: UUID, deadline: UInt64, revision: UUID, phoneRouting: Bool) {
        state.withLock {
            guard !$0.closed else { return }
            $0.generation &+= 1; $0.lease = Lease(epoch: epoch, deadline: deadline, revision: revision, phoneRouting: phoneRouting)
        }
    }
    func close() { state.withLock { $0.closed = true; $0.generation &+= 1; $0.lease = nil } }
    public func current() throws -> AuthorityWakeHints {
        let captured = try state.withLock { state in
            guard !state.closed else { throw AuthorityWakeHintError.unavailable }
            return (state.generation, state.lease)
        }
        guard let lease = captured.1 else { return try AuthorityWakeHints(binding: binding, deliveryIDs: []) }
        let ids = try journal.withRequests { [clock, routing, receiptTime, binding] owner in
            let now = try clock(), route = try routing(owner, now), trust = try owner.wakeDeliveryTrust()
            guard now.epoch == lease.epoch, now.milliseconds < lease.deadline,
                  trust.approval.macID == binding.macID, trust.approval.accountID == binding.accountID else {
                throw AuthorityWakeHintError.unavailable
            }
            let work = try owner.reconcileWakePublications(routing: route, now: now, receiptTimeMs: receiptTime(), trust: trust)
            guard trust.approval.revision == lease.revision, (route.destination == .phones) == lease.phoneRouting else { return [UUID]() }
            return work.readyDeliveryIDs
        }
        return try state.withLock { state in
            guard !state.closed else { throw AuthorityWakeHintError.unavailable }
            return try AuthorityWakeHints(binding: binding, deliveryIDs: state.generation == captured.0 ? ids : [])
        }
    }
}
