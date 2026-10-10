import Foundation
import Synchronization

public enum AuthorityPresenceError: Error, Equatable {
    case invalidConfiguration, wrongScope, invalidObservation, unavailable
}

/// One configured account's observation policy. It contains no activity history or device credentials.
public struct AuthorityAccountPresenceConfiguration: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let macID: Data
    public let accountID: Data
    public let ownerUID: UInt32
    public let policy: PresenceConfiguration
    public var description: String { "AuthorityAccountPresenceConfiguration(redacted)" }
    public var debugDescription: String { description }
    public init(macID: Data, accountID: Data, ownerUID: UInt32, policy: PresenceConfiguration) throws {
        guard macID.count == 16, accountID.count == 16, ownerUID > 0, ownerUID < UInt32.max,
              policy.observationLifetimeMilliseconds <= 60_000, policy.unavailableGraceMilliseconds <= 60_000 else {
            throw AuthorityPresenceError.invalidConfiguration
        }
        self.macID = macID; self.accountID = accountID; self.ownerUID = ownerUID; self.policy = policy
    }
}

/// Root retains one coarse snapshot. Only the authenticated local account observer may publish or withdraw it.
/// Routing reads the durable mode through the serialized request owner, never an app-provided mode cache.
public final class AuthorityPresenceRuntime: Sendable {
    private struct State {
        var router: PresenceRouter
        var snapshot = PresenceSnapshot()
        var sampledAt: AuthorityMoment?
        var observer: UUID?
        var closed = false
    }
    public let configuration: AuthorityAccountPresenceConfiguration
    private let epoch: UUID
    private let state: Mutex<State>
    public init(configuration: AuthorityAccountPresenceConfiguration, clockEpoch: UUID) {
        self.configuration = configuration; epoch = clockEpoch
        state = Mutex(State(router: PresenceRouter(configuration: configuration.policy)))
    }

    /// The owning XPC endpoint verifies the caller, account scope and operation ordering before calling this method.
    /// Missing signals stay unknown. All supplied observations must share the declared sample moment.
    @discardableResult
    func publish(_ snapshot: PresenceSnapshot, observer: UUID, sampledAt: AuthorityMoment, now: AuthorityMoment) throws -> Bool {
        guard now.epoch == epoch, sampledAt.epoch == epoch, sampledAt.milliseconds <= now.milliseconds,
              now.milliseconds - sampledAt.milliseconds < configuration.policy.observationLifetimeMilliseconds,
              matches(snapshot.remoteWorkspace, sampledAt), matches(snapshot.locked, sampledAt),
              matches(snapshot.displays, sampledAt), matches(snapshot.lastQualifyingInputMilliseconds, sampledAt),
              (snapshot.displays?.value.count ?? 0) <= 32,
              snapshot.lastQualifyingInputMilliseconds.map({ $0.value <= sampledAt.milliseconds }) ?? true else {
            throw AuthorityPresenceError.invalidObservation
        }
        return try state.withLock {
            guard !$0.closed else { throw AuthorityPresenceError.unavailable }
            if let previous = $0.sampledAt, sampledAt.milliseconds <= previous.milliseconds { return false }
            $0.snapshot = snapshot; $0.sampledAt = sampledAt; $0.observer = observer
            return true
        }
    }
    /// An old connection cannot clear the snapshot that a newer authenticated connection supplied.
    func withdraw(observer: UUID) {
        state.withLock {
            guard $0.observer == observer else { return }
            $0.snapshot = PresenceSnapshot(); $0.observer = nil
        }
    }
    /// Called inside the journal's request serialization. This does not reenter the journal or hold a network connection.
    public func routing(owner: ApprovalRequestCoordinator, now: AuthorityMoment) throws -> PresenceRouting {
        try requireScope(owner)
        return try evaluate(mode: owner.localRoutingState().mode, now: now)
    }
    /// The journal serializes the complete frame operation. Its durable mode cannot change during signing.
    /// This callback refreshes observations and time without reentering the request owner.
    func deliveryRouting(owner: ApprovalRequestCoordinator) throws -> @Sendable (AuthorityMoment) throws -> PresenceRouting {
        try requireScope(owner)
        let mode = try owner.localRoutingState().mode
        return { try self.evaluate(mode: mode, now: $0) }
    }
    private func requireScope(_ owner: ApprovalRequestCoordinator) throws {
        guard owner.routingScope.macID == configuration.macID, owner.routingScope.accountID == configuration.accountID else {
            throw AuthorityPresenceError.wrongScope
        }
    }
    private func evaluate(mode: RoutingMode, now: AuthorityMoment) throws -> PresenceRouting {
        guard now.epoch == epoch else { throw AuthorityPresenceError.invalidObservation }
        return try state.withLock {
            guard !$0.closed else { throw AuthorityPresenceError.unavailable }
            return $0.router.evaluate(mode: mode, snapshot: $0.snapshot,
                now: PresenceMoment(epoch: now.epoch, milliseconds: now.milliseconds))
        }
    }
    public func close() { state.withLock { $0.closed = true; $0.snapshot = PresenceSnapshot(); $0.observer = nil; $0.sampledAt = nil } }
    private func matches<T: Sendable>(_ value: PresenceObservation<T>?, _ moment: AuthorityMoment) -> Bool {
        value.map { $0.observedAt.epoch == moment.epoch && $0.observedAt.milliseconds == moment.milliseconds } ?? true
    }
}
