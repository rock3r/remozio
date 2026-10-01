import Foundation

public enum RoutingMode: String, Sendable { case automatic, present, away }
public enum RequestDestination: String, Sendable { case localMac, phones }
public enum PresenceReason: String, Sendable {
    case manualPresent, manualAway, remoteDesktop, locked, displaysOff, displaysDark, idle, active, detectorUnavailable
}
public enum RemoteWorkspace: Sendable { case usable, notUsable, unsupported }
public enum DisplayBrightness: Sendable { case readable, dark, unknown }
public enum DisplayPresence: Sendable { case asleep, awake(DisplayBrightness), unknown }

/// Milliseconds from one sleep-inclusive monotonic clock. A new clock epoch invalidates old observations.
public struct PresenceMoment: Equatable, Sendable {
    public let epoch: UUID
    public let milliseconds: UInt64

    public init(epoch: UUID, milliseconds: UInt64) {
        self.epoch = epoch
        self.milliseconds = milliseconds
    }
}

public struct PresenceObservation<Value: Sendable>: Sendable {
    public let value: Value
    public let observedAt: PresenceMoment

    public init(_ value: Value, observedAt: PresenceMoment) {
        self.value = value
        self.observedAt = observedAt
    }
}

/// Supply observations for one account only. A remote session must expose that account's desktop.
public struct PresenceSnapshot: Sendable {
    public var remoteWorkspace: PresenceObservation<RemoteWorkspace>?
    public var locked: PresenceObservation<Bool>?
    public var displays: PresenceObservation<[DisplayPresence]>?
    public var lastQualifyingInputMilliseconds: PresenceObservation<UInt64>?

    public init(
        remoteWorkspace: PresenceObservation<RemoteWorkspace>? = nil,
        locked: PresenceObservation<Bool>? = nil,
        displays: PresenceObservation<[DisplayPresence]>? = nil,
        lastQualifyingInputMilliseconds: PresenceObservation<UInt64>? = nil
    ) {
        self.remoteWorkspace = remoteWorkspace
        self.locked = locked
        self.displays = displays
        self.lastQualifyingInputMilliseconds = lastQualifyingInputMilliseconds
    }
}

public enum PresenceConfigurationError: Error { case zeroInterval }

public struct PresenceConfiguration: Sendable {
    public let idleMilliseconds: UInt64
    public let observationLifetimeMilliseconds: UInt64
    public let unavailableGraceMilliseconds: UInt64

    public init(
        idleMilliseconds: UInt64 = 120_000,
        observationLifetimeMilliseconds: UInt64,
        unavailableGraceMilliseconds: UInt64
    ) throws {
        guard idleMilliseconds > 0, observationLifetimeMilliseconds > 0 else { throw PresenceConfigurationError.zeroInterval }
        self.idleMilliseconds = idleMilliseconds
        self.observationLifetimeMilliseconds = observationLifetimeMilliseconds
        self.unavailableGraceMilliseconds = unavailableGraceMilliseconds
    }
}

public struct PresenceRouting: Equatable, Sendable {
    public let destination: RequestDestination
    public let reason: PresenceReason
    public let detectionLimited: Bool
}

/// Own one router per account. Serialize evaluations; this policy changes delivery only.
public struct PresenceRouter: Sendable {
    public let configuration: PresenceConfiguration
    private var lastMoment: PresenceMoment?
    private var lastDestination: RequestDestination?
    private var unavailableSince: UInt64?
    private var lastEvidenceExpiry: UInt64?

    public init(configuration: PresenceConfiguration) { self.configuration = configuration }

    public mutating func evaluate(mode: RoutingMode, snapshot: PresenceSnapshot, now: PresenceMoment) -> PresenceRouting {
        let regressed = lastMoment.map { $0.epoch == now.epoch && $0.milliseconds > now.milliseconds } ?? false
        if lastMoment?.epoch != now.epoch || regressed {
            lastDestination = nil
            unavailableSince = nil
            lastEvidenceExpiry = nil
        }
        lastMoment = now
        switch mode {
        case .present: return known(.localMac, .manualPresent, limited: false)
        case .away: return known(.phones, .manualAway, limited: false)
        case .automatic: break
        }
        guard !regressed else { return unavailable(now: now) }
        let remote = fresh(snapshot.remoteWorkspace, now: now)
        let limited = remote == nil || remote == .unsupported
        if remote == .usable { return known(.localMac, .remoteDesktop, limited: false, evidenceAt: snapshot.remoteWorkspace?.observedAt.milliseconds) }
        let locked = fresh(snapshot.locked, now: now)
        if locked == true { return known(.phones, .locked, limited: limited, evidenceAt: snapshot.locked?.observedAt.milliseconds) }
        let workspace = displayState(fresh(snapshot.displays, now: now))
        switch workspace {
        case .off: return known(.phones, .displaysOff, limited: limited, evidenceAt: snapshot.displays?.observedAt.milliseconds)
        case .dark: return known(.phones, .displaysDark, limited: limited, evidenceAt: snapshot.displays?.observedAt.milliseconds)
        case .usable, .unknown: break
        }
        guard locked == false, workspace == .usable,
              let input = snapshot.lastQualifyingInputMilliseconds,
              let lastInput = fresh(input, now: now), lastInput <= input.observedAt.milliseconds else {
            return unavailable(now: now)
        }
        let oldestEvidence = [snapshot.locked?.observedAt.milliseconds, snapshot.displays?.observedAt.milliseconds,
                              input.observedAt.milliseconds].compactMap { $0 }.min()
        if now.milliseconds - lastInput >= configuration.idleMilliseconds {
            return known(.phones, .idle, limited: limited, evidenceAt: oldestEvidence)
        }
        return known(.localMac, .active, limited: limited, evidenceAt: oldestEvidence)
    }

    private func fresh<T: Sendable>(_ observation: PresenceObservation<T>?, now: PresenceMoment) -> T? {
        guard let observation, observation.observedAt.epoch == now.epoch,
              observation.observedAt.milliseconds <= now.milliseconds,
              now.milliseconds - observation.observedAt.milliseconds < configuration.observationLifetimeMilliseconds else { return nil }
        return observation.value
    }

    private enum Workspace { case usable, dark, off, unknown }

    private func displayState(_ displays: [DisplayPresence]?) -> Workspace {
        guard let displays else { return .unknown }
        var hasDark = false
        var hasUnknown = false
        for display in displays {
            switch display {
            case .awake(.readable), .awake(.unknown): return .usable
            case .awake(.dark): hasDark = true
            case .unknown: hasUnknown = true
            case .asleep: break
            }
        }
        if hasUnknown { return .unknown }
        return hasDark ? .dark : .off
    }

    private mutating func known(_ destination: RequestDestination, _ reason: PresenceReason, limited: Bool, evidenceAt: UInt64? = nil) -> PresenceRouting {
        unavailableSince = nil
        lastDestination = destination
        lastEvidenceExpiry = evidenceAt.flatMap {
            let expiry = $0.addingReportingOverflow(configuration.observationLifetimeMilliseconds)
            return expiry.overflow ? nil : expiry.partialValue
        }
        return PresenceRouting(destination: destination, reason: reason, detectionLimited: limited)
    }

    private mutating func unavailable(now: PresenceMoment) -> PresenceRouting {
        let since = unavailableSince ?? min(now.milliseconds, lastEvidenceExpiry ?? now.milliseconds)
        unavailableSince = since
        let inGrace = now.milliseconds - since < configuration.unavailableGraceMilliseconds
        let destination = inGrace ? (lastDestination ?? .phones) : .phones
        return PresenceRouting(destination: destination, reason: .detectorUnavailable, detectionLimited: true)
    }
}
