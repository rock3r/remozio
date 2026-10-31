import RemozioProtocol

/// Explicit wire tags keep the local presence representation independent of the phone schema.
enum RoutingWireProjection {
    static func make(_ state: RoutingState, routing: PresenceRouting) throws -> RoutingStatusState {
        let mode: RoutingStatusMode
        switch state.mode { case .automatic: mode = .automatic; case .present: mode = .present; case .away: mode = .away }
        let destination: RoutingStatusDestination
        switch routing.destination { case .localMac: destination = .localMac; case .phones: destination = .phones }
        let reason: RoutingStatusReason
        switch routing.reason {
        case .manualPresent: reason = .manualPresent
        case .manualAway: reason = .manualAway
        case .remoteDesktop: reason = .remoteDesktop
        case .locked: reason = .locked
        case .displaysOff: reason = .displaysOff
        case .displaysDark: reason = .displaysDark
        case .idle: reason = .idle
        case .active: reason = .active
        case .detectorUnavailable: reason = .detectorUnavailable
        }
        return try .init(mode: mode, revision: state.revision, destination: destination, reason: reason, detectionLimited: routing.detectionLimited)
    }
}
