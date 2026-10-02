import Foundation

/// Local settings for transient approval wakes. No setting extends a request's original deadline.
public struct GatewayWakePolicy: Sendable {
    public let maximumEntries: Int
    public let maximumAttempts: Int
    public let minimumEnrollmentIntervalMillis: UInt64
    public let maximumLifetimeMillis: UInt64
    public let maximumTTLSeconds: UInt32
    public init(maximumEntries: Int, maximumAttempts: Int, minimumEnrollmentIntervalMillis: UInt64,
                maximumLifetimeMillis: UInt64, maximumTTLSeconds: UInt32) throws {
        guard (1...4096).contains(maximumEntries), (1...32).contains(maximumAttempts),
              (1...3_600_000).contains(minimumEnrollmentIntervalMillis),
              (1...86_400_000).contains(maximumLifetimeMillis), (1...86_400).contains(maximumTTLSeconds) else {
            throw GatewayDeliveryError.invalidConfiguration
        }
        self.maximumEntries = maximumEntries; self.maximumAttempts = maximumAttempts
        self.minimumEnrollmentIntervalMillis = minimumEnrollmentIntervalMillis
        self.maximumLifetimeMillis = maximumLifetimeMillis; self.maximumTTLSeconds = maximumTTLSeconds
    }
}

public enum GatewayWakeStatus: Sendable, Equatable {
    case queued, dispatching, accepted, expired, withdrawn, exhausted, rejected, failed
}

/// Provider acceptance is not phone receipt, request fetch, presentation, or consent.
public struct GatewayWakeProgress: Sendable, Equatable {
    public let deliveryID: UUID
    public let status: GatewayWakeStatus
    public let attempts: Int
    public let lastProviderResult: FCMDeliveryResult?
}

public enum GatewayWakeError: Error, Equatable {
    case unavailable, invalidDelivery, conflictingDelivery, unavailableMapping, localRouting
}
