import Foundation

/// Local service policy. These limits do not come from a submitted candidate or provider reply.
public struct GatewayProbePolicy: Sendable {
    public let maximumAttempts: Int
    public let minimumRetryDelayMillis: UInt64
    public let maximumTTLSeconds: UInt32
    public init(maximumAttempts: Int, minimumRetryDelayMillis: UInt64, maximumTTLSeconds: UInt32) throws {
        guard (1...32).contains(maximumAttempts), minimumRetryDelayMillis > 0, maximumTTLSeconds <= 2_419_200 else {
            throw GatewayDatabaseError.invalidConfiguration
        }
        self.maximumAttempts = maximumAttempts; self.minimumRetryDelayMillis = minimumRetryDelayMillis
        self.maximumTTLSeconds = maximumTTLSeconds
    }
}

public enum GatewayProbeError: Error, Equatable {
    case disabled, attemptInFlight, finished, attemptsExhausted, retryNotDue, staleReservation
}

/// Process-bound reservation. Only the originating database can consume it for a single dispatch.
public struct GatewayProbeReservation: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    let owner: UUID
    let operationID: Data
    let identifier: UUID
    let trustRevision: UUID
    public let number: Int
    public var description: String { "GatewayProbeReservation(redacted)" }
    public var debugDescription: String { description }
}

public enum GatewayProbeOutcome: Sendable {
    case accepted
    case retry(minimumDelayMillis: UInt64)
    case terminal
}

public enum GatewayProbeStatus: Int, Sendable {
    case reserved = 1, dispatched = 2, accepted = 3, retryable = 4, terminal = 5
}

/// Operational history only. This status does not prove device delivery or authorize token activation.
public struct GatewayProbeProgress: Sendable {
    public let number: Int
    public let status: GatewayProbeStatus
    public let retryAtMilliseconds: UInt64?
}
