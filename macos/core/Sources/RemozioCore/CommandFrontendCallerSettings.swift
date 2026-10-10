import Foundation
import RemozioProtocol

public enum CommandFrontendCallerSettingsError: Error, Equatable { case invalidPreferences }

/// User preferences control caller behavior. They contain no installation identity or authority pins.
public struct CommandFrontendCallerSettings: Sendable {
    public static let modeKey = "commandDefaultIOMode"
    public static let disconnectKey = "commandDefaultDisconnect"
    public static let timeoutKey = "commandReadinessTimeoutMilliseconds"
    public static let initialBackoffKey = "commandInitialBackoffMilliseconds"
    public static let maximumBackoffKey = "commandMaximumBackoffMilliseconds"
    public static let controlTimeoutKey = "commandControlTimeoutMilliseconds"
    public static let controlRetryKey = "commandControlRetryMilliseconds"
    public static let foregroundRetryKey = "commandForegroundRetryMilliseconds"

    public let ioMode: CommandIOMode
    public let disconnectBehavior: StartedCommandDisconnect
    public let readiness: CommandCallerReadinessConfiguration
    public let controlRetryMilliseconds: UInt32
    public let foregroundRetryMilliseconds: UInt32

    public init(preferences: [String: Any], defaultIOMode: CommandIOMode,
                defaultDisconnectBehavior: StartedCommandDisconnect,
                defaultReadiness: CommandCallerReadinessConfiguration) throws {
        func text(_ key: String) throws -> String? {
            guard let value = preferences[key] else { return nil }
            guard let value = value as? String else { throw CommandFrontendCallerSettingsError.invalidPreferences }
            return value
        }
        func number(_ key: String, fallback: UInt64) throws -> UInt64 {
            guard let value = try text(key) else { return fallback }
            guard !value.isEmpty, value.utf8.allSatisfy({ (48...57).contains($0) }),
                  let result = UInt64(value), result > 0 else { throw CommandFrontendCallerSettingsError.invalidPreferences }
            return result
        }
        func duration(_ key: String, fallback: UInt32) throws -> UInt32 {
            guard let value = UInt32(exactly: try number(key, fallback: UInt64(fallback))),
                  (1...60_000).contains(value) else { throw CommandFrontendCallerSettingsError.invalidPreferences }
            return value
        }
        switch try text(Self.modeKey) {
        case nil: ioMode = defaultIOMode
        case "pty": ioMode = .pty
        case "pipes": ioMode = .pipes
        default: throw CommandFrontendCallerSettingsError.invalidPreferences
        }
        switch try text(Self.disconnectKey) {
        case nil: disconnectBehavior = defaultDisconnectBehavior
        case "terminate": disconnectBehavior = .terminate
        case "continue": disconnectBehavior = .continueRunning
        default: throw CommandFrontendCallerSettingsError.invalidPreferences
        }
        do {
            readiness = try .init(timeoutMilliseconds: number(Self.timeoutKey, fallback: defaultReadiness.timeoutMilliseconds),
                initialBackoffMilliseconds: duration(Self.initialBackoffKey, fallback: defaultReadiness.initialBackoffMilliseconds),
                maximumBackoffMilliseconds: duration(Self.maximumBackoffKey, fallback: defaultReadiness.maximumBackoffMilliseconds),
                controlTimeoutMilliseconds: duration(Self.controlTimeoutKey, fallback: defaultReadiness.controlTimeoutMilliseconds))
        } catch { throw CommandFrontendCallerSettingsError.invalidPreferences }
        controlRetryMilliseconds = try duration(Self.controlRetryKey, fallback: 50)
        foregroundRetryMilliseconds = try duration(Self.foregroundRetryKey, fallback: 250)
    }
}
