import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class CommandFrontendCallerSettingsTests: XCTestCase {
    private func settings(_ preferences: [String: Any]) throws -> CommandFrontendCallerSettings {
        try .init(preferences: preferences, defaultIOMode: .pipes, defaultDisconnectBehavior: .continueRunning,
            defaultReadiness: .init(timeoutMilliseconds: 98765, initialBackoffMilliseconds: 125,
                maximumBackoffMilliseconds: 3000, controlTimeoutMilliseconds: 6000))
    }
    func testAbsentPreferencesUseInstallationDefaultsWithoutTerminalGuesses() throws {
        let value = try settings([:])
        XCTAssertEqual(value.ioMode, .pipes); XCTAssertEqual(value.disconnectBehavior, .continueRunning)
        XCTAssertEqual(value.readiness.timeoutMilliseconds, 98765)
        XCTAssertEqual(value.readiness.initialBackoffMilliseconds, 125)
        XCTAssertEqual(value.readiness.maximumBackoffMilliseconds, 3000)
        XCTAssertEqual(value.readiness.controlTimeoutMilliseconds, 6000)
        XCTAssertEqual(value.controlRetryMilliseconds, 50); XCTAssertEqual(value.foregroundRetryMilliseconds, 250)
    }
    func testPreferencesChangeCallerSettingsAndCannotSupplyTrustFields() throws {
        let value = try settings([
            CommandFrontendCallerSettings.modeKey: "pty", CommandFrontendCallerSettings.disconnectKey: "terminate",
            CommandFrontendCallerSettings.timeoutKey: String(UInt64.max),
            CommandFrontendCallerSettings.initialBackoffKey: "1", CommandFrontendCallerSettings.maximumBackoffKey: "60000",
            CommandFrontendCallerSettings.controlTimeoutKey: "12000", CommandFrontendCallerSettings.controlRetryKey: "7",
            CommandFrontendCallerSettings.foregroundRetryKey: "123", "authorityPolicy": "false", "serviceName": "untrusted"])
        XCTAssertEqual(value.ioMode, .pty); XCTAssertEqual(value.disconnectBehavior, .terminate)
        XCTAssertEqual(value.readiness.timeoutMilliseconds, UInt64.max)
        XCTAssertEqual(value.readiness.initialBackoffMilliseconds, 1); XCTAssertEqual(value.readiness.maximumBackoffMilliseconds, 60000)
        XCTAssertEqual(value.readiness.controlTimeoutMilliseconds, 12000)
        XCTAssertEqual(value.controlRetryMilliseconds, 7); XCTAssertEqual(value.foregroundRetryMilliseconds, 123)
    }
    func testMalformedAndContradictoryPreferencesDoNotSilentlyFallback() throws {
        for key in [CommandFrontendCallerSettings.timeoutKey, CommandFrontendCallerSettings.initialBackoffKey,
                    CommandFrontendCallerSettings.maximumBackoffKey, CommandFrontendCallerSettings.controlTimeoutKey,
                    CommandFrontendCallerSettings.controlRetryKey, CommandFrontendCallerSettings.foregroundRetryKey] {
            for value: Any in ["", "0", "-1", "1.5", " 50", "50 ", "18446744073709551616", NSNumber(value: 50), true] {
                XCTAssertThrowsError(try settings([key: value]), "\(key): \(value)")
            }
            if key != CommandFrontendCallerSettings.timeoutKey { XCTAssertThrowsError(try settings([key: "60001"])) }
        }
        XCTAssertThrowsError(try settings([CommandFrontendCallerSettings.initialBackoffKey: "4000"])) {
            XCTAssertEqual($0 as? CommandFrontendCallerSettingsError, .invalidPreferences)
        }
        XCTAssertThrowsError(try settings([CommandFrontendCallerSettings.modeKey: "automatic"]))
        XCTAssertThrowsError(try settings([CommandFrontendCallerSettings.disconnectKey: "ignore"]))
    }
}
