import Foundation
import XCTest

final class FrontendRuntimeTests: XCTestCase {
    func testReadOnlyTaskViewDistinguishesResumedSigwaitFromBsdStopStatus() throws {
        let result = try runFixture("sigwait-current-state")
        let cases = try XCTUnwrap(result["cases"] as? [[String: Any]])
        XCTAssertEqual(cases.count, 2)
        XCTAssertEqual(cases.map { $0["sigwait"] as? Bool }, [false, true])
        for record in cases {
            for key in ["ready", "resumed", "childReaped"] { XCTAssertEqual(record[key] as? Bool, true, key) }
            XCTAssertEqual(record["beforeBSD"] as? Int, 4)
            XCTAssertEqual(record["beforeSuspendCount"] as? Int, 1)
            XCTAssertEqual(record["afterSuspendCount"] as? Int, 0)
            XCTAssertTrue([2, 3, 4].contains(try XCTUnwrap(record["afterBSD"] as? Int)))
        }
    }
    func testActualOwnerPreservesDynamicReadinessSignalsAndInFlightDescriptorLifetime() throws {
        let result = try runFixture("frontend-runtime")
        XCTAssertEqual(result["failure"] as? Int, 0)
        for key in ["queuedMessagesPreserved", "disabledSourceIdle", "binaryInputPreserved", "threadDirectedSignalWake",
            "latestJobControlIntentPreserved", "foreignMembershipPreserved", "saturatedSignalPreserved", "handlerErrnoPreserved",
            "previousHandlerRestored", "closedDescriptors",
            "inFlightHandlerKeepsDescriptorAlive", "descriptorNumbersActuallyReused", "replacementPipeUntouched",
            "queueClosurePreservesSources", "workerJoined"] {
            XCTAssertEqual(result[key] as? Bool, true, key)
        }
        XCTAssertGreaterThan(try XCTUnwrap(result["saturatedBytes"] as? Int), 0)
    }
    func testActualCooperativeStopPreservesCancellationRestorationAndOrphanedGroupBehavior() throws {
        let result = try runFixture("frontend-suspension", sources: ["FrontendTerminal.c", "CommandStreamSource.c"])
        XCTAssertEqual(result["failure"] as? Int, 0)
        for key in ["orphanedGroupDoesNotHang", "confirmedStopTicketChecked", "noSyntheticContinueChecked", "restoredBeforeActualStop", "crossThreadContinueCancelsStop",
            "backgroundResumeNeverActivates", "foregroundResumeFreshActivation", "latestDimensionsCopied",
            "finalSettingsRestored", "sessionOwnerReaped"] {
            XCTAssertEqual(result[key] as? Bool, true, key)
        }
    }
    private func runFixture(_ name: String, sources: [String] = []) throws -> [String: Any] {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("remozio-frontend-runtime-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let core = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let native = core.appendingPathComponent("Sources/RemozioMach")
        let fixture = try XCTUnwrap(Bundle.module.url(forResource: name, withExtension: "c", subdirectory: "Fixtures/command-process"))
        let driver = directory.appendingPathComponent("driver")
        let compiler = Process(); compiler.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
        compiler.arguments = ["clang", "-std=c11", "-target", "arm64-apple-macos26.0", "-Wall", "-Wextra", "-Werror",
            "-I", native.path, "-I", native.appendingPathComponent("include").path, fixture.path]
            + sources.map { native.appendingPathComponent($0).path } + ["-o", driver.path]
        try compiler.run(); compiler.waitUntilExit()
        XCTAssertEqual(compiler.terminationStatus, 0)
        guard compiler.terminationStatus == 0 else { throw CocoaError(.executableNotLoadable) }
        let process = Process(); process.executableURL = driver
        let output = Pipe(), errors = Pipe(); process.standardOutput = output; process.standardError = errors
        try process.run(); process.waitUntilExit()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        let failure = errors.fileHandleForReading.readDataToEndOfFile()
        XCTAssertEqual(process.terminationStatus, 0, String(decoding: failure, as: UTF8.self))
        guard process.terminationStatus == 0 else { throw CocoaError(.coderReadCorrupt) }
        return try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
    }
}
