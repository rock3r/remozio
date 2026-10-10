import Foundation
import XCTest

final class FrontendTerminalTests: XCTestCase {
    private var directory: URL!, driver: URL!
    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent("remozio-frontend-terminal-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        driver = directory.appendingPathComponent("driver")
        let core = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let native = core.appendingPathComponent("Sources/RemozioMach")
        let fixture = try XCTUnwrap(Bundle.module.url(forResource: "frontend-terminal", withExtension: "c", subdirectory: "Fixtures/command-process"))
        let wrapper = directory.appendingPathComponent("terminal-wrapper.c")
        try """
        #include <unistd.h>
        #include <termios.h>
        extern int fixture_fake_foreground;
        static pid_t checked_foreground(int descriptor) {
            return fixture_fake_foreground ? getpgrp() : tcgetpgrp(descriptor);
        }
        #define tcgetpgrp checked_foreground
        #include "\(native.appendingPathComponent("FrontendTerminal.c").path)"
        """.write(to: wrapper, atomically: false, encoding: .utf8)
        let compiler = Process(); compiler.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
        compiler.arguments = ["clang", "-target", "arm64-apple-macos26.0", "-Wall", "-Wextra", "-Werror",
            "-I", native.appendingPathComponent("include").path, wrapper.path, fixture.path, native.appendingPathComponent("CommandStreamSource.c").path, "-o", driver.path]
        try compiler.run(); compiler.waitUntilExit()
        XCTAssertEqual(compiler.terminationStatus, 0)
        guard compiler.terminationStatus == 0 else { throw CocoaError(.executableNotLoadable) }
    }
    override func tearDownWithError() throws {
        if let directory { try FileManager.default.removeItem(at: directory) }
    }
    private func run(_ mode: String) throws {
        let process = Process(); process.executableURL = driver; process.arguments = [mode]
        let output = Pipe(); process.standardOutput = output
        try process.run(); process.waitUntilExit()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        XCTAssertEqual(process.terminationStatus, 0, String(decoding: data, as: UTF8.self))
        let record = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(record["failure"] as? Int, 0)
        XCTAssertEqual(record["sessionOwnerReaped"] as? Bool, true)
    }
    func testIndependentOwnerRestoresFreshSettingsAndPreservesUnreadInput() throws { try run("lifecycle") }
    func testDynamicTerminalAliasUsesAnIndependentPhysicalTerminalOwner() throws { try run("terminal-alias") }
    func testBackgroundResumeWaitsWithoutTakingForeground() throws { try run("background") }
    func testKernelRejectsForegroundLossDuringRawActivation() throws { try run("kernel-race") }
    func testIgnoredBlockedDefaultAndRestartingSignalsPreventRawMode() throws { try run("signal-guards") }
    func testReusedSourceDescriptorsCannotRedirectTheRetainedTerminal() throws { try run("source-reuse") }
    func testForkedCopyCannotChangeTheOriginalTerminal() throws { try run("fork-owner") }
}
