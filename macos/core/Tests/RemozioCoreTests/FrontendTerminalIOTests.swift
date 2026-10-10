import Foundation
import XCTest

final class FrontendTerminalIOTests: XCTestCase {
    private func run(_ name: String, wrapper: Bool) throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("remozio-frontend-io-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let core = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let native = core.appendingPathComponent("Sources/RemozioMach")
        let fixture = try XCTUnwrap(Bundle.module.url(forResource: name, withExtension: "c", subdirectory: "Fixtures/command-process"))
        let terminalSource: URL
        if wrapper {
            terminalSource = directory.appendingPathComponent("terminal-wrapper.c")
            try """
            #include <unistd.h>
            #include <termios.h>
            extern int fixture_fake_foreground;
            static pid_t checked_foreground(int descriptor) {
                return fixture_fake_foreground ? getpgrp() : tcgetpgrp(descriptor);
            }
            #define tcgetpgrp checked_foreground
            #include "\(native.appendingPathComponent("FrontendTerminal.c").path)"
            """.write(to: terminalSource, atomically: false, encoding: .utf8)
        } else { terminalSource = native.appendingPathComponent("FrontendTerminal.c") }
        let driver = directory.appendingPathComponent("driver")
        let compiler = Process(); compiler.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
        compiler.arguments = ["clang", "-target", "arm64-apple-macos26.0", "-Wall", "-Wextra", "-Werror",
            "-I", native.appendingPathComponent("include").path, terminalSource.path, fixture.path,
            native.appendingPathComponent("CommandStreamSource.c").path, "-o", driver.path]
        try compiler.run(); compiler.waitUntilExit(); XCTAssertEqual(compiler.terminationStatus, 0)
        guard compiler.terminationStatus == 0 else { throw CocoaError(.executableNotLoadable) }
        let process = Process(); process.executableURL = driver
        let output = Pipe(); process.standardOutput = output
        try process.run(); process.waitUntilExit()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        XCTAssertEqual(process.terminationStatus, 0, String(decoding: data, as: UTF8.self))
        let result = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(result["failure"] as? Int, 0)
        XCTAssertEqual(result["sessionOwnerReaped"] as? Bool, true)
        if wrapper {
            XCTAssertEqual(result["backgroundReadInterrupted"] as? Bool, true)
            XCTAssertEqual(result["queuedInputPreserved"] as? Bool, true)
            XCTAssertEqual(result["restorationRetainedThenCompleted"] as? Bool, true)
        } else {
            XCTAssertEqual(result["outputBackpressureObserved"] as? Bool, true)
            XCTAssertEqual(result["outputMatched"] as? Bool, true)
            XCTAssertEqual(result["exactOutputBytes"] as? Int, 1_048_576)
            XCTAssertEqual(result["binaryInputPreserved"] as? Bool, true)
        }
    }
    func testActualOwnerPreservesBinaryIOThroughRealTerminalBackpressure() throws {
        try run("frontend-terminal-io", wrapper: false)
    }
    func testActualBackgroundReadRaceRejectsUnsafeSignalsAndPreservesInput() throws {
        try run("frontend-terminal-read-race", wrapper: true)
    }
}
