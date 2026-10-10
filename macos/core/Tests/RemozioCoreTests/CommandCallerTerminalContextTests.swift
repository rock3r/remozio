import Darwin
import Foundation
import XCTest

final class CommandCallerTerminalContextTests: XCTestCase {
    func testOriginalAuditIncarnationRejectsTerminalLossReplacementAndActualExit() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("remozio-terminal-context-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let driver = directory.appendingPathComponent("driver")
        let core = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let native = core.appendingPathComponent("Sources/RemozioMach")
        let fixture = try XCTUnwrap(Bundle.module.url(forResource: "terminal-context", withExtension: "c", subdirectory: "Fixtures/command-process"))
        let compiler = Process(); compiler.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
        compiler.arguments = ["clang", "-target", "arm64-apple-macos26.0", "-Wall", "-Wextra", "-Werror",
            "-I", native.appendingPathComponent("include").path, fixture.path,
            native.appendingPathComponent("CommandTerminalContext.c").path, native.appendingPathComponent("Receive.c").path,
            "-framework", "Security", "-lbsm", "-o", driver.path]
        try compiler.run(); compiler.waitUntilExit()
        XCTAssertEqual(compiler.terminationStatus, 0)
        guard compiler.terminationStatus == 0 else { throw CocoaError(.executableNotLoadable) }
        let process = Process(); process.executableURL = driver
        let output = Pipe(); process.standardOutput = output
        try process.run(); process.waitUntilExit()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        let diagnostic = String(decoding: data, as: UTF8.self)
        XCTAssertEqual(process.terminationStatus, 0, diagnostic)
        let records = try diagnostic.split(separator: "\n").map {
            try XCTUnwrap(try JSONSerialization.jsonObject(with: Data($0.utf8)) as? [String: Any])
        }
        let contexts = records.filter { $0["contextStage"] != nil }
        XCTAssertEqual(contexts.count, 4)
        for record in contexts {
            let stage = try XCTUnwrap(record["contextStage"] as? Int)
            XCTAssertEqual(record["recheckError"] as? Int32, stage == 0 ? 0 : ESTALE)
        }
        let exit = try XCTUnwrap(records.last)
        XCTAssertEqual(exit["originalCallerReaped"] as? Bool, true)
        XCTAssertEqual(exit["exitRecheckError"] as? Int32, ESRCH)
    }
}
