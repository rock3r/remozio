import Darwin
import Foundation
import RemozioMach
import XCTest
@testable import RemozioCore

final class CommandStreamSourceTests: XCTestCase {
    private var directory: URL!, driver: URL!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent("remozio-terminal-source-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        driver = directory.appendingPathComponent("driver")
        let core = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let native = core.appendingPathComponent("Sources/RemozioMach")
        let fixture = try XCTUnwrap(Bundle.module.url(forResource: "terminal-source", withExtension: "c", subdirectory: "Fixtures/command-process"))
        let compiler = Process(); compiler.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
        compiler.arguments = ["clang", "-target", "arm64-apple-macos26.0", "-Wall", "-Wextra", "-Werror",
            "-I", native.appendingPathComponent("include").path, fixture.path,
            native.appendingPathComponent("CommandStreamSource.c").path, "-o", driver.path]
        try compiler.run(); compiler.waitUntilExit()
        XCTAssertEqual(compiler.terminationStatus, 0)
        guard compiler.terminationStatus == 0 else { throw CocoaError(.executableNotLoadable) }
    }

    override func tearDownWithError() throws {
        if let directory { try FileManager.default.removeItem(at: directory) }
    }

    private func run(flags: Int32) throws {
        let process = Process(); process.executableURL = driver; process.arguments = [String(flags)]
        let output = Pipe(); process.standardOutput = output
        try process.run(); process.waitUntilExit()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        let diagnostic = String(decoding: data, as: UTF8.self)
        XCTAssertEqual(process.terminationStatus, 0, diagnostic)
        let records = try diagnostic.split(separator: "\n").map {
            try XCTUnwrap(try JSONSerialization.jsonObject(with: Data($0.utf8)) as? [String: Any])
        }
        XCTAssertEqual(records.count, 2, diagnostic)
        guard records.count == 2 else { return }
        XCTAssertEqual(records[0]["physicalSessionMatchesCaller"] as? Bool, true)
        XCTAssertEqual(records[0]["aliasSessionMatchesCaller"] as? Bool, flags >= 0)
        XCTAssertEqual(records[0]["fstatIdentitiesEqual"] as? Bool, flags >= 0)
        XCTAssertEqual(records[0]["kernelCallerTTYDeviceMatchesPhysical"] as? Bool, true)
        XCTAssertEqual(records[1]["aliasRebindsToReceivingSession"] as? Bool, flags < 0)
        XCTAssertEqual(records[1]["physicalSourceStillNamesOriginalCaller"] as? Bool, true)
        for record in records { XCTAssertEqual(record["aliasFlagsUnchanged"] as? Bool, true) }
    }

    func testRawAliasActuallyRebindsAcrossMachTransfer() throws { try run(flags: -1) }

    func testBoundAliasKeepsCallerIdentityAcrossMachTransferAndReceiverSessionChange() throws {
        for access in [O_RDONLY, O_WRONLY, O_RDWR] { try run(flags: access) }
    }

    func testIndependentTerminalDescriptionPreservesIOFlagsSettingsAndUnreadBytes() throws {
        for flags in [O_NONBLOCK, O_APPEND, O_ASYNC, O_SYNC, O_NONBLOCK | O_APPEND | O_ASYNC | O_SYNC] {
            try run(flags: O_RDWR | flags)
        }
    }

    func testOrdinaryPipeRetainsItsDescriptionAndDoesNotConsumeInput() throws {
        var descriptors: [Int32] = [-1, -1]
        XCTAssertEqual(pipe(&descriptors), 0)
        defer { for fd in descriptors { _ = Darwin.close(fd) } }
        let bytes = Data([0x00, 0xfe, 0x0a])
        XCTAssertEqual(bytes.withUnsafeBytes { Darwin.write(descriptors[1], $0.baseAddress, $0.count) }, bytes.count)
        let original = fcntl(descriptors[0], F_GETFL)
        try CommandStreamSource.withRetainedDescriptor(descriptors[0]) { retained in
            XCTAssertNotEqual(retained, descriptors[0])
            XCTAssertNotEqual(fcntl(retained, F_GETFD) & FD_CLOEXEC, 0)
            XCTAssertEqual(fcntl(retained, F_SETFL, original | O_NONBLOCK), 0)
            XCTAssertEqual(fcntl(descriptors[0], F_GETFL), original | O_NONBLOCK)
            XCTAssertEqual(fcntl(retained, F_SETFL, original), 0)
        }
        XCTAssertEqual(fcntl(descriptors[0], F_GETFL), original)
        var actual = [UInt8](repeating: 0, count: bytes.count)
        XCTAssertEqual(Darwin.read(descriptors[0], &actual, actual.count), bytes.count)
        XCTAssertEqual(Data(actual), bytes)
    }

    func testClosedDescriptorDoesNotProduceAnOwnedResource() throws {
        var output: Int32 = 42
        XCTAssertEqual(remozio_command_stream_source_retain(-1, &output), EBADF)
        XCTAssertEqual(output, -1)
    }
}
