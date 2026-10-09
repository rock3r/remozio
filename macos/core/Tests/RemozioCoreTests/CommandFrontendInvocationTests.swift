import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class CommandFrontendInvocationTests: XCTestCase {
    private func bytes(_ text: String) -> Data { Data(text.utf8) }
    private func limits(bytes: Int = 8192, items: Int = 1024) throws -> CBORLimits {
        try CBORLimits(maxBytes: bytes, maxDepth: 16, maxItems: items)
    }
    private func parse(_ values: [Data], mode: CommandIOMode = .pipes,
                       disconnect: StartedCommandDisconnect = .terminate) throws -> CommandFrontendInvocation {
        try .init(arguments: values, defaultIOMode: mode, defaultDisconnectBehavior: disconnect, limits: limits())
    }
    private func argv(_ values: [String]) -> [Data] { values.map(bytes) }
    private func copied(_ values: [Data], limits: CBORLimits? = nil) throws -> [Data] {
        let vector = UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>.allocate(capacity: values.count + 1)
        var allocations: [UnsafeMutablePointer<CChar>] = []
        defer { allocations.forEach { $0.deallocate() }; vector.deallocate() }
        for (index, data) in values.enumerated() {
            let pointer = UnsafeMutablePointer<CChar>.allocate(capacity: data.count + 1)
            for (offset, byte) in data.enumerated() { pointer[offset] = CChar(bitPattern: byte) }
            pointer[data.count] = 0; allocations.append(pointer); vector[index] = pointer
        }
        vector[values.count] = nil
        return try CommandFrontendInvocation.copyArguments(count: Int32(values.count), vector: UnsafePointer(vector),
                                                           limits: limits ?? self.limits())
    }
    private func withPath<T>(_ path: Data, _ body: (UnsafePointer<CChar>) throws -> T) rethrows -> T {
        var terminated = path; terminated.append(0)
        return try terminated.withUnsafeBytes { try body($0.baseAddress!.assumingMemoryBound(to: CChar.self)) }
    }

    func testActualCVectorPreservesEmptyInvalidUTF8AndControlBytesThroughSubmission() throws {
        let raw = argv(["remozio", "sudo", "--", "/bin/echo", ""]) + [Data([0xff, 0xfe, 0x0a, 0x1b]), bytes("$(touch /tmp/unwanted)")]
        let invocation = try parse(copied(raw))
        let binding = CapturedSubmission(id: Data(repeating: 1, count: 16), nonce: Data(repeating: 2, count: 32),
                                         callerBinding: Data(repeating: 3, count: 16))
        let submission = try invocation.submission(directory: bytes("/tmp"), executablePath: bytes("/bin/echo"),
                                                   binding: binding, schemaVersion: 1, limits: limits())
        let decoded = try CommandSubmission(canonicalBytes: submission.canonicalBytes, limits: limits(), expectedSchemaVersion: 1)
        XCTAssertEqual(decoded.arguments, Array(raw[3...])); XCTAssertEqual(decoded.binding, binding)
        XCTAssertEqual(decoded.requestedTargetUID, 0); XCTAssertEqual(decoded.environmentAdditions, [])
    }
    func testBothCommandNamesProduceTheSameClaims() throws {
        XCTAssertEqual(try parse(argv(["remozio", "run", "--", "tool"])),
                       try parse(argv(["remozio", "sudo", "--", "tool"])))
    }
    func testTargetOptionsAndShellOperatorsAreNotFrontendOptions() throws {
        let raw = argv(["remozio", "run", "--", "tool", "--pty", "--env", "SECRET=x", ">", "file", "&&", "true", "--"])
        let invocation = try parse(raw)
        XCTAssertEqual(invocation.arguments, Array(raw[3...])); XCTAssertEqual(invocation.ioMode, .pipes)
        XCTAssertEqual(invocation.environmentAdditions, [])
    }
    func testExplicitOptionsPreserveRawEnvironmentAndLastRequestedValues() throws {
        let raw = argv(["remozio", "run", "--pty", "--pipes", "--uid", "4294967295", "--env", "Z=old", "--env", "EMPTY=", "--env"])
            + [bytes("RAW=") + Data([0xff, 0x0a, 0x3d])]
            + argv(["--env", "Z=new=value", "--on-disconnect", "continue", "--reason", "caller supplied\nreason", "--", "tool"])
        let invocation = try parse(raw)
        XCTAssertEqual(invocation.requestedTargetUID, UInt32.max); XCTAssertEqual(invocation.ioMode, .pipes)
        XCTAssertEqual(invocation.disconnectBehavior, .continueRunning)
        XCTAssertEqual(invocation.unverifiedRationale, "caller supplied\nreason")
        XCTAssertEqual(invocation.environmentAdditions, [
            .init(name: bytes("EMPTY"), value: Data()), .init(name: bytes("RAW"), value: Data([0xff, 0x0a, 0x3d])),
            .init(name: bytes("Z"), value: bytes("new=value"))])
    }
    func testDefaultsComeFromSettingsAndCanBeOverridden() throws {
        let base = argv(["remozio", "run", "--", "tool"])
        let invocation = try parse(base, mode: .pty, disconnect: .continueRunning)
        XCTAssertEqual(invocation.ioMode, .pty); XCTAssertEqual(invocation.disconnectBehavior, .continueRunning)
        let overridden = try parse(argv(["remozio", "run", "--pipes", "--on-disconnect", "terminate", "--", "tool"]),
                                   mode: .pty, disconnect: .continueRunning)
        XCTAssertEqual(overridden.ioMode, .pipes); XCTAssertEqual(overridden.disconnectBehavior, .terminate)
    }
    func testUIDOverflowSignsAndNonDigitsAreRejected() throws {
        for value in ["4294967296", "-1", "+1", "1.0", "", "１２"] {
            XCTAssertThrowsError(try parse(argv(["remozio", "run", "--uid", value, "--", "tool"]))) {
                XCTAssertEqual($0 as? CommandFrontendInvocationError, .invalidUserID)
            }
        }
    }
    func testMissingSeparatorDoesNotGuessWhichArgumentIsTheCommand() throws {
        XCTAssertThrowsError(try parse(argv(["remozio", "run", "--pty"]))) {
            XCTAssertEqual($0 as? CommandFrontendInvocationError, .missingSeparator)
        }
        XCTAssertThrowsError(try parse(argv(["remozio", "run", "tool"]))) {
            XCTAssertEqual($0 as? CommandFrontendInvocationError, .unknownOption)
        }
    }
    func testUnknownCommandMissingExecutableAndEmptyExecutableAreDistinct() throws {
        for (values, error) in [(["remozio", "exec", "--", "tool"], CommandFrontendInvocationError.unknownCommand),
                                (["remozio", "run", "--"], .missingExecutable), (["remozio", "sudo", "--", ""], .missingExecutable)] {
            XCTAssertThrowsError(try parse(argv(values))) { XCTAssertEqual($0 as? CommandFrontendInvocationError, error) }
        }
    }
    func testMalformedOptionsDoNotBecomeTargetArguments() throws {
        for option in ["--env", "--uid", "--reason", "--on-disconnect"] {
            XCTAssertThrowsError(try parse(argv(["remozio", "run", option, "--", "tool"]))) {
                XCTAssertEqual($0 as? CommandFrontendInvocationError, .missingOptionValue)
            }
        }
        for value in ["NO_EQUALS", "=missing_name"] {
            XCTAssertThrowsError(try parse(argv(["remozio", "run", "--env", value, "--", "tool"]))) {
                XCTAssertEqual($0 as? CommandFrontendInvocationError, .invalidEnvironment)
            }
        }
        XCTAssertThrowsError(try parse(argv(["remozio", "run", "--on-disconnect", "retry", "--", "tool"]))) {
            XCTAssertEqual($0 as? CommandFrontendInvocationError, .invalidDisconnectBehavior)
        }
        XCTAssertThrowsError(try parse(argv(["remozio", "run", "--reason"]) + [Data([0xff])] + argv(["--", "tool"]))) {
            XCTAssertEqual($0 as? CommandFrontendInvocationError, .invalidRationale)
        }
    }
    func testBoundsCountEmptyArgumentsAndCStringsBeforeCopying() throws {
        let raw = argv(["r", "run", "--", "t", "", ""])
        XCTAssertEqual(try copied(raw, limits: limits(bytes: 13)), raw)
        XCTAssertThrowsError(try copied(raw, limits: limits(bytes: 12))) {
            XCTAssertEqual($0 as? CommandFrontendInvocationError, .oversized)
        }
        XCTAssertThrowsError(try copied(raw, limits: limits(items: 5)))
        XCTAssertThrowsError(try CommandFrontendInvocation(arguments: raw, defaultIOMode: .pipes,
            defaultDisconnectBehavior: .terminate, limits: limits(bytes: 12)))
        XCTAssertThrowsError(try parse(argv(["r", "run", "--", "t"]) + [Data([1, 0, 2])])) {
            XCTAssertEqual($0 as? CommandFrontendInvocationError, .invalidArguments)
        }
    }
    func testMissingPointerIsRejectedWithoutInventingAnEmptyArgument() throws {
        let vector = UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>.allocate(capacity: 1)
        defer { vector.deallocate() }; vector[0] = nil
        XCTAssertThrowsError(try CommandFrontendInvocation.copyArguments(count: 1, vector: UnsafePointer(vector), limits: limits())) {
            XCTAssertEqual($0 as? CommandFrontendInvocationError, .invalidArguments)
        }
    }
    func testAbsoluteAndRelativeClaimsDoNotRewriteArgvZeroOrResolveSymlinks() throws {
        for executable in ["/bin/../bin/echo", "./linked-tool", "subdir/../tool"] {
            let invocation = try parse(argv(["r", "run", "--", executable]))
            let path = try invocation.executablePath(directory: bytes("/tmp/cwd"), searchPath: bytes("/ignored"))
            XCTAssertEqual(path, bytes(executable.hasPrefix("/") ? executable : "/tmp/cwd/" + executable))
            XCTAssertEqual(invocation.arguments[0], bytes(executable))
        }
    }
    func testRawPathSearchUsesCapturedDirectoryAndPreservesSelectedBytes() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("remozio-frontend-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let base = bytes(directory.path), name = bytes("tool-é"), path = base + bytes("/") + name
        let fd = withPath(path) { open($0, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o700) }
        XCTAssertGreaterThanOrEqual(fd, 0); guard fd >= 0 else { throw CommandFrontendInvocationError.system(errno) }
        XCTAssertEqual(write(fd, "fixture", 7), 7); close(fd)
        let invocation = try parse(argv(["r", "run", "--"]) + [name, Data([0xfe])])
        let selected = try invocation.executablePath(directory: base, searchPath: bytes("/missing::/bin"))
        XCTAssertEqual(selected, path)
        let capture = try CommandFilesystemCapture(executablePath: selected, directoryPath: base)
        defer { capture.close() }; try capture.recheck()
        XCTAssertEqual(capture.executable.path, path); XCTAssertEqual(invocation.arguments[0], name)
        XCTAssertEqual(try invocation.executablePath(directory: base, searchPath: Data()), path)
    }
    func testPathSearchSkipsOverlongEntriesAndUsesRelativeDirectories() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("remozio-search-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory.appendingPathComponent("bin"), withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let tool = directory.appendingPathComponent("bin/tool")
        try Data("fixture".utf8).write(to: tool); XCTAssertEqual(chmod(tool.path, 0o700), 0)
        let invocation = try parse(argv(["r", "run", "--", "tool"]))
        let search = Data(repeating: 0x61, count: Int(PATH_MAX)) + bytes(":bin")
        XCTAssertEqual(try invocation.executablePath(directory: bytes(directory.path), searchPath: search), bytes(tool.path))
    }
    func testInvalidUTF8PathClaimIsPreservedForRootValidation() throws {
        let raw = bytes("/tmp/raw-") + Data([0xff])
        let invocation = try parse(argv(["r", "run", "--"]) + [raw])
        XCTAssertEqual(try invocation.executablePath(directory: bytes("/tmp"), searchPath: Data()), raw)
    }
    func testPathSearchSkipsDirectoriesAndNonExecutableFiles() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("remozio-search-types-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory.appendingPathComponent("a/echo"), withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: directory.appendingPathComponent("b"), withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let nonExecutable = directory.appendingPathComponent("b/echo")
        try Data("fixture".utf8).write(to: nonExecutable); XCTAssertEqual(chmod(nonExecutable.path, 0o600), 0)
        let invocation = try parse(argv(["r", "run", "--", "echo"]))
        XCTAssertEqual(try invocation.executablePath(directory: bytes(directory.path), searchPath: bytes("a:b:/bin")), bytes("/bin/echo"))
        let missing = try parse(argv(["r", "run", "--", "definitely-missing-remozio-fixture"]))
        XCTAssertThrowsError(try missing.executablePath(directory: bytes("/tmp"), searchPath: bytes("/bin"))) {
            XCTAssertEqual($0 as? CommandFrontendInvocationError, .executableNotFound)
        }
        XCTAssertThrowsError(try invocation.executablePath(directory: bytes("relative"), searchPath: bytes("/bin")))
        XCTAssertThrowsError(try invocation.executablePath(directory: bytes("/tmp"), searchPath: Data([0])))
    }
    func testCurrentDirectoryIsAnActualAbsoluteFilesystemPath() throws {
        let cwd = try CommandFrontendInvocation.currentDirectory()
        XCTAssertEqual(cwd.first, 0x2f); XCTAssertFalse(cwd.contains(0))
        var captured = stat(), current = stat()
        XCTAssertEqual(withPath(cwd) { stat($0, &captured) }, 0)
        XCTAssertEqual(stat(".", &current), 0)
        XCTAssertEqual(captured.st_dev, current.st_dev); XCTAssertEqual(captured.st_ino, current.st_ino)
    }
}
