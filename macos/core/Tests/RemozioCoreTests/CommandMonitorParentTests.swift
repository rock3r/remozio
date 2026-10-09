import Darwin
import Foundation
import XCTest

final class CommandMonitorParentTests: XCTestCase {
    private var directory: URL!, child: URL!, monitor: URL!, driver: URL!, faultDriver: URL!, malformedMonitor: URL!
    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent("remozio-monitor-parent-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        child = directory.appendingPathComponent("child"); monitor = directory.appendingPathComponent("monitor")
        driver = directory.appendingPathComponent("driver"); faultDriver = directory.appendingPathComponent("fault-driver")
        malformedMonitor = directory.appendingPathComponent("malformed-monitor")
        let core = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let native = core.appendingPathComponent("Sources/RemozioMach")
        let product = core.deletingLastPathComponent().appendingPathComponent("app/CommandMonitor/MonitorMain.c")
        let wrapper = directory.appendingPathComponent("fixture-monitor.c")
        // This wrapper changes only the UID guard. The fixture grants no privilege and is never packaged.
        try """
        #include <unistd.h>
        static uid_t fixture_root_uid(void) { return 0; }
        #define getuid fixture_root_uid
        #define geteuid fixture_root_uid
        #include "\(product.path)"
        """.write(to: wrapper, atomically: false, encoding: .utf8)
        func fixture(_ name: String) throws -> URL {
            try XCTUnwrap(Bundle.module.url(forResource: name, withExtension: "c", subdirectory: "Fixtures/command-process"))
        }
        let specification = native.appendingPathComponent("CommandChildSpecification.c")
        let protocolSource = native.appendingPathComponent("CommandMonitorProtocol.c")
        try compile([wrapper, native.appendingPathComponent("CommandProcess.c"), specification, protocolSource], native: native, output: monitor)
        try compile([fixture("child"), specification], native: native, output: child)
        try compile([native.appendingPathComponent("CommandMonitor.c"), fixture("monitor-parent-driver"), specification,
                     protocolSource, native.appendingPathComponent("CommandPTY.c")], native: native, output: driver)
        try compile([fixture("monitor-parent-fault-wrapper"), fixture("monitor-parent-fault-driver"), specification, protocolSource],
                    native: native, output: faultDriver)
        try compile([fixture("malformed-monitor"), protocolSource], native: native, output: malformedMonitor)
    }
    override func tearDownWithError() throws { if let directory { try FileManager.default.removeItem(at: directory) } }
    private func compile(_ sources: [URL], native: URL, output: URL) throws {
        let compiler = Process(); compiler.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
        compiler.arguments = ["clang", "-target", "arm64-apple-macos26.0", "-Wall", "-Wextra", "-Werror", "-I", native.path,
                              "-I", native.appendingPathComponent("include").path] + sources.map(\.path) + ["-o", output.path]
        try compiler.run(); compiler.waitUntilExit(); XCTAssertEqual(compiler.terminationStatus, 0)
        guard compiler.terminationStatus == 0 else { throw CocoaError(.executableNotLoadable) }
    }
    private func run(_ mode: String, fault: Int32? = nil, malformed: Bool = false) throws {
        let arguments = [Data([0xff]), Data(), Data([0xfe]), Data((mode.contains("stop_resume") ? "plain_stop" : "output").utf8)]
        let environment = [Data("CWD=\(directory.path)".utf8), Data("EMPTY=".utf8), Data([0x52,0x41,0x57,0x3d,0xfd])]
        var body = Data()
        let executable = mode == "exec_failure" ? directory.appendingPathComponent("missing-target").path : child.path
        for value in [Data(executable.utf8)] + arguments + environment {
            var size = UInt32(value.count).bigEndian; withUnsafeBytes(of: &size) { body.append(contentsOf: $0) }; body.append(value)
        }
        var frame = Data()
        for value in [UInt32(0x524d4331), UInt32(body.count), getuid(), getgid(), 0, UInt32(arguments.count),
                      UInt32(environment.count), 5000, 0o022, mode.hasPrefix("pty_") ? 1 : 0] {
            var word = value.bigEndian; withUnsafeBytes(of: &word) { frame.append(contentsOf: $0) }
        }
        frame.append(body)
        let file = directory.appendingPathComponent("frame.bin"); try frame.write(to: file)
        let process = Process(); process.executableURL = fault == nil ? driver : faultDriver; process.currentDirectoryURL = directory
        process.arguments = [(malformed ? malformedMonitor : monitor).path,
                             malformed ? directory.appendingPathComponent(mode).path : child.path, file.path, mode]
        if let fault { process.arguments?.append(String(fault)); process.environment = ["PARENT_FAULT": mode] }
        let output = Pipe(); process.standardOutput = output
        try process.run(); process.waitUntilExit()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        XCTAssertEqual(process.terminationStatus, 0, String(decoding: data, as: UTF8.self))
        let record = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(record["failure"] as? Int, 0)
        XCTAssertEqual(record["monitorActuallyReaped"] as? Bool, mode != "preflight")
    }
    func testExactSeparatePipesAndInputRetention() throws { try run("output") }
    func testIndependentExecExitAndActualMonitorWait() throws { try run("stop_resume") }
    func testPreparedCancellationNeverExecutes() throws { try run("cancel") }
    func testImmediateCancellationRetiresTheMonitor() throws { try run("immediate_cancel") }
    func testOwnedTerminalStopResume() throws { try run("pty_stop_resume") }
    func testOwnedTerminalCancellationRetainsItsMasterUntilCleanup() throws { try run("pty_cancel") }
    func testExecFailureHasNoFalseKernelExec() throws { try run("exec_failure") }
    func testRejectedPreflightCreatesNoOwnerAndPreservesInput() throws { try run("preflight") }
    func testMonitorRegistrationFailureRetainsAndRetiresTheSuspendedOwner() throws { try run("register_monitor", fault: EPERM) }
    func testFirstResumeFailureRetiresTheSuspendedOwner() throws { try run("resume_monitor", fault: EPERM) }
    func testTargetMetadataFailurePreventsRelease() throws { try run("target_metadata", fault: ESRCH) }
    func testTargetRegistrationFailurePreventsRelease() throws { try run("target_register", fault: EPERM) }
    func testTargetMustRemainTheMonitorChild() throws { try run("target_nonchild", fault: ESRCH) }
    func testTargetBirthMustMatchTheReportedBirth() throws { try run("target_birth", fault: EPROTO) }
    func testTargetBirthMustStayBoundAcrossKernelRegistration() throws { try run("target_second_snapshot", fault: EPROTO) }
    func testRejectedStatusClosesThePipeAndRetiresABlockedWriter() throws { try run("blocked_bad_status", fault: EPROTO, malformed: true) }
    func testBadStatusVersionIsSticky() throws { try run("bad_version", fault: EPROTO, malformed: true) }
    func testTruncatedStatusEOFPreventsRelease() throws { try run("partial", fault: EPROTO, malformed: true) }
    func testSkippedStatusSequencePreventsRelease() throws { try run("bad_sequence", fault: EPROTO, malformed: true) }
    func testMonitorCannotReportItselfAsTheTarget() throws { try run("same_pid", fault: EPROTO, malformed: true) }
}
