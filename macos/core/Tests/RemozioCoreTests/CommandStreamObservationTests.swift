import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class CommandStreamObservationTests: XCTestCase {
    private let binding = Data(repeating: 0x71, count: 16)

    func testFileAccessAndEveryFlagCombinationRemainUnchanged() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("remozio-stream-observation-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("source").path
        for access in [O_RDONLY, O_WRONLY, O_RDWR] {
            for mask in 0..<16 {
                let bits: [Int32] = [O_APPEND, O_NONBLOCK, O_ASYNC, O_SYNC]
                let flags = bits.enumerated().reduce(access) { $0 | (mask & (1 << $1.offset) == 0 ? 0 : $1.element) }
                let descriptor = open(path, flags | O_CREAT | O_CLOEXEC, 0o600)
                XCTAssertGreaterThanOrEqual(descriptor, 0)
                guard descriptor >= 0 else { throw POSIXError(.init(rawValue: errno) ?? .EIO) }
                defer { _ = Darwin.close(descriptor) }
                let originalFlags = fcntl(descriptor, F_GETFL)
                let resolved = try XCTUnwrap(realpath(path, nil))
                defer { free(resolved) }
                let observation = try CommandStreamObservation(descriptor: descriptor, streamBinding: binding)
                XCTAssertEqual(observation.captured.source.kind, .file)
                XCTAssertEqual(observation.captured.source.streamBinding, binding)
                XCTAssertEqual(observation.captured.source.observedPath, Data(String(cString: resolved).utf8))
                XCTAssertEqual(observation.captured.access.rawValue, UInt64([O_RDONLY, O_WRONLY, O_RDWR].firstIndex(of: access)!))
                for (index, flag) in bits.enumerated() {
                    XCTAssertEqual(observation.captured.flags.rawValue & (1 << index) != 0, originalFlags & flag != 0)
                }
                XCTAssertEqual(fcntl(descriptor, F_GETFL), originalFlags)
                XCTAssertNil(observation.terminalSessionID)
                XCTAssertNil(observation.terminalDevice)
                try observation.recheck(descriptor: descriptor)
                XCTAssertEqual(fcntl(descriptor, F_GETFL), originalFlags)
            }
        }
    }

    func testPipeInputStaysUnreadAndSharedFlagChangeFailsRecheck() throws {
        var descriptors: [Int32] = [-1, -1]
        XCTAssertEqual(pipe(&descriptors), 0)
        defer { for descriptor in descriptors { _ = Darwin.close(descriptor) } }
        let bytes: [UInt8] = [0, 0xff, 10]
        XCTAssertEqual(bytes.withUnsafeBytes { Darwin.write(descriptors[1], $0.baseAddress, $0.count) }, bytes.count)
        let originalFlags = fcntl(descriptors[0], F_GETFL)
        let observation = try CommandStreamObservation(descriptor: descriptors[0], streamBinding: binding)
        XCTAssertEqual(observation.captured.source.kind, .pipe)
        XCTAssertEqual(observation.captured.access, .readOnly)
        let output = try CommandStreamObservation(descriptor: descriptors[1], streamBinding: binding)
        XCTAssertEqual(output.captured.access, .writeOnly)
        try observation.recheck(descriptor: descriptors[0])
        XCTAssertEqual(fcntl(descriptors[0], F_GETFL), originalFlags)
        let shared = dup(descriptors[0])
        XCTAssertGreaterThanOrEqual(shared, 0)
        defer { _ = Darwin.close(shared) }
        XCTAssertEqual(fcntl(shared, F_SETFL, originalFlags | O_NONBLOCK), 0)
        XCTAssertThrowsError(try observation.recheck(descriptor: descriptors[0])) {
            XCTAssertEqual($0 as? CommandStreamObservationError, .changed)
        }
        XCTAssertEqual(fcntl(shared, F_SETFL, originalFlags), 0)
        try observation.recheck(descriptor: descriptors[0])
        var actual = [UInt8](repeating: 0, count: bytes.count)
        XCTAssertEqual(Darwin.read(descriptors[0], &actual, actual.count), bytes.count)
        XCTAssertEqual(actual, bytes)
    }

    func testPTYObservationKeepsTerminalSettingsAndQueuedInput() throws {
        var master: Int32 = -1, slave: Int32 = -1
        XCTAssertEqual(openpty(&master, &slave, nil, nil, nil), 0)
        defer { _ = Darwin.close(master); _ = Darwin.close(slave) }
        var original = termios()
        XCTAssertEqual(tcgetattr(slave, &original), 0)
        let line = Data("pending\n".utf8)
        XCTAssertEqual(line.withUnsafeBytes { Darwin.write(master, $0.baseAddress, $0.count) }, line.count)
        let originalFlags = fcntl(slave, F_GETFL)
        let observation = try CommandStreamObservation(descriptor: slave, streamBinding: binding)
        XCTAssertEqual(observation.captured.source.kind, .tty)
        XCTAssertNotNil(observation.captured.source.identity)
        XCTAssertNotNil(observation.terminalDevice)
        try observation.recheck(descriptor: slave)
        var after = termios()
        XCTAssertEqual(tcgetattr(slave, &after), 0)
        XCTAssertEqual(withUnsafeBytes(of: &original) { Data($0) }, withUnsafeBytes(of: &after) { Data($0) })
        XCTAssertEqual(fcntl(slave, F_GETFL), originalFlags)
        var actual = [UInt8](repeating: 0, count: line.count)
        XCTAssertEqual(Darwin.read(slave, &actual, actual.count), line.count)
        XCTAssertEqual(Data(actual), line)
    }

    func testNullSourceStillRechecksItsOriginalObjectAndAccess() throws {
        let descriptor = open("/dev/null", O_RDWR | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(descriptor, 0)
        defer { _ = Darwin.close(descriptor) }
        let observation = try CommandStreamObservation(descriptor: descriptor, streamBinding: binding)
        XCTAssertEqual(observation.captured.source, CapturedCommandInput(kind: .null, streamBinding: nil, observedPath: nil, identity: nil))
        XCTAssertEqual(observation.captured.access, .readWrite)
        try observation.recheck(descriptor: descriptor)
        let replacement = open("/dev/zero", O_RDWR | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(replacement, 0)
        defer { _ = Darwin.close(replacement) }
        XCTAssertEqual(dup2(replacement, descriptor), descriptor)
        XCTAssertThrowsError(try observation.recheck(descriptor: descriptor)) {
            XCTAssertEqual($0 as? CommandStreamObservationError, .changed)
        }
    }

    func testClosedEventOnlyAndInvalidBindingFail() throws {
        XCTAssertThrowsError(try CommandStreamObservation(descriptor: -1, streamBinding: binding))
        let descriptor = open("/dev/null", O_EVTONLY | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(descriptor, 0)
        defer { _ = Darwin.close(descriptor) }
        XCTAssertThrowsError(try CommandStreamObservation(descriptor: descriptor, streamBinding: binding)) {
            XCTAssertEqual($0 as? CommandStreamObservationError, .eventOnly)
        }
        XCTAssertThrowsError(try CommandStreamObservation(descriptor: descriptor, streamBinding: Data())) {
            XCTAssertEqual($0 as? RetainedCommandInputError, .invalidBinding)
        }
    }
}
