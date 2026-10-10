import Darwin
import Foundation
import RemozioMach
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class MappedCommandPTYTests: XCTestCase {
    private func layout(mask: UInt32, flags: UInt64 = 0) -> CapturedCommandStdioLayout {
        let source = CapturedCommandInput(kind: .tty, streamBinding: Data(count: 16), observedPath: nil,
            identity: .init(device: 1, inode: 2))
        return .init(input: .init(source: source, access: .readOnly, flags: .init(rawValue: flags)),
            output: .init(source: source, access: .writeOnly, flags: .init(rawValue: flags)),
            error: .init(source: source, access: .writeOnly, flags: .init(rawValue: flags)),
            terminal: .init(stream: .init(source: source, access: .readWrite, flags: []), sessionID: 1, terminalDevice: 2), ptyMask: mask)
    }
    private func nativeFlags(_ value: UInt32) -> Int32 {
        (value & 1 == 0 ? 0 : O_APPEND) | (value & 2 == 0 ? 0 : O_NONBLOCK) |
        (value & 4 == 0 ? 0 : O_ASYNC) | (value & 8 == 0 ? 0 : O_SYNC)
    }
    private func attributes(_ fd: Int32) throws -> Data {
        var value = termios()
        guard tcgetattr(fd, &value) == 0 else { throw RetainedCommandPTYError.native(errno) }
        return withUnsafeBytes(of: &value) { Data($0) }
    }
    func testNativeCopiesPreserveEveryAccessAndSemanticFlagCombinationWithoutChangingControl() throws {
        var handle: OpaquePointer?
        XCTAssertEqual(remozio_command_pty_create(nil, nil, &handle), 0)
        defer { remozio_command_pty_close(handle) }
        let pty = try XCTUnwrap(handle)
        var control: Int32 = -1
        XCTAssertEqual(remozio_command_pty_borrow_slave(pty, &control), 0)
        let originalFlags = fcntl(control, F_GETFL), originalAttributes = try attributes(control)
        for access: UInt32 in 0...2 {
            for flags: UInt32 in 0...15 {
                var copied: Int32 = -1
                XCTAssertEqual(remozio_command_pty_copy_stream(pty, access, flags, &copied), 0)
                guard copied >= 0 else { continue }
                defer { _ = Darwin.close(copied) }
                let status = fcntl(copied, F_GETFL)
                XCTAssertEqual(status & O_ACCMODE, Int32(access))
                XCTAssertEqual(status & (O_APPEND | O_NONBLOCK | O_ASYNC | O_SYNC), nativeFlags(flags))
                XCTAssertNotEqual(fcntl(copied, F_GETFD) & FD_CLOEXEC, 0)
                XCTAssertEqual(isatty(copied), 1)
                XCTAssertEqual(fcntl(copied, F_SETFL, status ^ O_NONBLOCK), 0)
                XCTAssertEqual(fcntl(control, F_GETFL), originalFlags)
                XCTAssertEqual(try attributes(control), originalAttributes)
            }
        }
        for (access, flags): (UInt32, UInt32) in [(3, 0), (0, 16)] {
            var copied: Int32 = 99
            XCTAssertEqual(remozio_command_pty_copy_stream(pty, access, flags, &copied), EINVAL)
            XCTAssertEqual(copied, -1)
        }
        remozio_command_pty_seal_slave(pty)
        var copied: Int32 = 99
        XCTAssertEqual(remozio_command_pty_copy_stream(pty, 0, 0, &copied), EBADF)
        XCTAssertEqual(copied, -1)
    }
    func testEveryMaskPreservesDirectStreamsAndClosesOnlyPrivateSelectedDescriptions() throws {
        let pty = try RetainedCommandPTY()
        defer { pty.close() }
        var pairs: [[Int32]] = []
        for _ in 0..<3 {
            var pair: [Int32] = [-1, -1]
            XCTAssertEqual(pipe(&pair), 0); pairs.append(pair)
        }
        defer { for pair in pairs { for fd in pair { _ = Darwin.close(fd) } } }
        let direct = [pairs[0][0], pairs[1][1], pairs[2][1]]
        let flags = direct.map { fcntl($0, F_GETFL) }
        XCTAssertEqual(Darwin.write(pairs[0][1], "pipe", 4), 4)
        XCTAssertEqual(try pty.write(Data("queued\n".utf8)), 7)
        try pty.withBorrowedSlave { original in
            let terminalFlags = fcntl(original, F_GETFL), terminalAttributes = try attributes(original)
            for mask: UInt32 in 0...7 {
                var selected: [Int32] = []
                try pty.withBorrowedMappedStreams(layout: layout(mask: mask), direct: direct) { streams, control in
                    XCTAssertEqual(control, original)
                    for index in 0..<3 {
                        if mask & (1 << index) == 0 { XCTAssertEqual(streams[index], direct[index]) }
                        else {
                            selected.append(streams[index])
                            XCTAssertNotEqual(streams[index], control)
                            XCTAssertEqual(isatty(streams[index]), 1)
                            XCTAssertEqual(fcntl(streams[index], F_GETFL) & O_ACCMODE, index == 0 ? O_RDONLY : O_WRONLY)
                            var source = stat(), target = stat()
                            XCTAssertEqual(fstat(control, &source), 0); XCTAssertEqual(fstat(streams[index], &target), 0)
                            XCTAssertEqual(target.st_dev, source.st_dev); XCTAssertEqual(target.st_ino, source.st_ino)
                            XCTAssertEqual(target.st_rdev, source.st_rdev)
                        }
                    }
                }
                for fd in selected { XCTAssertEqual(fcntl(fd, F_GETFD), -1); XCTAssertEqual(errno, EBADF) }
                XCTAssertEqual(direct.map { fcntl($0, F_GETFL) }, flags)
                XCTAssertEqual(fcntl(original, F_GETFL), terminalFlags)
                XCTAssertEqual(try attributes(original), terminalAttributes)
            }
            var bytes = [UInt8](repeating: 0, count: 7)
            XCTAssertEqual(Darwin.read(original, &bytes, bytes.count), bytes.count)
            XCTAssertEqual(Data(bytes), Data("queued\n".utf8))
        }
        var bytes = [UInt8](repeating: 0, count: 4)
        XCTAssertEqual(Darwin.read(pairs[0][0], &bytes, bytes.count), bytes.count)
        XCTAssertEqual(Data(bytes), Data("pipe".utf8))
    }
    func testThrowingSpawnCallbackRetiresSelectedDescriptionsAndKeepsThePTYOwner() throws {
        enum Stop: Error { case fixture }
        let pty = try RetainedCommandPTY()
        defer { pty.close() }
        let null = Darwin.open("/dev/null", O_RDWR)
        defer { _ = Darwin.close(null) }
        var selected: [Int32] = []
        XCTAssertThrowsError(try pty.withBorrowedMappedStreams(layout: layout(mask: 7), direct: [null, null, null]) { streams, _ in
            selected = streams
            throw Stop.fixture
        }) { XCTAssertTrue($0 is Stop) }
        XCTAssertEqual(selected.count, 3)
        for fd in selected { XCTAssertEqual(fcntl(fd, F_GETFD), -1); XCTAssertEqual(errno, EBADF) }
        try pty.withBorrowedSlave { XCTAssertEqual(isatty($0), 1) }
        XCTAssertEqual(fcntl(null, F_GETFL) & O_ACCMODE, O_RDWR)
    }
}
