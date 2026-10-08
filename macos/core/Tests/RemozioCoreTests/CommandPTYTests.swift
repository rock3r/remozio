import Darwin
import Foundation
import RemozioMach
import XCTest
@testable import RemozioCore

final class CommandPTYTests: XCTestCase {
    private func rawPTY() throws -> RetainedCommandPTY {
        let seed = try RetainedCommandPTY()
        var attributes = termios()
        try seed.withBorrowedSlave { descriptor in
            guard tcgetattr(descriptor, &attributes) == 0 else { throw RetainedCommandPTYError.native(errno) }
        }
        seed.close(); cfmakeraw(&attributes)
        return try RetainedCommandPTY(attributes: attributes, size: winsize(ws_row: 24, ws_col: 80, ws_xpixel: 0, ws_ypixel: 0))
    }
    private func awaitBytes(_ pty: RetainedCommandPTY, count: Int) throws -> Data {
        var bytes = Data()
        let deadline = Date().addingTimeInterval(3)
        while bytes.count < count {
            switch try pty.read(maximumBytes: min(64, count - bytes.count)) {
            case .bytes(let value): bytes.append(value)
            case .waiting: usleep(1000)
            case .end: throw RetainedCommandPTYError.native(EIO)
            }
            if Date() > deadline { throw RetainedCommandPTYError.native(ETIMEDOUT) }
        }
        return bytes
    }
    func testPrivateTerminalPreservesOriginalStreamFlagsAndBlockingSlave() throws {
        let before = (0...2).map { fcntl(Int32($0), F_GETFL) }
        let pty = try rawPTY(); defer { pty.close() }
        try pty.withBorrowedSlave { descriptor in
            XCTAssertEqual(isatty(descriptor), 1)
            XCTAssertNotEqual(fcntl(descriptor, F_GETFD) & FD_CLOEXEC, 0)
            XCTAssertEqual(fcntl(descriptor, F_GETFL) & O_NONBLOCK, 0)
            var size = winsize()
            XCTAssertEqual(ioctl(descriptor, TIOCGWINSZ, &size), 0)
            XCTAssertEqual(size.ws_row, 24); XCTAssertEqual(size.ws_col, 80)
        }
        XCTAssertEqual((0...2).map { fcntl(Int32($0), F_GETFL) }, before)
    }
    func testBoundedReadWaitsWithoutBlockingAndPreservesRawOutput() throws {
        let pty = try rawPTY(); defer { pty.close() }
        let start = DispatchTime.now().uptimeNanoseconds
        XCTAssertEqual(try pty.read(), .waiting)
        XCTAssertLessThan(DispatchTime.now().uptimeNanoseconds - start, 100_000_000)
        let expected = Data((0..<128).map { UInt8($0) }) + Data([0xff, 0x0a, 0x00, 0x0d])
        try pty.withBorrowedSlave { descriptor in
            XCTAssertEqual(expected.withUnsafeBytes { Darwin.write(descriptor, $0.baseAddress, $0.count) }, expected.count)
        }
        XCTAssertEqual(try awaitBytes(pty, count: expected.count), expected)
    }
    func testChunkLimitsRejectOversizedWorkBeforeAllocatingOrWriting() throws {
        let pty = try rawPTY(); defer { pty.close() }
        for count in [-1, 0, 65_537] {
            XCTAssertThrowsError(try pty.read(maximumBytes: count)) { XCTAssertEqual($0 as? RetainedCommandPTYError, .invalidChunk) }
        }
        XCTAssertThrowsError(try pty.write(Data(count: 65_537))) { XCTAssertEqual($0 as? RetainedCommandPTYError, .invalidChunk) }
        XCTAssertEqual(try pty.write(Data()), 0)
        XCTAssertEqual(try pty.read(), .waiting)
    }
    func testRawInputWriteReturnsOnlyAcceptedBytesAndOrdinaryBackpressure() throws {
        let pty = try rawPTY(); defer { pty.close() }
        let input = Data((0..<65_536).map { UInt8($0 % 251) })
        let accepted = try pty.write(input)
        XCTAssertGreaterThan(accepted, 0); XCTAssertLessThanOrEqual(accepted, input.count)
        var received = Data()
        try pty.withBorrowedSlave { descriptor in
            let deadline = Date().addingTimeInterval(3)
            while received.count < accepted {
                var readiness = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
                XCTAssertEqual(poll(&readiness, 1, 1000), 1)
                var buffer = [UInt8](repeating: 0, count: min(4096, accepted - received.count))
                let count = Darwin.read(descriptor, &buffer, buffer.count)
                guard count > 0 else { throw RetainedCommandPTYError.native(EIO) }
                received.append(contentsOf: buffer.prefix(count))
                if Date() > deadline { throw RetainedCommandPTYError.native(ETIMEDOUT) }
            }
        }
        XCTAssertEqual(received, input.prefix(accepted))
        var stalled = false
        for _ in 0..<64 {
            if try pty.write(input) == 0 { stalled = true; break }
        }
        XCTAssertTrue(stalled)
    }
    func testResizeChangesOnlyPrivateSlaveIncludingUnknownZeroDimensions() throws {
        let pty = try rawPTY(); defer { pty.close() }
        for (rows, columns): (UInt16, UInt16) in [(53, 143), (0, 0)] {
            try pty.resize(winsize(ws_row: rows, ws_col: columns, ws_xpixel: 0, ws_ypixel: 0))
            try pty.withBorrowedSlave { descriptor in
                var observed = winsize()
                XCTAssertEqual(ioctl(descriptor, TIOCGWINSZ, &observed), 0)
                XCTAssertEqual(observed.ws_row, rows); XCTAssertEqual(observed.ws_col, columns)
            }
        }
    }
    func testSealingAndClosingHaveExplicitStreamOnlyOutcomes() throws {
        let pty = try rawPTY()
        pty.sealSlave(); pty.sealSlave()
        XCTAssertThrowsError(try pty.withBorrowedSlave { _ in () }) { XCTAssertEqual($0 as? RetainedCommandPTYError, .native(EBADF)) }
        XCTAssertEqual(try pty.read(), .end); XCTAssertEqual(try pty.read(), .end)
        XCTAssertThrowsError(try pty.write(Data([1]))) { XCTAssertEqual($0 as? RetainedCommandPTYError, .native(EPIPE)) }
        pty.close(); pty.close()
        XCTAssertThrowsError(try pty.read()) { XCTAssertEqual($0 as? RetainedCommandPTYError, .closed) }
        XCTAssertThrowsError(try pty.write(Data([1]))) { XCTAssertEqual($0 as? RetainedCommandPTYError, .closed) }
        XCTAssertThrowsError(try pty.resize(winsize())) { XCTAssertEqual($0 as? RetainedCommandPTYError, .closed) }
    }
}
