import Darwin
import Foundation
import RemozioMach

public enum CommandFrontendTerminalError: Error, Equatable {
    case closed, invalidChunk, native(Int32)
}

public enum CommandFrontendTerminalRead: Equatable {
    case waiting, end, bytes(Data)
}

public struct CommandFrontendTerminalSize: Equatable, Sendable {
    public let rows: UInt16
    public let columns: UInt16
    public let pixelWidth: UInt16
    public let pixelHeight: UInt16
    public init(rows: UInt16, columns: UInt16, pixelWidth: UInt16 = 0, pixelHeight: UInt16 = 0) {
        self.rows = rows; self.columns = columns; self.pixelWidth = pixelWidth; self.pixelHeight = pixelHeight
    }
}

protocol CommandFrontendTerminalIO: AnyObject {
    var needsRestore: Bool { get }
    func isForeground() throws -> Bool
    func activate() throws
    func restore() throws
    func read(maximumBytes: Int) throws -> CommandFrontendTerminalRead
    func write(_ bytes: Data) throws -> Int
    func dimensions() throws -> CommandFrontendTerminalSize
    func close() throws
}

/// Owns the calling terminal independently. The CLI must serialize this owner and its signal routes.
public final class CommandFrontendTerminal: CommandFrontendTerminalIO {
    private var handle: OpaquePointer?
    private let reportRestorationFailure: (Int32) -> Void

    /// The descriptor names the separate calling terminal, regardless of redirected stdin, stdout or stderr.
    public init(descriptor: Int32, reportRestorationFailure: @escaping (Int32) -> Void) throws {
        self.reportRestorationFailure = reportRestorationFailure
        try check(remozio_frontend_terminal_open(descriptor, &handle))
    }
    deinit {
        if let handle {
            let status = remozio_frontend_terminal_close(handle)
            if status != 0 {
                reportRestorationFailure(status)
                remozio_frontend_terminal_abandon(handle)
            }
        }
    }
    public var needsRestore: Bool { handle.map { remozio_frontend_terminal_needs_restore($0) } ?? false }
    public func isForeground() throws -> Bool {
        let status = remozio_frontend_terminal_check_foreground(try owner())
        if status == EAGAIN { return false }
        try check(status); return true
    }
    public func activate() throws { try check(remozio_frontend_terminal_activate(try owner())) }
    public func restore() throws { try check(remozio_frontend_terminal_restore(try owner())) }
    public func read(maximumBytes: Int) throws -> CommandFrontendTerminalRead {
        guard (1...Int(REMOZIO_FRONTEND_TERMINAL_MAX_CHUNK)).contains(maximumBytes) else {
            throw CommandFrontendTerminalError.invalidChunk
        }
        let handle = try owner()
        var bytes = Data(count: maximumBytes), count = 0
        let status = bytes.withUnsafeMutableBytes {
            remozio_frontend_terminal_read(handle, $0.baseAddress!, $0.count, &count)
        }
        if status == EAGAIN { return .waiting }
        try check(status)
        guard count > 0 else { return .end }
        bytes.removeSubrange(count...); return .bytes(bytes)
    }
    public func write(_ bytes: Data) throws -> Int {
        guard (1...Int(REMOZIO_FRONTEND_TERMINAL_MAX_CHUNK)).contains(bytes.count) else {
            throw CommandFrontendTerminalError.invalidChunk
        }
        let handle = try owner()
        var count = 0
        let status = bytes.withUnsafeBytes { remozio_frontend_terminal_write(handle, $0.baseAddress!, $0.count, &count) }
        if status == EAGAIN { return 0 }
        try check(status); return count
    }
    public func dimensions() throws -> CommandFrontendTerminalSize {
        var size = winsize()
        try check(remozio_frontend_terminal_dimensions(try owner(), &size))
        return .init(rows: size.ws_row, columns: size.ws_col, pixelWidth: size.ws_xpixel, pixelHeight: size.ws_ypixel)
    }
    /// A failure preserves the owner and saved settings for an explicit foreground retry.
    public func close() throws {
        guard let handle else { return }
        try check(remozio_frontend_terminal_close(handle)); self.handle = nil
    }
    private func owner() throws -> OpaquePointer {
        guard let handle else { throw CommandFrontendTerminalError.closed }
        return handle
    }
    private func check(_ status: Int32) throws {
        if status != 0 { throw CommandFrontendTerminalError.native(status) }
    }
}
