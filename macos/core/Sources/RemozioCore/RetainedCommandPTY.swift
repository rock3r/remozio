import Darwin
import Foundation
import RemozioMach

/// Owns one private terminal inside the serialized command controller. This grants no execution or caller control permission.
final class RetainedCommandPTY {
    enum Read: Equatable { case waiting, bytes(Data), end }
    private var handle: OpaquePointer?

    init(attributes: termios? = nil, size: winsize? = nil) throws {
        var copiedAttributes = attributes ?? termios(), copiedSize = size ?? winsize()
        let status = withUnsafePointer(to: &copiedAttributes) { attributesPointer in
            withUnsafePointer(to: &copiedSize) { sizePointer in
                remozio_command_pty_create(attributes == nil ? nil : attributesPointer,
                    size == nil ? nil : sizePointer, &handle)
            }
        }
        if status != 0 { throw RetainedCommandPTYError.native(status) }
    }
    deinit { close() }

    /// Borrow only while spawning the original approved child. The callback must not close or retain this descriptor.
    func withBorrowedSlave<Value>(_ body: (Int32) throws -> Value) throws -> Value {
        guard let handle else { throw RetainedCommandPTYError.closed }
        var descriptor: Int32 = -1
        let status = remozio_command_pty_borrow_slave(handle, &descriptor)
        if status != 0 { throw RetainedCommandPTYError.native(status) }
        return try body(descriptor)
    }
    func sealSlave() {
        if let handle { remozio_command_pty_seal_slave(handle) }
    }
    func read(maximumBytes: Int = 16_384) throws -> Read {
        guard let handle else { throw RetainedCommandPTYError.closed }
        guard (1...Int(REMOZIO_PTY_MAX_CHUNK)).contains(maximumBytes) else { throw RetainedCommandPTYError.invalidChunk }
        var bytes = Data(count: maximumBytes), count = 0, eof = false
        let status = bytes.withUnsafeMutableBytes {
            remozio_command_pty_read(handle, $0.baseAddress!, $0.count, &count, &eof)
        }
        if status != 0 { throw RetainedCommandPTYError.native(status) }
        if count > 0 { bytes.removeSubrange(count...); return .bytes(bytes) }
        return eof ? .end : .waiting
    }
    /// Keep the unsent suffix when this returns less than the input count. Zero progress is ordinary backpressure.
    func write(_ bytes: Data) throws -> Int {
        guard let handle else { throw RetainedCommandPTYError.closed }
        guard bytes.count <= Int(REMOZIO_PTY_MAX_CHUNK) else { throw RetainedCommandPTYError.invalidChunk }
        var count = 0
        let status = bytes.withUnsafeBytes { remozio_command_pty_write(handle, $0.baseAddress, $0.count, &count) }
        if status != 0 { throw RetainedCommandPTYError.native(status) }
        return count
    }
    func resize(_ size: winsize) throws {
        guard let handle else { throw RetainedCommandPTYError.closed }
        var size = size
        let status = remozio_command_pty_resize(handle, &size)
        if status != 0 { throw RetainedCommandPTYError.native(status) }
    }
    /// Retain this owner until the child finishes and the output drains. Closing early can hang up the private slave.
    func close() { remozio_command_pty_close(handle); handle = nil }
}

enum RetainedCommandPTYError: Error, Equatable { case closed, invalidChunk, native(Int32) }
