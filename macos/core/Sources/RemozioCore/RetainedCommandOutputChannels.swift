import Darwin
import Foundation

public enum RetainedCommandOutputError: Error, Equatable {
    case closed, notWritable
    case system(Int32)
}

/// Owns a copied output descriptor. Import and inspection never write bytes or change shared open-file flags.
final class RetainedCommandOutputDescriptor {
    private var descriptor: Int32
    init(fileport: mach_port_t) throws {
        let imported = fileport_makefd(fileport)
        guard imported >= 0 else { throw RetainedCommandOutputError.system(errno) }
        var completed = false
        defer { if !completed { _ = Darwin.close(imported) } }
        try CommandStreamSource.rejectTerminalAlias(imported)
        let descriptorFlags = fcntl(imported, F_GETFD), flags = fcntl(imported, F_GETFL)
        guard descriptorFlags >= 0, flags >= 0 else { throw RetainedCommandOutputError.system(errno) }
        guard flags & O_ACCMODE != O_RDONLY, flags & O_EVTONLY == 0 else { throw RetainedCommandOutputError.notWritable }
        guard fcntl(imported, F_SETFD, descriptorFlags | FD_CLOEXEC) == 0 else { throw RetainedCommandOutputError.system(errno) }
        descriptor = imported; completed = true
    }
    func withBorrowedDescriptor<T>(_ body: (Int32) throws -> T) throws -> T {
        guard descriptor >= 0 else { throw RetainedCommandOutputError.closed }
        return try body(descriptor)
    }
    func recheck() throws {
        try withBorrowedDescriptor { fd in
            let flags = fcntl(fd, F_GETFL)
            guard flags >= 0 else { throw RetainedCommandOutputError.system(errno) }
            guard flags & O_ACCMODE != O_RDONLY, flags & O_EVTONLY == 0 else { throw RetainedCommandOutputError.notWritable }
        }
    }
    func close() { if descriptor >= 0 { _ = Darwin.close(descriptor); descriptor = -1 } }
    deinit { close() }
}

/// These resources belong to the same authenticated submission. Holding them grants no dispatch or result authority.
final class RetainedCommandOutputChannels {
    let output: RetainedCommandOutputDescriptor
    let error: RetainedCommandOutputDescriptor
    private var result: MachCommandReplyRight?
    private var closed = false
    init(output: RetainedCommandOutputDescriptor, error: RetainedCommandOutputDescriptor, result: MachCommandReplyRight) {
        self.output = output; self.error = error; self.result = result
    }
    func recheck() throws {
        guard !closed else { throw RetainedCommandOutputError.closed }
        try recheckStreams(); guard let result else { throw RetainedCommandOutputError.closed }; try result.recheck()
    }
    func sendTerminalResult(_ bytes: Data, timeoutMilliseconds: UInt32) throws {
        guard !closed else { throw RetainedCommandOutputError.closed }
        guard let result else { throw RetainedCommandOutputError.closed }
        try result.send(bytes, timeoutMilliseconds: timeoutMilliseconds)
    }
    func sendTerminalNonblocking(_ bytes: Data) throws {
        guard !closed else { throw RetainedCommandOutputError.closed }
        guard let result else { throw RetainedCommandOutputError.closed }
        try result.sendTerminalNonblocking(bytes)
    }
    func recheckStreams() throws {
        guard !closed else { throw RetainedCommandOutputError.closed }
        try output.recheck(); try error.recheck()
    }
    func takeTerminalReply() throws -> MachCommandReplyRight {
        guard !closed, let result else { throw RetainedCommandOutputError.closed }
        self.result = nil
        return result
    }
    func close() {
        if !closed { closed = true; output.close(); error.close(); result?.close(); result = nil }
    }
    deinit { close() }
}
