import CryptoKit
import Darwin
import Foundation
import RemozioProtocol

public enum CommandFilesystemCaptureError: Error, Equatable {
    case invalidPath, invalidExecutable, invalidDirectory, changed, closed
    case system(Int32)
}

/// Captures filesystem facts in the calling process. This does not authorize or execute a command.
/// The owner must serialize access and close the capture when its request retires.
public final class CommandFilesystemCapture {
    public let executable: CapturedExecutable
    public let directory: CapturedDirectory
    private var executableFD: Int32
    private var directoryFD: Int32

    public init(executablePath: Data, directoryPath: Data, checkCancellation: () throws -> Void = {}) throws {
        try Self.validatePath(executablePath)
        try Self.validatePath(directoryPath)
        try checkCancellation()
        let cwd = try Self.openPath(directoryPath, flags: O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NONBLOCK)
        var file: Int32 = -1
        do {
            let cwdInfo = try Self.directoryInfo(cwd)
            file = try Self.openPath(executablePath, flags: O_RDONLY | O_CLOEXEC | O_NONBLOCK)
            let fileInfo = try Self.executableInfo(file)
            let digest = try Self.digest(file, initial: fileInfo, checkCancellation: checkCancellation)
            try Self.checkNamedExecutable(executablePath, held: fileInfo)
            try Self.checkDirectory(cwd, path: directoryPath, identity: Self.identity(cwdInfo))
            try checkCancellation()
            executable = CapturedExecutable(path: executablePath, identity: Self.identity(fileInfo), sha256: digest)
            directory = CapturedDirectory(path: directoryPath, identity: Self.identity(cwdInfo))
            executableFD = file
            directoryFD = cwd
        } catch {
            if file >= 0 { _ = Darwin.close(file) }
            _ = Darwin.close(cwd)
            throw error
        }
    }

    deinit { close() }

    /// Call immediately before dispatch. Pathname execution still has the accepted race after this check.
    /// A failed check retires this capture; approval must never authorize a replacement capture.
    public func recheck(checkCancellation: () throws -> Void = {}) throws {
        guard executableFD >= 0, directoryFD >= 0 else { throw CommandFilesystemCaptureError.closed }
        do {
            try checkCancellation()
            try Self.checkDirectory(directoryFD, path: directory.path, identity: directory.identity)
            let info = try Self.executableInfo(executableFD)
            guard Self.identity(info) == executable.identity else { throw CommandFilesystemCaptureError.changed }
            try Self.checkNamedExecutable(executable.path, held: info)
            let digest = try Self.digest(executableFD, initial: info, checkCancellation: checkCancellation)
            guard digest == executable.sha256 else { throw CommandFilesystemCaptureError.changed }
            try checkCancellation()
            try Self.checkNamedExecutable(executable.path, held: info)
            try Self.checkDirectory(directoryFD, path: directory.path, identity: directory.identity)
        } catch { close(); throw error }
    }

    /// Borrow the retained directory only for this call. Do not close, retain, or pass the descriptor to another thread.
    public func withBorrowedDirectoryDescriptor<T>(_ body: (Int32) throws -> T) throws -> T {
        guard executableFD >= 0, directoryFD >= 0 else { throw CommandFilesystemCaptureError.closed }
        return try body(directoryFD)
    }

    public func close() {
        if executableFD >= 0 { _ = Darwin.close(executableFD); executableFD = -1 }
        if directoryFD >= 0 { _ = Darwin.close(directoryFD); directoryFD = -1 }
    }

    private static func validatePath(_ path: Data) throws {
        guard path.first == 0x2f, !path.contains(0), path.count < Int(PATH_MAX) else {
            throw CommandFilesystemCaptureError.invalidPath
        }
    }

    private static func withPath<T>(_ path: Data, _ body: (UnsafePointer<CChar>) throws -> T) rethrows -> T {
        var terminated = path
        terminated.append(0)
        return try terminated.withUnsafeBytes { bytes in
            try body(bytes.baseAddress!.assumingMemoryBound(to: CChar.self))
        }
    }

    private static func openPath(_ path: Data, flags: Int32) throws -> Int32 {
        let fd = withPath(path) { Darwin.open($0, flags) }
        guard fd >= 0 else { throw CommandFilesystemCaptureError.system(errno) }
        return fd
    }

    private static func info(_ fd: Int32) throws -> stat {
        var result = stat()
        guard fstat(fd, &result) == 0 else { throw CommandFilesystemCaptureError.system(errno) }
        return result
    }

    private static func executableInfo(_ fd: Int32) throws -> stat {
        let result = try info(fd)
        guard result.st_mode & S_IFMT == S_IFREG, result.st_mode & 0o111 != 0, result.st_size >= 0 else {
            throw CommandFilesystemCaptureError.invalidExecutable
        }
        return result
    }

    private static func directoryInfo(_ fd: Int32) throws -> stat {
        let result = try info(fd)
        guard result.st_mode & S_IFMT == S_IFDIR else { throw CommandFilesystemCaptureError.invalidDirectory }
        return result
    }

    private static func identity(_ info: stat) -> CapturedFileIdentity {
        CapturedFileIdentity(device: UInt64(UInt32(bitPattern: info.st_dev)), inode: info.st_ino)
    }

    private static func checkNamedExecutable(_ path: Data, held: stat) throws {
        var named = stat()
        guard withPath(path, { fstatat(AT_FDCWD, $0, &named, 0) }) == 0 else { throw CommandFilesystemCaptureError.system(errno) }
        guard stable(held, named) else { throw CommandFilesystemCaptureError.changed }
    }

    private static func checkDirectory(_ fd: Int32, path: Data, identity expected: CapturedFileIdentity) throws {
        let held = try directoryInfo(fd)
        var named = stat()
        guard withPath(path, { fstatat(AT_FDCWD, $0, &named, 0) }) == 0 else { throw CommandFilesystemCaptureError.system(errno) }
        guard identity(held) == expected, identity(named) == expected, named.st_mode & S_IFMT == S_IFDIR else {
            throw CommandFilesystemCaptureError.changed
        }
    }

    private static func stable(_ before: stat, _ after: stat) -> Bool {
        before.st_dev == after.st_dev && before.st_ino == after.st_ino && before.st_mode == after.st_mode &&
            before.st_uid == after.st_uid && before.st_gid == after.st_gid && before.st_size == after.st_size &&
            before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec && before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec &&
            before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec && before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec
    }

    private static func digest(_ fd: Int32, initial: stat, checkCancellation: () throws -> Void) throws -> Data {
        var hash = SHA256()
        var offset: off_t = 0
        var buffer = [UInt8](repeating: 0, count: 65_536)
        while offset < initial.st_size {
            try checkCancellation()
            let length = Int(min(off_t(buffer.count), initial.st_size - offset))
            let count = buffer.withUnsafeMutableBytes { pread(fd, $0.baseAddress, length, offset) }
            if count < 0 {
                if errno == EINTR { continue }
                throw CommandFilesystemCaptureError.system(errno)
            }
            guard count > 0 else { throw CommandFilesystemCaptureError.changed }
            hash.update(data: Data(buffer.prefix(count)))
            offset += off_t(count)
        }
        try checkCancellation()
        guard stable(initial, try executableInfo(fd)) else { throw CommandFilesystemCaptureError.changed }
        return Data(hash.finalize())
    }
}
