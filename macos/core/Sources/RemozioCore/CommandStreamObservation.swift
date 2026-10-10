import Darwin
import Foundation
import RemozioProtocol

/// Observes a retained descriptor without reading bytes or changing its shared flags.
struct CommandStreamObservation {
    let captured: CapturedCommandStream
    let terminalSessionID: Int32?
    let terminalDevice: UInt32?
    private let original: Snapshot

    init(descriptor: Int32, streamBinding: Data) throws {
        guard streamBinding.count == 16 else { throw RetainedCommandInputError.invalidBinding }
        let before = try Snapshot(descriptor: descriptor)
        var path = [CChar](repeating: 0, count: Int(PATH_MAX))
        let result = path.withUnsafeMutableBufferPointer { fcntl(descriptor, F_GETPATH, $0.baseAddress!) }
        let observedPath: Data?
        if result == 0, path.first == 0x2f, let end = path.firstIndex(of: 0) {
            observedPath = Data(path[..<end].map { UInt8(bitPattern: $0) })
        } else { observedPath = nil }
        let after = try Snapshot(descriptor: descriptor)
        guard before == after else { throw CommandStreamObservationError.changed }
        let source: CapturedCommandInput
        if before.isNull {
            source = CapturedCommandInput(kind: .null, streamBinding: nil, observedPath: nil, identity: nil)
        } else {
            source = CapturedCommandInput(kind: before.kind, streamBinding: streamBinding, observedPath: observedPath,
                identity: CapturedFileIdentity(device: UInt64(before.device), inode: before.inode))
        }
        captured = CapturedCommandStream(source: source, access: before.access, flags: before.flags)
        terminalSessionID = before.terminalSessionID
        terminalDevice = before.isTerminal ? before.specialDevice : nil
        original = before
    }

    func recheck(descriptor: Int32) throws {
        guard try Snapshot(descriptor: descriptor) == original else { throw CommandStreamObservationError.changed }
    }

    private struct Snapshot: Equatable {
        let device: UInt32
        let inode: UInt64
        let type: mode_t
        let specialDevice: UInt32
        let isTerminal: Bool
        let terminalSessionID: Int32?
        let isNull: Bool
        let access: CommandStreamAccess
        let flags: CommandStreamFlags
        var kind: CommandInputKind {
            switch type {
            case S_IFREG: .file
            case S_IFDIR: .directory
            case S_IFIFO: .pipe
            case S_IFSOCK: .socket
            case S_IFCHR: isTerminal ? .tty : .device
            case S_IFBLK: .device
            default: .other
            }
        }

        init(descriptor: Int32) throws {
            try CommandStreamSource.rejectTerminalAlias(descriptor)
            let status = fcntl(descriptor, F_GETFL)
            guard status >= 0 else { throw RetainedCommandInputError.system(errno) }
            guard status & O_EVTONLY == 0 else { throw CommandStreamObservationError.eventOnly }
            var information = stat()
            guard fstat(descriptor, &information) == 0 else { throw RetainedCommandInputError.system(errno) }
            device = UInt32(bitPattern: information.st_dev)
            inode = information.st_ino
            type = information.st_mode & S_IFMT
            specialDevice = UInt32(bitPattern: information.st_rdev)
            isTerminal = type == S_IFCHR && isatty(descriptor) == 1
            let session = isTerminal ? tcgetsid(descriptor) : -1
            terminalSessionID = session > 0 ? session : nil
            var null = stat()
            isNull = type == S_IFCHR && fstatat(AT_FDCWD, "/dev/null", &null, AT_SYMLINK_NOFOLLOW) == 0 &&
                null.st_mode & S_IFMT == S_IFCHR && null.st_rdev == information.st_rdev
            switch status & O_ACCMODE {
            case O_RDONLY: access = .readOnly
            case O_WRONLY: access = .writeOnly
            case O_RDWR: access = .readWrite
            default: throw CommandStreamObservationError.access
            }
            var flags: CommandStreamFlags = []
            if status & O_APPEND != 0 { flags.insert(.append) }
            if status & O_NONBLOCK != 0 { flags.insert(.nonblocking) }
            if status & O_ASYNC != 0 { flags.insert(.asynchronous) }
            if status & O_SYNC != 0 { flags.insert(.synchronous) }
            self.flags = flags
        }
    }
}

enum CommandStreamObservationError: Error, Equatable {
    case changed, eventOnly, access
}
