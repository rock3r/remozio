import Darwin
import Dispatch
import Foundation
import RemozioMach
import RemozioProtocol
import Security

public enum MachCommandCallerError: Error, Equatable {
    case configuration, malformed, version, timeout, retired, wrongPeer, unavailable
    case mach(Int32), security(OSStatus)
}

/// Receives untrusted submission bytes and authenticates their actual sender. This grants no command authority.
/// This receiver is the port's sole consumer. The owner supplies the borrowed right, serializes access, and owns its lifetime.
public final class MachCommandCallerReceiver {
    public static let messageID: mach_msg_id_t = 0x524d0401
    public static let carrierVersion: UInt32 = 1
    public static let inputMessageID: mach_msg_id_t = 0x524d0402
    public static let inputCarrierVersion: UInt32 = 2
    public static let helloMessageID: mach_msg_id_t = 0x524d0403
    public static let helloReplyMessageID: mach_msg_id_t = 0x524d0404
    public static let handshakeCarrierVersion: UInt32 = 1
    private let port: mach_port_t
    private let maxPayloadBytes: Int
    private let requirement: SecRequirement
    private let userID: uid_t
    private let auditSessionID: au_asid_t?

    public convenience init(receivePort: mach_port_t, policy: XPCPeerPolicy, maxPayloadBytes: Int) throws {
        try self.init(receivePort: receivePort, expression: policy.requirement, userID: policy.expectedUserID,
            auditSessionID: policy.expectedAuditSessionID, maxPayloadBytes: maxPayloadBytes)
    }

    // Internal fixture policy does not expose an ad-hoc option to product callers.
    init(receivePort: mach_port_t, expression: String, userID: uid_t, auditSessionID: au_asid_t?, maxPayloadBytes: Int) throws {
        guard receivePort != MACH_PORT_NULL, receivePort != UInt32.max, maxPayloadBytes > 0,
              maxPayloadBytes <= Int(UInt32.max) - 1024 else { throw MachCommandCallerError.configuration }
        self.port = receivePort; self.maxPayloadBytes = maxPayloadBytes
        self.requirement = try Self.compile(expression)
        self.userID = userID; self.auditSessionID = auditSessionID
    }

    /// A finite timeout keeps receive loops cancellable. Oversized and malformed packets fail without truncation.
    public func receive(timeoutMilliseconds: UInt32) throws -> ReceivedMachCommandSubmission {
        let packet = try receivePacket(timeoutMilliseconds: timeoutMilliseconds, kind: .submission)
        return ReceivedMachCommandSubmission(payload: packet.payload, caller: packet.caller)
    }

    /// Imports one actual input fileport from the verified sender without reading its input.
    public func receiveInput(timeoutMilliseconds: UInt32) throws -> ReceivedMachCommandInputSubmission {
        let packet = try receivePacket(timeoutMilliseconds: timeoutMilliseconds, kind: .input)
        guard let input = packet.input else { throw MachCommandCallerError.malformed }
        return ReceivedMachCommandInputSubmission(payload: packet.payload, caller: packet.caller, input: input)
    }

    /// Receives protocol metadata and a private reply right from the actual frontend process.
    /// The listener must still reserve capacity and validate its current protected role before retaining a session.
    public func receiveHello(timeoutMilliseconds: UInt32) throws -> MachCommandHello {
        let packet = try receivePacket(timeoutMilliseconds: timeoutMilliseconds, kind: .hello)
        guard let reply = packet.reply else { packet.caller.close(); throw MachCommandCallerError.malformed }
        return MachCommandHello(payload: packet.payload, caller: packet.caller, reply: reply)
    }

    func receiveHelloReply(timeoutMilliseconds: UInt32) throws -> ReceivedMachCommandSubmission {
        let packet = try receivePacket(timeoutMilliseconds: timeoutMilliseconds, kind: .helloReply)
        return ReceivedMachCommandSubmission(payload: packet.payload, caller: packet.caller)
    }

    private enum PacketKind { case submission, input, hello, helloReply }

    private struct Packet {
        let payload: Data
        let caller: RetainedCommandCaller
        let input: RetainedCommandInputDescriptor?
        let reply: MachCommandReplyRight?
    }

    private func receivePacket(timeoutMilliseconds: UInt32, kind: PacketKind) throws -> Packet {
        guard timeoutMilliseconds > 0 else { throw MachCommandCallerError.configuration }
        let hasInput = kind == .input
        let hasPort = hasInput || kind == .hello
        let payloadLimit = kind == .hello || kind == .helloReply ? min(maxPayloadBytes, CommandHandshakeOffer.maximumBytes) : maxPayloadBytes
        let started = DispatchTime.now().uptimeNanoseconds
        var preview = remozio_mach_preview_t()
        let previewResult = remozio_preview_audit(port, timeoutMilliseconds, &preview)
        if previewResult == MACH_RCV_TIMED_OUT { throw MachCommandCallerError.timeout }
        guard previewResult == KERN_SUCCESS else { throw MachCommandCallerError.mach(previewResult) }
        let headerBytes = MemoryLayout<mach_msg_header_t>.size
        let descriptorBytes = hasPort ? MemoryLayout<mach_msg_body_t>.size + MemoryLayout<mach_msg_port_descriptor_t>.size : 0
        let metadataOffset = headerBytes + descriptorBytes
        let prefixBytes = metadataOffset + 8
        let identifier: mach_msg_id_t
        let carrierVersion: UInt32
        switch kind {
        case .submission: identifier = Self.messageID; carrierVersion = Self.carrierVersion
        case .input: identifier = Self.inputMessageID; carrierVersion = Self.inputCarrierVersion
        case .hello: identifier = Self.helloMessageID; carrierVersion = Self.handshakeCarrierVersion
        case .helloReply: identifier = Self.helloReplyMessageID; carrierVersion = Self.handshakeCarrierVersion
        }
        let maximumMessage = (prefixBytes + payloadLimit + 3) & ~3
        guard preview.identifier == identifier, preview.size >= prefixBytes, preview.size <= maximumMessage else {
            try discardQueueHead()
            throw MachCommandCallerError.malformed
        }
        let caller: RetainedCommandCaller
        do {
            caller = try RetainedCommandCaller(token: preview.token, requirement: requirement,
                userID: userID, auditSessionID: auditSessionID)
        } catch {
            try discardQueueHead()
            throw error
        }
        var completed = false
        defer { if !completed { caller.close() } }
        let elapsed = DispatchTime.now().uptimeNanoseconds - started
        let budget = UInt64(timeoutMilliseconds) * 1_000_000
        guard elapsed < budget else {
            try discardQueueHead()
            throw MachCommandCallerError.timeout
        }
        let remaining = UInt32((budget - elapsed + 999_999) / 1_000_000)
        let capacity = maximumMessage + MemoryLayout<mach_msg_audit_trailer_t>.size
        let storage = UnsafeMutableRawPointer.allocate(byteCount: capacity,
            alignment: max(MemoryLayout<mach_msg_header_t>.alignment, MemoryLayout<mach_msg_audit_trailer_t>.alignment))
        defer { storage.deallocate() }
        storage.initializeMemory(as: UInt8.self, repeating: 0, count: capacity)
        let header = storage.bindMemory(to: mach_msg_header_t.self, capacity: 1)
        let result = remozio_receive_audit(header, UInt32(capacity), port, remaining)
        if result == MACH_RCV_TIMED_OUT { throw MachCommandCallerError.timeout }
        guard result == KERN_SUCCESS else { throw MachCommandCallerError.mach(result) }
        defer { mach_msg_destroy(header) }
        let value = header.pointee
        guard (value.msgh_bits & MACH_MSGH_BITS_COMPLEX != 0) == hasPort, value.msgh_remote_port == MACH_PORT_NULL,
              value.msgh_voucher_port == MACH_PORT_NULL, value.msgh_local_port == port,
              value.msgh_id == identifier, value.msgh_size >= prefixBytes,
              value.msgh_size <= maximumMessage else { throw MachCommandCallerError.malformed }
        let size = Int(value.msgh_size)
        let trailerOffset = (size + 3) & ~3
        guard trailerOffset <= capacity - MemoryLayout<mach_msg_audit_trailer_t>.size else {
            throw MachCommandCallerError.malformed
        }
        let trailer = storage.loadUnaligned(fromByteOffset: trailerOffset, as: mach_msg_audit_trailer_t.self)
        guard trailer.msgh_trailer_type == MACH_MSG_TRAILER_FORMAT_0,
              trailer.msgh_trailer_size == MemoryLayout<mach_msg_audit_trailer_t>.size,
              trailer.msgh_seqno == preview.sequence, value.msgh_size == preview.size, value.msgh_id == preview.identifier,
              Self.sameToken(trailer.msgh_audit, preview.token) else {
            throw MachCommandCallerError.malformed
        }
        var inputPort: mach_port_t?
        if hasPort {
            let body = storage.loadUnaligned(fromByteOffset: headerBytes, as: mach_msg_body_t.self)
            guard body.msgh_descriptor_count == 1 else { throw MachCommandCallerError.malformed }
            let descriptor = storage.loadUnaligned(fromByteOffset: headerBytes + MemoryLayout<mach_msg_body_t>.size,
                as: mach_msg_port_descriptor_t.self)
            guard descriptor.type == UInt32(MACH_MSG_PORT_DESCRIPTOR),
                  descriptor.disposition == UInt32(MACH_MSG_TYPE_PORT_SEND),
                  descriptor.name != MACH_PORT_NULL, descriptor.name != UInt32.max else {
                throw MachCommandCallerError.malformed
            }
            inputPort = descriptor.name
        }
        let version = UInt32(bigEndian: storage.loadUnaligned(fromByteOffset: metadataOffset, as: UInt32.self))
        guard version == carrierVersion else { throw MachCommandCallerError.version }
        let count = Int(UInt32(bigEndian: storage.loadUnaligned(fromByteOffset: metadataOffset + 4, as: UInt32.self)))
        guard count > 0, count <= payloadLimit, (prefixBytes + count + 3) & ~3 == size else {
            throw MachCommandCallerError.malformed
        }
        for offset in (prefixBytes + count)..<size where storage.load(fromByteOffset: offset, as: UInt8.self) != 0 {
            throw MachCommandCallerError.malformed
        }
        try caller.recheck(requirement: requirement, userID: userID, auditSessionID: auditSessionID)
        let input = hasInput ? try inputPort.map { try RetainedCommandInputDescriptor(fileport: $0) } : nil
        let reply: MachCommandReplyRight?
        if kind == .hello, let inputPort {
            reply = MachCommandReplyRight(taking: inputPort)
            let offset = headerBytes + MemoryLayout<mach_msg_body_t>.size
            var descriptor = storage.loadUnaligned(fromByteOffset: offset, as: mach_msg_port_descriptor_t.self)
            descriptor.name = 0
            storage.storeBytes(of: descriptor, toByteOffset: offset, as: mach_msg_port_descriptor_t.self)
        } else { reply = nil }
        completed = true
        return Packet(payload: Data(bytes: storage.advanced(by: prefixBytes), count: count), caller: caller, input: input, reply: reply)
    }

    private func discardQueueHead() throws {
        let result = remozio_discard_message(port)
        guard result == MACH_MSG_SUCCESS || result == MACH_RCV_TOO_LARGE else {
            throw MachCommandCallerError.mach(result)
        }
    }

    private static func sameToken(_ first: audit_token_t, _ second: audit_token_t) -> Bool {
        var first = first, second = second
        return withUnsafeBytes(of: &first) { a in withUnsafeBytes(of: &second) { b in a.elementsEqual(b) } }
    }

    fileprivate static func compile(_ expression: String) throws -> SecRequirement {
        var requirement: SecRequirement?
        let status = SecRequirementCreateWithString(expression as CFString, [], &requirement)
        guard status == errSecSuccess, let requirement else { throw MachCommandCallerError.security(status) }
        return requirement
    }
}

/// Payload fields remain untrusted. Only the receiver can construct this sender binding.
public struct ReceivedMachCommandSubmission {
    public let payload: Data
    public let caller: RetainedCommandCaller
    fileprivate init(payload: Data, caller: RetainedCommandCaller) { self.payload = payload; self.caller = caller }
}

/// The input remains caller-controlled. Holding its descriptor grants no execution authority.
public struct ReceivedMachCommandInputSubmission {
    public let payload: Data
    public let caller: RetainedCommandCaller
    public let input: RetainedCommandInputDescriptor
    fileprivate init(payload: Data, caller: RetainedCommandCaller, input: RetainedCommandInputDescriptor) {
        self.payload = payload; self.caller = caller; self.input = input
    }
}

public enum RetainedCommandInputError: Error, Equatable {
    case closed, invalidBinding, notReadable
    case system(Int32)
}

/// Owns an imported descriptor without reading input or changing shared open-file flags.
/// The owner serializes access and closes it when the request retires.
public final class RetainedCommandInputDescriptor {
    private var descriptor: Int32

    fileprivate init(fileport: mach_port_t) throws {
        let imported = fileport_makefd(fileport)
        guard imported >= 0 else { throw RetainedCommandInputError.system(errno) }
        let flags = fcntl(imported, F_GETFD)
        guard flags >= 0, fcntl(imported, F_SETFD, flags | FD_CLOEXEC) == 0 else {
            let error = errno
            _ = Darwin.close(imported)
            throw RetainedCommandInputError.system(error)
        }
        descriptor = imported
    }

    deinit { close() }

    /// Borrow only for this call. Do not close, retain, or pass this descriptor to another thread.
    public func withBorrowedDescriptor<T>(_ body: (Int32) throws -> T) throws -> T {
        guard descriptor >= 0 else { throw RetainedCommandInputError.closed }
        return try body(descriptor)
    }

    /// Observes this retained object. The authority supplies and retains the stream binding; this method reads no source bytes.
    public func capture(streamBinding: Data) throws -> CapturedCommandInput {
        guard streamBinding.count == 16 else { throw RetainedCommandInputError.invalidBinding }
        return try withBorrowedDescriptor { fd in
            let flags = fcntl(fd, F_GETFL)
            guard flags >= 0 else { throw RetainedCommandInputError.system(errno) }
            guard flags & O_ACCMODE != O_WRONLY, flags & O_EVTONLY == 0 else { throw RetainedCommandInputError.notReadable }
            var information = stat()
            guard fstat(fd, &information) == 0 else { throw RetainedCommandInputError.system(errno) }
            let type = information.st_mode & S_IFMT
            if type == S_IFCHR {
                var null = stat()
                if fstatat(AT_FDCWD, "/dev/null", &null, AT_SYMLINK_NOFOLLOW) == 0,
                   null.st_mode & S_IFMT == S_IFCHR, null.st_rdev == information.st_rdev {
                    return CapturedCommandInput(kind: .null, streamBinding: nil, observedPath: nil, identity: nil)
                }
            }
            let kind: CommandInputKind
            switch type {
            case S_IFREG: kind = .file
            case S_IFDIR: kind = .directory
            case S_IFIFO: kind = .pipe
            case S_IFSOCK: kind = .socket
            case S_IFCHR: kind = isatty(fd) == 1 ? .tty : .device
            case S_IFBLK: kind = .device
            default: kind = .other
            }
            var path = [CChar](repeating: 0, count: Int(PATH_MAX))
            let result = path.withUnsafeMutableBufferPointer { fcntl(fd, F_GETPATH, $0.baseAddress!) }
            let observedPath: Data?
            if result == 0, path.first == 0x2f, let end = path.firstIndex(of: 0) {
                observedPath = Data(path[..<end].map { UInt8(bitPattern: $0) })
            } else { observedPath = nil }
            return CapturedCommandInput(kind: kind, streamBinding: streamBinding, observedPath: observedPath,
                identity: CapturedFileIdentity(device: UInt64(UInt32(bitPattern: information.st_dev)), inode: information.st_ino))
        }
    }

    public func close() {
        if descriptor >= 0 { _ = Darwin.close(descriptor); descriptor = -1 }
    }
}

/// Retains an OS process incarnation and dynamic code reference. It is not user consent or an execution permit.
/// The owner serializes access, closes this record on retirement, and supplies current protected policy at dispatch.
public final class RetainedCommandCaller {
    public let requester: CapturedRequester
    public let auditSessionID: au_asid_t
    private var token: audit_token_t
    private var code: SecCode?

    fileprivate init(token: audit_token_t, requirement: SecRequirement, userID: uid_t, auditSessionID: au_asid_t?) throws {
        try Self.credentials(token, userID: userID, auditSessionID: auditSessionID)
        let code = try Self.code(token)
        try Self.valid(code, requirement: requirement)
        let path = try Self.path(token)
        var information: CFDictionary?
        let status = remozio_copy_dynamic_signing_information(code, &information)
        guard status == errSecSuccess, let values = information as? [String: Any],
              let identifier = values[kSecCodeInfoIdentifier as String] as? String,
              let hash = values[kSecCodeInfoUnique as String] as? Data, hash.count == 20,
              let flags = values[kSecCodeInfoFlags as String] as? NSNumber else { throw MachCommandCallerError.unavailable }
        let session = getsid(audit_token_to_pid(token))
        try Self.valid(code, requirement: requirement)
        guard try Self.path(token) == path else { throw MachCommandCallerError.wrongPeer }
        self.token = token; self.code = code; self.auditSessionID = audit_token_to_asid(token)
        requester = CapturedRequester(executablePath: path, realUID: audit_token_to_ruid(token),
            effectiveUID: audit_token_to_euid(token), pid: UInt32(audit_token_to_pid(token)),
            pidVersion: UInt32(bitPattern: audit_token_to_pidversion(token)),
            signing: CapturedSigningIdentity(status: remozio_code_is_adhoc(flags.uint32Value) ? .adHoc : .validated,
                identifier: identifier, team: values[kSecCodeInfoTeamIdentifier as String] as? String, cdHash: hash),
            sessionID: session > 0 ? UInt32(session) : nil, ttyPath: nil)
    }

    /// Rechecking a failed or closed record never recaptures a replacement process.
    public func recheck(currentPolicy: XPCPeerPolicy) throws {
        try recheck(expression: currentPolicy.requirement, userID: currentPolicy.expectedUserID,
            auditSessionID: currentPolicy.expectedAuditSessionID)
    }

    func recheck(expression: String, userID: uid_t, auditSessionID: au_asid_t?) throws {
        guard code != nil else { throw MachCommandCallerError.retired }
        do {
            let requirement = try MachCommandCallerReceiver.compile(expression)
            try recheck(requirement: requirement, userID: userID, auditSessionID: auditSessionID)
        } catch { close(); throw error }
    }

    fileprivate func recheck(requirement: SecRequirement, userID: uid_t, auditSessionID: au_asid_t?) throws {
        guard let code else { throw MachCommandCallerError.retired }
        do {
            try Self.credentials(token, userID: userID, auditSessionID: auditSessionID)
            try Self.valid(code, requirement: requirement)
            guard try Self.path(token) == requester.executablePath else { throw MachCommandCallerError.wrongPeer }
        } catch { close(); throw error }
    }

    /// Observes parent links with kernel process incarnations. Ancestors are observations, not trusted initiators or consent.
    public func captureAncestry(currentPolicy: XPCPeerPolicy, maximumEntries: Int = 16,
                               checkCancellation: () throws -> Void = {}) throws -> CapturedAncestry {
        try captureAncestry(expression: currentPolicy.requirement, userID: currentPolicy.expectedUserID,
            auditSessionID: currentPolicy.expectedAuditSessionID, maximumEntries: maximumEntries, checkCancellation: checkCancellation)
    }

    func captureAncestry(expression: String, userID: uid_t, auditSessionID: au_asid_t?, maximumEntries: Int = 16,
                        checkCancellation: () throws -> Void = {}) throws -> CapturedAncestry {
        guard (0...64).contains(maximumEntries) else { throw MachCommandCallerError.configuration }
        try recheck(expression: expression, userID: userID, auditSessionID: auditSessionID)
        do {
            let result = try CommandAncestryObservation.capture(source: token, maximumEntries: maximumEntries,
                checkCancellation: checkCancellation)
            try recheck(expression: expression, userID: userID, auditSessionID: auditSessionID)
            return result
        } catch let failure as MachCommandCallerError { close(); throw failure }
    }

    /// Compare the complete kernel audit binding, including process incarnation and credentials.
    func hasSameAuditBinding(as other: RetainedCommandCaller) -> Bool {
        guard code != nil, other.code != nil else { return false }
        var first = token, second = other.token
        return withUnsafeBytes(of: &first) { a in withUnsafeBytes(of: &second) { b in a.elementsEqual(b) } }
    }

    public func close() { code = nil }

    private static func credentials(_ token: audit_token_t, userID: uid_t, auditSessionID: au_asid_t?) throws {
        guard audit_token_to_pid(token) > 0, audit_token_to_euid(token) == userID,
              auditSessionID == nil || audit_token_to_asid(token) == auditSessionID else { throw MachCommandCallerError.wrongPeer }
    }

    private static func code(_ token: audit_token_t) throws -> SecCode {
        var token = token
        let data = withUnsafeBytes(of: &token) { Data($0) }
        var code: SecCode?
        let status = SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributeAudit: data] as CFDictionary, [], &code)
        guard status == errSecSuccess, let code else { throw MachCommandCallerError.security(status) }
        return code
    }

    private static func valid(_ code: SecCode, requirement: SecRequirement) throws {
        let status = SecCodeCheckValidity(code, [], requirement)
        guard status == errSecSuccess else { throw MachCommandCallerError.security(status) }
    }

    private static func path(_ token: audit_token_t) throws -> Data {
        var token = token, bytes = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        let count = proc_pidpath_audittoken(&token, &bytes, UInt32(bytes.count))
        guard count > 0, let end = bytes.firstIndex(of: 0), end > 0, bytes[0] == 0x2f else {
            throw MachCommandCallerError.unavailable
        }
        return Data(bytes[..<end].map { UInt8(bitPattern: $0) })
    }
}
