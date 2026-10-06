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
/// The owner supplies a borrowed receive right and serializes access. It also owns the port's lifetime.
public final class MachCommandCallerReceiver {
    public static let messageID: mach_msg_id_t = 0x524d0401
    public static let carrierVersion: UInt32 = 1
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
        guard timeoutMilliseconds > 0 else { throw MachCommandCallerError.configuration }
        let started = DispatchTime.now().uptimeNanoseconds
        var preview = remozio_mach_preview_t()
        let previewResult = remozio_preview_audit(port, timeoutMilliseconds, &preview)
        if previewResult == MACH_RCV_TIMED_OUT { throw MachCommandCallerError.timeout }
        guard previewResult == KERN_SUCCESS else { throw MachCommandCallerError.mach(previewResult) }
        let headerBytes = MemoryLayout<mach_msg_header_t>.size
        let prefixBytes = headerBytes + 8
        let maximumMessage = (prefixBytes + maxPayloadBytes + 3) & ~3
        guard preview.identifier == Self.messageID, preview.size >= prefixBytes, preview.size <= maximumMessage else {
            _ = remozio_discard_message(port)
            throw MachCommandCallerError.malformed
        }
        let caller: RetainedCommandCaller
        do {
            caller = try RetainedCommandCaller(token: preview.token, requirement: requirement,
                userID: userID, auditSessionID: auditSessionID)
        } catch {
            _ = remozio_discard_message(port)
            throw error
        }
        var completed = false
        defer { if !completed { caller.close() } }
        let elapsed = DispatchTime.now().uptimeNanoseconds - started
        let budget = UInt64(timeoutMilliseconds) * 1_000_000
        guard elapsed < budget else {
            _ = remozio_discard_message(port)
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
        guard value.msgh_bits & MACH_MSGH_BITS_COMPLEX == 0, value.msgh_remote_port == MACH_PORT_NULL,
              value.msgh_voucher_port == MACH_PORT_NULL, value.msgh_local_port == port,
              value.msgh_id == Self.messageID, value.msgh_size >= prefixBytes,
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
        let version = UInt32(bigEndian: storage.loadUnaligned(fromByteOffset: headerBytes, as: UInt32.self))
        guard version == Self.carrierVersion else { throw MachCommandCallerError.version }
        let count = Int(UInt32(bigEndian: storage.loadUnaligned(fromByteOffset: headerBytes + 4, as: UInt32.self)))
        guard count > 0, count <= maxPayloadBytes, (prefixBytes + count + 3) & ~3 == size else {
            throw MachCommandCallerError.malformed
        }
        for offset in (prefixBytes + count)..<size where storage.load(fromByteOffset: offset, as: UInt8.self) != 0 {
            throw MachCommandCallerError.malformed
        }
        try caller.recheck(requirement: requirement, userID: userID, auditSessionID: auditSessionID)
        completed = true
        return ReceivedMachCommandSubmission(payload: Data(bytes: storage.advanced(by: prefixBytes), count: count), caller: caller)
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
