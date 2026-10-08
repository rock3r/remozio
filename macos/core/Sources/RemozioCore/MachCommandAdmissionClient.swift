import Darwin
import Foundation
import RemozioProtocol

/// Authenticated bytes from the retained Root incarnation. They are not yet an admission result or retry authority.
public struct AuthenticatedCommandReply: Sendable {
    public let payload: Data
    public let profile: CommandHandshakeProfile
    let verifiedResult: VerifiedCommandAdmissionResult?
    fileprivate init(payload: Data, profile: CommandHandshakeProfile, verifiedResult: VerifiedCommandAdmissionResult? = nil) {
        self.payload = payload; self.profile = profile; self.verifiedResult = verifiedResult
    }
}

public enum MachCommandAdmissionClient {
    /// Borrows the original input without reading it. The control deadline does not change an admitted approval lifetime.
    /// A lost reply is uncertain and never authorizes automatic resubmission. The result still needs semantic validation.
    public static func submit(_ submission: CommandSubmission, inputDescriptor: Int32,
                              handshake: VerifiedCommandHandshake, authorityPolicy: XPCPeerPolicy,
                              maximumPayloadBytes: Int, timeoutMilliseconds: UInt32 = 5000,
                              checkCancellation: () throws -> Void = {}) throws -> AuthenticatedCommandReply {
        guard authorityPolicy.expectedUserID == 0 else { throw MachCommandHandshakeError.invalidConfiguration }
        return try submit(submission, inputDescriptor: inputDescriptor, handshake: handshake,
            expression: authorityPolicy.requirement, userID: 0, auditSessionID: authorityPolicy.expectedAuditSessionID,
            maximumPayloadBytes: maximumPayloadBytes, timeoutMilliseconds: timeoutMilliseconds, checkCancellation: checkCancellation)
    }

    /// Validates typed semantics before the same final control deadline. A result grants no execution permit.
    public static func submitWithResult(_ submission: CommandSubmission, inputDescriptor: Int32,
                                       handshake: VerifiedCommandHandshake, authorityPolicy: XPCPeerPolicy,
                                       maximumPayloadBytes: Int, timeoutMilliseconds: UInt32 = 5000,
                                       checkCancellation: () throws -> Void = {}) throws -> VerifiedCommandAdmissionResult {
        guard authorityPolicy.expectedUserID == 0 else { throw MachCommandHandshakeError.invalidConfiguration }
        let reply = try submit(submission, inputDescriptor: inputDescriptor, handshake: handshake,
            expression: authorityPolicy.requirement, userID: 0, auditSessionID: authorityPolicy.expectedAuditSessionID,
            maximumPayloadBytes: maximumPayloadBytes, timeoutMilliseconds: timeoutMilliseconds,
            checkCancellation: checkCancellation, typedResult: true)
        guard let result = reply.verifiedResult else { throw CommandAdmissionResultError.incompatible }
        return result
    }

    /// Fixture identity seam. Product callers always require the configured release Root policy and UID zero.
    static func submit(_ submission: CommandSubmission, inputDescriptor: Int32,
                       handshake: VerifiedCommandHandshake, expression: String, userID: uid_t, auditSessionID: au_asid_t?,
                       maximumPayloadBytes: Int, timeoutMilliseconds: UInt32 = 5000,
                       checkCancellation: () throws -> Void = {}, clock: (() throws -> UInt64)? = nil,
                       typedResult: Bool = false) throws -> AuthenticatedCommandReply {
        guard !typedResult || handshake.profile.supportsAdmissionResults else { throw CommandAdmissionResultError.incompatible }
        guard handshake.profile.inputCarrierVersion == UInt64(MachCommandCallerReceiver.admissionInputCarrierVersion),
              submission.schemaVersion == handshake.profile.submissionSchemaVersion,
              submission.binding.callerBinding == handshake.profile.callerBinding else { throw MachCommandHandshakeError.incompatible }
        guard (1...60_000).contains(timeoutMilliseconds), maximumPayloadBytes > 0,
              maximumPayloadBytes <= Int(UInt32.max) - 1024,
              !submission.canonicalBytes.isEmpty, submission.canonicalBytes.count <= maximumPayloadBytes else {
            throw MachCommandHandshakeError.invalidConfiguration
        }
        let authorityClock = try AuthorityClock()
        let now = clock ?? { try authorityClock.now().milliseconds }
        let started = try now()
        func remaining() throws -> UInt32 {
            let current = try now()
            guard current >= started, current - started < UInt64(timeoutMilliseconds) else { throw MachCommandCallerError.timeout }
            return UInt32(UInt64(timeoutMilliseconds) - (current - started))
        }
        try checkCancellation()
        // Recheck the same retained authority before exposing invocation bytes or an input fileport.
        try handshake.authenticateReplyAuthority(expression: expression, userID: userID, auditSessionID: auditSessionID)
        let authorityPort = try handshake.borrowedAuthorityPort()
        let endpoint = try MachCommandPrivateReplyPort()
        defer { endpoint.close() }
        let receiver = try MachCommandCallerReceiver(receivePort: endpoint.port, expression: expression,
            userID: userID, auditSessionID: auditSessionID, maxPayloadBytes: CommandHandshakeOffer.maximumBytes)
        try MachCommandAdmissionWire.send(submission.canonicalBytes, inputDescriptor: inputDescriptor,
            destination: authorityPort, replyPort: endpoint.port, maximumPayloadBytes: maximumPayloadBytes,
            timeoutMilliseconds: remaining())
        try checkCancellation()
        func receiveReply() throws -> sending ReceivedMachCommandSubmission {
            while true {
                try checkCancellation()
                let budget = try remaining()
                do { return try receiver.receiveAdmissionReply(timeoutMilliseconds: budget, previewTimeoutMilliseconds: min(budget, 250)) }
                catch MachCommandCallerError.timeout { _ = try remaining() }
            }
        }
        let reply = try receiveReply()
        defer { reply.caller.close() }
        try checkCancellation()
        _ = try remaining()
        try handshake.authenticateReply(reply.caller, expression: expression, userID: userID, auditSessionID: auditSessionID)
        let result = typedResult ? try CommandAdmissionResultPayload.decode(reply.payload, profile: handshake.profile, original: submission) : nil
        try checkCancellation()
        _ = try remaining()
        return AuthenticatedCommandReply(payload: reply.payload, profile: handshake.profile, verifiedResult: result)
    }
}

enum MachCommandAdmissionWire {
    /// Each copied descriptor has its own ownership. No input byte or shared open-file flag is changed.
    static func send(_ bytes: Data, inputDescriptor: Int32, destination: mach_port_t, replyPort: mach_port_t,
                     maximumPayloadBytes: Int, timeoutMilliseconds: UInt32) throws {
        guard destination != MACH_PORT_NULL, destination != UInt32.max,
              replyPort != MACH_PORT_NULL, replyPort != UInt32.max,
              maximumPayloadBytes > 0, maximumPayloadBytes <= Int(UInt32.max) - 1024,
              !bytes.isEmpty, bytes.count <= maximumPayloadBytes, (1...60_000).contains(timeoutMilliseconds) else {
            throw MachCommandHandshakeError.invalidConfiguration
        }
        let flags = fcntl(inputDescriptor, F_GETFL)
        guard flags >= 0 else { throw RetainedCommandInputError.system(errno) }
        guard flags & O_ACCMODE != O_WRONLY else { throw RetainedCommandInputError.notReadable }
        var fileport: mach_port_t = 0
        guard fileport_makeport(inputDescriptor, &fileport) == 0 else { throw RetainedCommandInputError.system(errno) }
        defer { _ = mach_port_deallocate(mach_task_self_, fileport) }
        let headerBytes = MemoryLayout<mach_msg_header_t>.size
        let bodyBytes = MemoryLayout<mach_msg_body_t>.size, descriptorBytes = MemoryLayout<mach_msg_port_descriptor_t>.size
        let metadata = headerBytes + bodyBytes + 2 * descriptorBytes
        let size = (metadata + 8 + bytes.count + 3) & ~3
        let storage = UnsafeMutableRawPointer.allocate(byteCount: size, alignment: 8)
        defer { storage.deallocate() }
        storage.initializeMemory(as: UInt8.self, repeating: 0, count: size)
        let header = storage.bindMemory(to: mach_msg_header_t.self, capacity: 1)
        header.pointee.msgh_bits = UInt32(MACH_MSG_TYPE_COPY_SEND) | MACH_MSGH_BITS_COMPLEX
        header.pointee.msgh_size = UInt32(size); header.pointee.msgh_remote_port = destination
        header.pointee.msgh_id = MachCommandCallerReceiver.admissionInputMessageID
        storage.storeBytes(of: mach_msg_body_t(msgh_descriptor_count: 2), toByteOffset: headerBytes, as: mach_msg_body_t.self)
        for (index, port) in [fileport, replyPort].enumerated() {
            var descriptor = mach_msg_port_descriptor_t()
            descriptor.name = port; descriptor.disposition = UInt32(MACH_MSG_TYPE_COPY_SEND); descriptor.type = UInt32(MACH_MSG_PORT_DESCRIPTOR)
            storage.storeBytes(of: descriptor, toByteOffset: headerBytes + bodyBytes + index * descriptorBytes, as: mach_msg_port_descriptor_t.self)
        }
        storage.storeBytes(of: MachCommandCallerReceiver.admissionInputCarrierVersion.bigEndian, toByteOffset: metadata, as: UInt32.self)
        storage.storeBytes(of: UInt32(bytes.count).bigEndian, toByteOffset: metadata + 4, as: UInt32.self)
        bytes.withUnsafeBytes { storage.advanced(by: metadata + 8).copyMemory(from: $0.baseAddress!, byteCount: $0.count) }
        let result = mach_msg(header, MACH_SEND_MSG | MACH_SEND_TIMEOUT | MACH_SEND_INTERRUPT, UInt32(size), 0, 0, timeoutMilliseconds, 0)
        guard result == KERN_SUCCESS else {
            let code = result & ~MACH_MSG_MASK
            if code == MACH_SEND_TIMED_OUT || code == MACH_SEND_INTERRUPTED || code == MACH_SEND_INVALID_DEST { mach_msg_destroy(header) }
            throw MachCommandCallerError.mach(result)
        }
    }
}
