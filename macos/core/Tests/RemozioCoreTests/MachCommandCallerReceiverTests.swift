import CryptoKit
import Darwin
import Foundation
import os
import RemozioMach
import RemozioProtocol
import Security
import SQLite3
import XCTest
@testable import RemozioCore

final class MachCommandCallerReceiverTests: XCTestCase {
    private final class Endpoint {
        var port: mach_port_t = 0
        private var ownsReceive = true
        func transferReceiveRight() -> mach_port_t { precondition(ownsReceive); ownsReceive = false; return port }
        init() throws {
            guard mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &port) == KERN_SUCCESS,
                  mach_port_insert_right(mach_task_self_, port, port, UInt32(MACH_MSG_TYPE_MAKE_SEND)) == KERN_SUCCESS else {
                throw MachCommandCallerError.configuration
            }
        }
        deinit {
            if ownsReceive { _ = mach_port_mod_refs(mach_task_self_, port, MACH_PORT_RIGHT_RECEIVE, -1) }
            _ = mach_port_deallocate(mach_task_self_, port)
        }
        func send(_ payload: Data, version: UInt32 = 1, claimedLength: UInt32? = nil,
                  identifier: mach_msg_id_t = MachCommandCallerReceiver.messageID, badPadding: Bool = false) throws {
            let prefix = MemoryLayout<mach_msg_header_t>.size
            let size = (prefix + 8 + payload.count + 3) & ~3
            let storage = UnsafeMutableRawPointer.allocate(byteCount: size, alignment: MemoryLayout<mach_msg_header_t>.alignment)
            defer { storage.deallocate() }
            storage.initializeMemory(as: UInt8.self, repeating: 0, count: size)
            let header = storage.bindMemory(to: mach_msg_header_t.self, capacity: 1)
            header.pointee.msgh_bits = UInt32(MACH_MSG_TYPE_COPY_SEND)
            header.pointee.msgh_size = UInt32(size)
            header.pointee.msgh_remote_port = port
            header.pointee.msgh_id = identifier
            storage.storeBytes(of: version.bigEndian, toByteOffset: prefix, as: UInt32.self)
            storage.storeBytes(of: (claimedLength ?? UInt32(payload.count)).bigEndian, toByteOffset: prefix + 4, as: UInt32.self)
            payload.withUnsafeBytes { bytes in
                if let base = bytes.baseAddress { storage.advanced(by: prefix + 8).copyMemory(from: base, byteCount: bytes.count) }
            }
            if badPadding { storage.storeBytes(of: UInt8(1), toByteOffset: size - 1, as: UInt8.self) }
            let result = mach_msg(header, MACH_SEND_MSG | MACH_SEND_TIMEOUT, UInt32(size), 0, 0, 1000, 0)
            guard result == KERN_SUCCESS else { throw MachCommandCallerError.mach(result) }
        }
        func sendPort(_ carried: mach_port_t, outOfLineBytes: Int = 0) throws {
            let size = MemoryLayout<mach_msg_header_t>.size + MemoryLayout<mach_msg_body_t>.size + MemoryLayout<mach_msg_port_descriptor_t>.size +
                (outOfLineBytes > 0 ? MemoryLayout<mach_msg_ool_descriptor_t>.size : 0)
            let storage = UnsafeMutableRawPointer.allocate(byteCount: size, alignment: MemoryLayout<mach_msg_header_t>.alignment)
            defer { storage.deallocate() }
            storage.initializeMemory(as: UInt8.self, repeating: 0, count: size)
            let header = storage.bindMemory(to: mach_msg_header_t.self, capacity: 1)
            header.pointee.msgh_bits = UInt32(MACH_MSG_TYPE_COPY_SEND) | MACH_MSGH_BITS_COMPLEX
            header.pointee.msgh_size = UInt32(size)
            header.pointee.msgh_remote_port = port
            header.pointee.msgh_id = MachCommandCallerReceiver.messageID
            storage.storeBytes(of: mach_msg_body_t(msgh_descriptor_count: outOfLineBytes > 0 ? 2 : 1), toByteOffset: MemoryLayout<mach_msg_header_t>.size, as: mach_msg_body_t.self)
            var descriptor = mach_msg_port_descriptor_t()
            descriptor.name = carried
            descriptor.disposition = UInt32(MACH_MSG_TYPE_COPY_SEND)
            descriptor.type = UInt32(MACH_MSG_PORT_DESCRIPTOR)
            storage.storeBytes(of: descriptor, toByteOffset: MemoryLayout<mach_msg_header_t>.size + MemoryLayout<mach_msg_body_t>.size, as: mach_msg_port_descriptor_t.self)
            let bytes = UnsafeMutableRawPointer.allocate(byteCount: max(1, outOfLineBytes), alignment: 8)
            defer { bytes.deallocate() }
            bytes.initializeMemory(as: UInt8.self, repeating: 0x5a, count: max(1, outOfLineBytes))
            if outOfLineBytes > 0 {
                var outOfLine = mach_msg_ool_descriptor_t()
                outOfLine.address = bytes
                outOfLine.size = UInt32(outOfLineBytes)
                outOfLine.copy = UInt32(MACH_MSG_VIRTUAL_COPY)
                outOfLine.type = UInt32(MACH_MSG_OOL_DESCRIPTOR)
                storage.storeBytes(of: outOfLine, toByteOffset: MemoryLayout<mach_msg_header_t>.size +
                    MemoryLayout<mach_msg_body_t>.size + MemoryLayout<mach_msg_port_descriptor_t>.size,
                    as: mach_msg_ool_descriptor_t.self)
            }
            let result = mach_msg(header, MACH_SEND_MSG | MACH_SEND_TIMEOUT, UInt32(size), 0, 0, 1000, 0)
            guard result == KERN_SUCCESS else { throw MachCommandCallerError.mach(result) }
        }

        func sendInput(_ payload: Data, fileport: mach_port_t, version: UInt32 = 2, descriptorCount: Int = 1,
                       identifier: mach_msg_id_t = MachCommandCallerReceiver.inputMessageID, replyPort: mach_port_t? = nil, badPadding: Bool = false) throws {
            let headerBytes = MemoryLayout<mach_msg_header_t>.size
            let bodyBytes = MemoryLayout<mach_msg_body_t>.size
            let descriptorBytes = MemoryLayout<mach_msg_port_descriptor_t>.size
            let metadata = headerBytes + bodyBytes + descriptorCount * descriptorBytes
            let size = (metadata + 8 + payload.count + 3) & ~3
            let storage = UnsafeMutableRawPointer.allocate(byteCount: size, alignment: 8)
            defer { storage.deallocate() }
            storage.initializeMemory(as: UInt8.self, repeating: 0, count: size)
            let header = storage.bindMemory(to: mach_msg_header_t.self, capacity: 1)
            header.pointee.msgh_bits = UInt32(MACH_MSG_TYPE_COPY_SEND) | MACH_MSGH_BITS_COMPLEX
            header.pointee.msgh_size = UInt32(size)
            header.pointee.msgh_remote_port = port
            header.pointee.msgh_id = identifier
            storage.storeBytes(of: mach_msg_body_t(msgh_descriptor_count: UInt32(descriptorCount)),
                toByteOffset: headerBytes, as: mach_msg_body_t.self)
            for index in 0..<descriptorCount {
                var descriptor = mach_msg_port_descriptor_t()
                descriptor.name = index == 1 ? (replyPort ?? fileport) : fileport
                descriptor.disposition = UInt32(MACH_MSG_TYPE_COPY_SEND)
                descriptor.type = UInt32(MACH_MSG_PORT_DESCRIPTOR)
                storage.storeBytes(of: descriptor, toByteOffset: headerBytes + bodyBytes + index * descriptorBytes,
                    as: mach_msg_port_descriptor_t.self)
            }
            storage.storeBytes(of: version.bigEndian, toByteOffset: metadata, as: UInt32.self)
            storage.storeBytes(of: UInt32(payload.count).bigEndian, toByteOffset: metadata + 4, as: UInt32.self)
            payload.withUnsafeBytes { bytes in
                if let base = bytes.baseAddress { storage.advanced(by: metadata + 8).copyMemory(from: base, byteCount: bytes.count) }
            }
            if badPadding { storage.storeBytes(of: UInt8(1), toByteOffset: size - 1, as: UInt8.self) }
            let result = mach_msg(header, MACH_SEND_MSG | MACH_SEND_TIMEOUT, UInt32(size), 0, 0, 1000, 0)
            guard result == KERN_SUCCESS else { throw MachCommandCallerError.mach(result) }
        }

        func sendOutOfLineInput() throws {
            let headerBytes = MemoryLayout<mach_msg_header_t>.size, bodyBytes = MemoryLayout<mach_msg_body_t>.size
            let metadata = headerBytes + bodyBytes + MemoryLayout<mach_msg_ool_descriptor_t>.size
            let size = metadata + 12
            let storage = UnsafeMutableRawPointer.allocate(byteCount: size, alignment: 8)
            let bytes = UnsafeMutableRawPointer.allocate(byteCount: 65536, alignment: 8)
            defer { storage.deallocate(); bytes.deallocate() }
            bytes.initializeMemory(as: UInt8.self, repeating: 0x5a, count: 65536)
            storage.initializeMemory(as: UInt8.self, repeating: 0, count: size)
            let header = storage.bindMemory(to: mach_msg_header_t.self, capacity: 1)
            header.pointee.msgh_bits = UInt32(MACH_MSG_TYPE_COPY_SEND) | MACH_MSGH_BITS_COMPLEX
            header.pointee.msgh_size = UInt32(size)
            header.pointee.msgh_remote_port = port
            header.pointee.msgh_id = MachCommandCallerReceiver.inputMessageID
            storage.storeBytes(of: mach_msg_body_t(msgh_descriptor_count: 1), toByteOffset: headerBytes, as: mach_msg_body_t.self)
            var descriptor = mach_msg_ool_descriptor_t()
            descriptor.address = bytes
            descriptor.size = 65536
            descriptor.copy = UInt32(MACH_MSG_VIRTUAL_COPY)
            descriptor.type = UInt32(MACH_MSG_OOL_DESCRIPTOR)
            storage.storeBytes(of: descriptor, toByteOffset: headerBytes + bodyBytes, as: mach_msg_ool_descriptor_t.self)
            storage.storeBytes(of: UInt32(2).bigEndian, toByteOffset: metadata, as: UInt32.self)
            storage.storeBytes(of: UInt32(1).bigEndian, toByteOffset: metadata + 4, as: UInt32.self)
            let result = mach_msg(header, MACH_SEND_MSG | MACH_SEND_TIMEOUT, UInt32(size), 0, 0, 1000, 0)
            guard result == KERN_SUCCESS else { throw MachCommandCallerError.mach(result) }
        }

        func sendBareHeader() throws {
            var header = mach_msg_header_t()
            header.msgh_bits = UInt32(MACH_MSG_TYPE_COPY_SEND)
            header.msgh_size = UInt32(MemoryLayout<mach_msg_header_t>.size)
            header.msgh_remote_port = port
            header.msgh_id = MachCommandCallerReceiver.messageID
            let result = mach_msg(&header, MACH_SEND_MSG | MACH_SEND_TIMEOUT, header.msgh_size, 0, 0, 1000, 0)
            guard result == KERN_SUCCESS else { throw MachCommandCallerError.mach(result) }
        }
    }

    private func admissionInput(_ endpoint: Endpoint, reply: Endpoint, descriptor: Int32, payload: Data) throws -> ReceivedMachCommandInputSubmission {
        try MachCommandAdmissionWire.send(payload, inputDescriptor: descriptor, destination: endpoint.port,
            replyPort: reply.port, maximumPayloadBytes: 8192, timeoutMilliseconds: 1000)
        return try receiver(endpoint, maximum: 8192).receiveAdmissionInput(timeoutMilliseconds: 1000)
    }
    private func admissionClientFixture(_ destination: mach_port_t, input: UInt64 = 3, wire: UInt64 = 1, mac: Data? = nil, account: Data? = nil) throws -> sending VerifiedCommandHandshake {
        let endpoint = try Endpoint()
        try endpoint.send(Data([1]))
        let sender = try receiver(endpoint).receive(timeoutMilliseconds: 1000)
        return VerifiedCommandHandshake(profile: .init(wireVersion: wire, submissionSchemaVersion: 1, inputCarrierVersion: input,
            callerBinding: assemblyBinding, macID: mac ?? handshakeMac, accountID: account ?? handshakeAccount), authority: sender.caller,
            destination: try MachCommandAuthorityPort(copying: destination))
    }

    func testAdmissionReplyCarrierPreservesOriginalInputAndRepliesOnce() throws {
        let endpoint = try Endpoint(), reply = try Endpoint()
        var pipeFDs: [Int32] = [-1, -1]
        XCTAssertEqual(pipe(&pipeFDs), 0)
        defer { for fd in pipeFDs { _ = Darwin.close(fd) } }
        XCTAssertEqual(Darwin.write(pipeFDs[1], "queued", 6), 6)
        let flags = fcntl(pipeFDs[0], F_GETFL), baseline = try sendReferences(reply.port)
        let input = try admissionInput(endpoint, reply: reply, descriptor: pipeFDs[0], payload: Data([0xa0]))
        defer { input.closeIfUnclaimed() }
        XCTAssertEqual(input.carrierVersion, 3); XCTAssertEqual(input.payload, Data([0xa0]))
        XCTAssertEqual(try sendReferences(reply.port), baseline + 1)
        try input.sendAdmissionReply(Data([0xa0]))
        XCTAssertEqual(try sendReferences(reply.port), baseline)
        XCTAssertThrowsError(try input.sendAdmissionReply(Data([0xa0])))
        let response = try receiver(reply).receiveAdmissionReply(timeoutMilliseconds: 1000)
        defer { response.caller.close() }
        XCTAssertEqual(response.payload, Data([0xa0])); XCTAssertEqual(response.caller.requester.pid, UInt32(getpid()))
        XCTAssertEqual(fcntl(pipeFDs[0], F_GETFL), flags)
        var bytes = [UInt8](repeating: 0, count: 6)
        XCTAssertEqual(Darwin.read(pipeFDs[0], &bytes, 6), 6); XCTAssertEqual(Data(bytes), Data("queued".utf8))
    }

    func testAdmissionReplyCarrierKeepsLegacyMeaningAndMixedReceiveQueue() throws {
        let endpoint = try Endpoint(), reply = try Endpoint(), fd = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(fd, 0); defer { _ = Darwin.close(fd) }
        let baseline = try sendReferences(reply.port)
        try MachCommandAdmissionWire.send(Data([1]), inputDescriptor: fd, destination: endpoint.port,
            replyPort: reply.port, maximumPayloadBytes: 8192, timeoutMilliseconds: 1000)
        XCTAssertThrowsError(try receiver(endpoint).receiveInput(timeoutMilliseconds: 1000))
        XCTAssertEqual(try sendReferences(reply.port), baseline)
        var fileport: mach_port_t = 0
        XCTAssertEqual(fileport_makeport(fd, &fileport), 0); defer { _ = mach_port_deallocate(mach_task_self_, fileport) }
        try endpoint.sendInput(Data([2]), fileport: fileport)
        XCTAssertThrowsError(try receiver(endpoint).receiveAdmissionInput(timeoutMilliseconds: 1000))
        try endpoint.sendInput(Data([3]), fileport: fileport)
        try MachCommandAdmissionWire.send(Data([4]), inputDescriptor: fd, destination: endpoint.port,
            replyPort: reply.port, maximumPayloadBytes: 8192, timeoutMilliseconds: 1000)
        for (payload, version) in [(UInt8(3), UInt32(2)), (4, 3)] {
            guard case .input(let input) = try receiver(endpoint).receiveNext(timeoutMilliseconds: 1000) else { return XCTFail("Input missing") }
            XCTAssertEqual(input.payload, Data([payload])); XCTAssertEqual(input.carrierVersion, version)
            input.closeIfUnclaimed()
        }
        XCTAssertEqual(try sendReferences(reply.port), baseline)
    }

    func testAdmissionReplyCarrierRejectsWrongSenderAndMalformedRightsWithoutLeaks() throws {
        let endpoint = try Endpoint(), reply = try Endpoint(), fd = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(fd, 0); defer { _ = Darwin.close(fd) }
        var fileport: mach_port_t = 0
        XCTAssertEqual(fileport_makeport(fd, &fileport), 0); defer { _ = mach_port_deallocate(mach_task_self_, fileport) }
        let baseline = try sendReferences(reply.port), inputBaseline = try sendReferences(fileport)
        try endpoint.sendInput(Data([1]), fileport: fileport, version: 3, descriptorCount: 2,
            identifier: MachCommandCallerReceiver.admissionInputMessageID, replyPort: reply.port)
        XCTAssertThrowsError(try receiver(endpoint, user: geteuid() ^ 1).receiveAdmissionInput(timeoutMilliseconds: 1000))
        for (count, version, padding) in [(0, UInt32(3), false), (1, 3, false), (3, 3, false), (2, 2, false), (2, 3, true)] {
            try endpoint.sendInput(Data([1]), fileport: fileport, version: version, descriptorCount: count,
                identifier: MachCommandCallerReceiver.admissionInputMessageID, replyPort: reply.port, badPadding: padding)
            XCTAssertThrowsError(try receiver(endpoint).receiveAdmissionInput(timeoutMilliseconds: 1000))
            XCTAssertEqual(try sendReferences(reply.port), baseline); XCTAssertEqual(try sendReferences(fileport), inputBaseline)
        }
        try endpoint.sendInput(Data([1]), fileport: reply.port, version: 3, descriptorCount: 2,
            identifier: MachCommandCallerReceiver.admissionInputMessageID, replyPort: reply.port)
        XCTAssertThrowsError(try receiver(endpoint).receiveAdmissionInput(timeoutMilliseconds: 1000)) {
            XCTAssertEqual($0 as? RetainedCommandInputError, .system(EINVAL))
        }
        XCTAssertEqual(try sendReferences(reply.port), baseline)
        let next = try admissionInput(endpoint, reply: reply, descriptor: fd, payload: Data([2]))
        next.closeIfUnclaimed(); XCTAssertEqual(try sendReferences(reply.port), baseline)
    }

    func testAdmissionReplyControlCarrierRejectsWrongVersionOversizeAndWrongKind() throws {
        let endpoint = try Endpoint()
        let control = try receiver(endpoint, maximum: 8192)
        for (version, identifier, bytes) in [(UInt32(2), MachCommandCallerReceiver.admissionReplyMessageID, Data([1])),
            (1, MachCommandCallerReceiver.helloReplyMessageID, Data([1])),
            (1, MachCommandCallerReceiver.admissionReplyMessageID, Data(repeating: 1, count: 4097))] {
            try endpoint.send(bytes, version: version, identifier: identifier)
            XCTAssertThrowsError(try control.receiveAdmissionReply(timeoutMilliseconds: 1000))
        }
        try endpoint.send(Data([2]), identifier: MachCommandCallerReceiver.admissionReplyMessageID, badPadding: true)
        XCTAssertThrowsError(try control.receiveAdmissionReply(timeoutMilliseconds: 1000))
        try endpoint.send(Data([3]), identifier: MachCommandCallerReceiver.admissionReplyMessageID)
        let reply = try control.receiveAdmissionReply(timeoutMilliseconds: 1000)
        reply.caller.close(); XCTAssertEqual(reply.payload, Data([3]))
    }

    func testCaptureRetainsAdmissionReplyAcrossOwnershipAndClosesItOnRetirement() throws {
        let endpoint = try Endpoint(), reply = try Endpoint(), fd = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(fd, 0); defer { _ = Darwin.close(fd) }
        let baseline = try sendReferences(reply.port), payload = try commandSubmission().canonicalBytes
        let received = try admissionInput(endpoint, reply: reply, descriptor: fd, payload: payload)
        let command = try assemble(received)
        defer { command.close() }
        XCTAssertThrowsError(try received.sendAdmissionReply(Data([0xa0])))
        XCTAssertThrowsError(try assemble(received)) { XCTAssertEqual($0 as? RetainedCommandCaptureError, .alreadyOwned) }
        received.closeIfUnclaimed()
        XCTAssertEqual(try sendReferences(reply.port), baseline + 1)
        try command.sendAdmissionReply(Data([0xa0]))
        XCTAssertEqual(try sendReferences(reply.port), baseline)
        let response = try receiver(reply).receiveAdmissionReply(timeoutMilliseconds: 1000)
        response.caller.close(); XCTAssertEqual(response.payload, Data([0xa0]))
        let secondReply = try Endpoint(), second = try admissionInput(endpoint, reply: secondReply, descriptor: fd, payload: payload)
        let owned = try assemble(second)
        XCTAssertEqual(try sendReferences(secondReply.port), 2)
        owned.close(); XCTAssertEqual(try sendReferences(secondReply.port), 1)
        XCTAssertThrowsError(try owned.sendAdmissionReply(Data([0xa0])))
        let failed = try admissionInput(endpoint, reply: reply, descriptor: fd, payload: Data([0]))
        XCTAssertThrowsError(try assemble(failed))
        XCTAssertEqual(try sendReferences(reply.port), baseline)
        try expectAssemblyResourcesRetired(failed)
    }

    func testNegotiatedAdmissionCarrierCannotUseLegacyInputAndPreservesReplyOnCapture() throws {
        let endpoint = try Endpoint(), helloReply = try Endpoint(), reply = try Endpoint()
        let session = try RetainedCommandHandshake(hello: hello(endpoint, reply: helloReply, capabilities: .admissionReplies),
            capabilities: .admissionReplies, macID: handshakeMac, accountID: handshakeAccount,
            expression: selfExpression(), userID: geteuid(), auditSessionID: nil)
        defer { session.close() }
        XCTAssertEqual(session.profile.inputCarrierVersion, 3)
        let payload = try commandSubmission(binding: .init(id: Data(repeating: 2, count: 16), nonce: Data(repeating: 3, count: 32),
            callerBinding: session.profile.callerBinding)).canonicalBytes
        let fd = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(fd, 0); defer { _ = Darwin.close(fd) }
        let legacy = try inputSubmission(fd, payload: payload)
        XCTAssertThrowsError(try session.assemble(received: TestInputInspection(received: legacy).received,
            expression: selfExpression(), userID: geteuid(), auditSessionID: nil,
            captureSchemaVersion: 2, resolvedTarget: assemblyTarget, minimalEnvironment: assemblyEnvironment,
            streamBinding: Data(repeating: 4, count: 16), submissionLimits: assemblyLimits, captureLimits: assemblyLimits)) {
            XCTAssertEqual($0 as? MachCommandHandshakeError, .incompatible)
        }
        try expectAssemblyResourcesRetired(legacy)
        let incoming = try admissionInput(endpoint, reply: reply, descriptor: fd, payload: payload)
        let command = try session.assemble(received: TestInputInspection(received: incoming).received,
            expression: selfExpression(), userID: geteuid(), auditSessionID: nil,
            captureSchemaVersion: 2, resolvedTarget: assemblyTarget, minimalEnvironment: assemblyEnvironment,
            streamBinding: Data(repeating: 4, count: 16), submissionLimits: assemblyLimits, captureLimits: assemblyLimits)
        defer { command.close() }
        try command.sendAdmissionReply(Data([0xa0]))
        let response = try receiver(reply).receiveAdmissionReply(timeoutMilliseconds: 1000)
        response.caller.close(); XCTAssertEqual(response.payload, Data([0xa0]))
    }

    func testTypedAdmissionClientRequiresNewWireBeforeExposingInput() throws {
        let endpoint = try Endpoint(), handshake = try admissionClientFixture(endpoint.port)
        defer { handshake.close() }
        XCTAssertThrowsError(try MachCommandAdmissionClient.submit(commandSubmission(), inputDescriptor: -1,
            handshake: handshake, expression: selfExpression(), userID: geteuid(), auditSessionID: nil,
            maximumPayloadBytes: 8192, typedResult: true)) {
            XCTAssertEqual($0 as? CommandAdmissionResultError, .incompatible)
        }
        XCTAssertThrowsError(try receiver(endpoint).receiveAdmissionInput(timeoutMilliseconds: 10)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .timeout)
        }
    }

    func testTypedAdmissionClientAuthenticatesKnownResultsAndRejectsChangedCommand() throws {
        for altered in [false, true] {
            let endpoint = try Endpoint(), handshake = try admissionClientFixture(endpoint.port, wire: 2)
            defer { handshake.close() }
            let submission = try commandSubmission(), replySubmission = altered ? try commandSubmission(executablePath: "/usr/bin/false") : submission
            let payload = CommandAdmissionResultPayload(profile: handshake.profile, submission: submission.binding,
                submissionDigest: Data(SHA256.hash(data: replySubmission.canonicalBytes)), outcome: .notAdmitted(.updateWaiting, .updateWaiting))
            let server = try serveAdmission(endpoint.port, response: payload.canonicalBytes)
            let fd = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
            XCTAssertGreaterThanOrEqual(fd, 0); defer { _ = Darwin.close(fd) }
            func submit() throws -> AuthenticatedCommandReply {
                try MachCommandAdmissionClient.submit(submission, inputDescriptor: fd, handshake: handshake,
                    expression: selfExpression(), userID: geteuid(), auditSessionID: nil, maximumPayloadBytes: 8192, typedResult: true)
            }
            if altered { XCTAssertThrowsError(try submit()) { XCTAssertEqual($0 as? CommandAdmissionResultError, .wrongBinding) } }
            else {
                let result = try XCTUnwrap(submit().verifiedResult)
                XCTAssertEqual(result.outcome, .notAdmitted(.updateWaiting, .updateWaiting)); XCTAssertEqual(result.retryClass, .updateWaiting)
            }
            XCTAssertEqual(server.0.wait(timeout: .now() + 5), .success); try server.1.withLock { try $0?.get() }
        }
    }

    func testTypedAdmissionClientValidatesBeforeTheFinalDeadlineAndRejectsMalformedResults() throws {
        for expired in [false, true] {
            let endpoint = try Endpoint(), handshake = try admissionClientFixture(endpoint.port, wire: 2)
            defer { handshake.close() }
            let submission = try commandSubmission()
            let payload = CommandAdmissionResultPayload(profile: handshake.profile, submission: submission.binding,
                submissionDigest: Data(SHA256.hash(data: submission.canonicalBytes)), outcome: .uncertain(.admissionRejected))
            let server = try serveAdmission(endpoint.port, response: expired ? payload.canonicalBytes : Data([0xa0]))
            let fd = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
            XCTAssertGreaterThanOrEqual(fd, 0); defer { _ = Darwin.close(fd) }
            var samples = 0
            XCTAssertThrowsError(try MachCommandAdmissionClient.submit(submission, inputDescriptor: fd, handshake: handshake,
                expression: selfExpression(), userID: geteuid(), auditSessionID: nil, maximumPayloadBytes: 8192,
                timeoutMilliseconds: 1000, clock: { samples += 1; return expired && samples >= 5 ? 1000 : 0 }, typedResult: true)) {
                if expired { XCTAssertEqual($0 as? MachCommandCallerError, .timeout) }
                else { XCTAssertEqual($0 as? CommandAdmissionResultError, .malformed) }
            }
            XCTAssertEqual(server.0.wait(timeout: .now() + 5), .success); try server.1.withLock { try $0?.get() }
        }
    }

    private func typedRequestCommand(reply: Endpoint, binding: CapturedSubmission? = nil, macID: Data? = nil) throws -> (RetainedCommandCapture, CommandSubmission, CommandHandshakeProfile) {
        let endpoint = try Endpoint(), fd = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        guard fd >= 0 else { throw MachCommandCallerError.unavailable }
        defer { _ = Darwin.close(fd) }
        let submission = try commandSubmission(binding: binding)
        let profile = CommandHandshakeProfile(wireVersion: 2, submissionSchemaVersion: 1, inputCarrierVersion: 3,
            callerBinding: submission.binding.callerBinding, macID: macID ?? Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16))
        let received = try admissionInput(endpoint, reply: reply, descriptor: fd, payload: submission.canonicalBytes)
        return (try assemble(received, admissionProfile: profile), submission, profile)
    }

    func testTypedAdmissionAcknowledgmentMatchesCommittedRequestAndLostDeliveryPreservesIt() throws {
        for checkpointed in [false, true] {
            for lost in [false, true] {
                let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true), reply = try Endpoint()
                let (command, submission, profile) = try typedRequestCommand(reply: reply)
                if lost {
                    let owned = reply.transferReceiveRight()
                    XCTAssertEqual(mach_port_mod_refs(mach_task_self_, owned, MACH_PORT_RIGHT_RECEIVE, -1), KERN_SUCCESS)
                }
                let request = try admitOwnedCommand(command, fixture: fixture)
                XCTAssertNotNil(try fixture.reservation(submission.binding.id))
                XCTAssertEqual(try XCTUnwrap(fixture.authority).withRequests { try $0.state(requestID: request.requestID).phase }, .queued)
                try command.withBorrowedInputDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
                if !lost {
                    let raw = try receiver(reply, maximum: 4096).receiveAdmissionReply(timeoutMilliseconds: 1000)
                    defer { raw.caller.close() }
                    let result = try CommandAdmissionResultPayload.decode(raw.payload, profile: profile, original: submission)
                    XCTAssertEqual(result.outcome, .admitted(.init(requestID: request.requestID,
                        requestDigest: try request.requestDigest(bodyLimits: fixture.limits, signingLimits: fixture.limits), challenge: request.challenge)))
                    XCTAssertEqual(result.retryClass, .never)
                }
            }
        }
    }

    func testTypedDuplicateReplyIsUncertainAndPreservesTheOriginalRequest() throws {
        let fixture = try CommandRequestFixture(checkpointed: true), firstReply = try Endpoint()
        let (first, submission, _) = try typedRequestCommand(reply: firstReply)
        let request = try admitCommand(first, fixture: fixture), secondReply = try Endpoint()
        let (second, replay, profile) = try typedRequestCommand(reply: secondReply, binding: submission.binding)
        XCTAssertThrowsError(try admitCommand(second, fixture: fixture)) { XCTAssertEqual($0 as? CommandSubmissionReplayError, .alreadyReserved) }
        let raw = try receiver(secondReply, maximum: 4096).receiveAdmissionReply(timeoutMilliseconds: 1000)
        defer { raw.caller.close() }
        let result = try CommandAdmissionResultPayload.decode(raw.payload, profile: profile, original: replay)
        XCTAssertEqual(result.outcome, .uncertain(.duplicateSubmission)); XCTAssertEqual(result.retryClass, .never)
        XCTAssertEqual(try fixture.requests.state(requestID: request.requestID).phase, .queued)
        try first.withBorrowedInputDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
        XCTAssertThrowsError(try second.withBorrowedInputDescriptor { _ in () })
    }

    func testTypedForeignScopeFailsBeforeRequestCreation() throws {
        let fixture = try CommandRequestFixture(), reply = try Endpoint()
        let (command, submission, _) = try typedRequestCommand(reply: reply, macID: Data(repeating: 99, count: 16))
        let before = try fixture.auditRecordCount
        XCTAssertThrowsError(try admitCommand(command, fixture: fixture)) { XCTAssertEqual($0 as? ApprovalCoordinatorError, .invalidDraft) }
        XCTAssertEqual(try fixture.auditRecordCount, before); XCTAssertNil(try fixture.reservation(submission.binding.id))
        XCTAssertThrowsError(try command.withBorrowedInputDescriptor { _ in () })
        XCTAssertThrowsError(try receiver(reply, maximum: 4096).receiveAdmissionReply(timeoutMilliseconds: 10)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .timeout)
        }
    }

    func testMixedWireCapabilitiesSelectTheHighestUnderstoodPair() throws {
        let server = try CommandHandshakeCapabilities(wireVersions: [1, 2], submissionSchemaVersions: [1], inputCarrierVersions: [2, 3])
        for offered in [try CommandHandshakeCapabilities(wireVersions: [1, 2], submissionSchemaVersions: [1], inputCarrierVersions: [2]), server] {
            let endpoint = try Endpoint(), reply = try Endpoint()
            let session = try RetainedCommandHandshake(hello: hello(endpoint, reply: reply, capabilities: offered), capabilities: server,
                macID: handshakeMac, accountID: handshakeAccount, expression: selfExpression(), userID: geteuid(), auditSessionID: nil)
            defer { session.close() }
            let response = try receiver(reply, maximum: 4096).receiveHelloReply(timeoutMilliseconds: 1000)
            defer { response.caller.close() }
            XCTAssertEqual(session.profile.wireVersion, offered.inputCarrierVersions.contains(3) ? 2 : 1)
            XCTAssertEqual(session.profile.inputCarrierVersion, offered.inputCarrierVersions.contains(3) ? 3 : 2)
            XCTAssertEqual(try CommandHandshakeReply.decode(response.payload,
                offer: CommandHandshakeOffer(nonce: Data(repeating: 0xd3, count: 32), capabilities: offered), macID: handshakeMac, accountID: handshakeAccount), session.profile)
        }
        let endpoint = try Endpoint(), reply = try Endpoint()
        let impossible = try CommandHandshakeCapabilities(wireVersions: [2], submissionSchemaVersions: [1], inputCarrierVersions: [2])
        XCTAssertThrowsError(try RetainedCommandHandshake(hello: hello(endpoint, reply: reply, capabilities: impossible), capabilities: server,
            macID: handshakeMac, accountID: handshakeAccount, expression: selfExpression(), userID: geteuid(), auditSessionID: nil)) {
            XCTAssertEqual($0 as? MachCommandHandshakeError, .incompatible)
        }
        let response = try receiver(reply, maximum: 4096).receiveHelloReply(timeoutMilliseconds: 1000)
        defer { response.caller.close() }
        XCTAssertThrowsError(try CommandHandshakeReply.decode(response.payload,
            offer: CommandHandshakeOffer(nonce: Data(repeating: 0xd3, count: 32), capabilities: impossible), macID: handshakeMac, accountID: handshakeAccount)) {
            XCTAssertEqual($0 as? MachCommandHandshakeError, .incompatible)
        }
    }

    private func typedOutcome(_ reply: Endpoint, submission: CommandSubmission, profile: CommandHandshakeProfile) throws -> CommandAdmissionOutcome {
        let raw = try receiver(reply, maximum: 4096).receiveAdmissionReply(timeoutMilliseconds: 1000)
        defer { raw.caller.close() }
        return try CommandAdmissionResultPayload.decode(raw.payload, profile: profile, original: submission).outcome
    }

    private func admissionAttempt(reply: Endpoint, executable: String = "/usr/bin/true", binding: CapturedSubmission? = nil,
                                  descriptor: Int32? = nil) throws -> (RetainedCommandAdmissionAttempt, CommandSubmission, CommandHandshakeProfile) {
        let endpoint = try Endpoint(), helloReply = try Endpoint()
        let session = try RetainedCommandHandshake(hello: hello(endpoint, reply: helloReply, capabilities: .admissionResults),
            capabilities: .admissionResults, macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16),
            expression: selfExpression(), userID: geteuid(), auditSessionID: nil)
        defer { session.close() }
        let fresh = binding ?? CapturedSubmission(id: Data(repeating: 0xb2, count: 16), nonce: Data(repeating: 0xb3, count: 32),
            callerBinding: session.profile.callerBinding)
        let submission = try commandSubmission(executablePath: executable, binding: .init(id: fresh.id, nonce: fresh.nonce,
            callerBinding: session.profile.callerBinding))
        let fd = descriptor ?? Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        guard fd >= 0 else { throw MachCommandCallerError.unavailable }
        defer { if descriptor == nil { _ = Darwin.close(fd) } }
        let received = try admissionInput(endpoint, reply: reply, descriptor: fd, payload: submission.canonicalBytes)
        return (try session.prepareAdmission(received: TestInputInspection(received: received).received, expression: selfExpression(), userID: geteuid(),
            auditSessionID: nil, submissionLimits: assemblyLimits), submission, session.profile)
    }
    private func admissionContext() throws -> CommandAdmissionCaptureContext {
        .init(schemaVersion: 1, target: assemblyTarget, minimalEnvironment: assemblyEnvironment,
            streamBinding: Data(repeating: 0xe4, count: 16), limits: try assemblyLimits, maximumAncestryEntries: 1)
    }
    private func admissionDraft(_ capture: CommandCapture, fixture: CommandRequestFixture) -> ApprovalRequestDraft {
        .init(contract: fixture.contract, requiredFeatures: [], capture: capture.canonicalBytes,
            actions: [.init(choice: .execute, scope: .currentRequest), .init(choice: .decline, scope: .currentRequest)],
            firstObservedAt: fixture.now(100), deadlineMilliseconds: 200, createdUnixMilliseconds: 1000, expiresUnixMilliseconds: 1100)
    }
    private func admitAttempt(_ attempt: RetainedCommandAdmissionAttempt, fixture: CommandRequestFixture,
                              resolution: CommandAdmissionResolution? = nil,
                              checkCancellation: @escaping @Sendable () throws -> Void = {}) throws -> IssuedRequestPayload {
        let resolved = try resolution ?? .capture(admissionContext())
        return try XCTUnwrap(fixture.authority).admitCommandAttempt(attempt, expression: selfExpression(), resolve: { _ in resolved },
            draft: { self.admissionDraft($0, fixture: fixture) }, now: { fixture.now() }, receiptTimeMs: nil,
            checkCancellation: checkCancellation)
    }

    func testAdmissionAttemptAuthenticatesBeforeCaptureAndPreservesUnreadInputOnAdmission() throws {
        for checkpointed in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true), reply = try Endpoint()
            var fds: [Int32] = [-1, -1]
            XCTAssertEqual(pipe(&fds), 0); defer { for fd in fds { _ = Darwin.close(fd) } }
            XCTAssertEqual(Darwin.write(fds[1], "unread", 6), 6)
            let (attempt, submission, profile) = try admissionAttempt(reply: reply, descriptor: fds[0])
            let request = try admitAttempt(attempt, fixture: fixture)
            guard case .admitted(let identity) = try typedOutcome(reply, submission: submission, profile: profile) else {
                return XCTFail("Attempt was not admitted")
            }
            XCTAssertEqual(identity.requestID, request.requestID)
            XCTAssertNotNil(try fixture.reservation(submission.binding.id)); XCTAssertEqual(try sendReferences(reply.port), 1)
            var bytes = [UInt8](repeating: 0, count: 6)
            XCTAssertEqual(Darwin.read(fds[0], &bytes, 6), 6); XCTAssertEqual(Data(bytes), Data("unread".utf8))
            XCTAssertThrowsError(try admitAttempt(attempt, fixture: fixture)) {
                XCTAssertEqual($0 as? CommandAdmissionAttemptError, .closed)
            }
            XCTAssertEqual(try XCTUnwrap(fixture.authority).withRequests { try $0.state(requestID: request.requestID).phase }, .queued)
        }
    }

    func testAdmissionAttemptReportsAllTrustedBusyAndPermanentRefusalsOnlyAfterFreshAbsenceRead() throws {
        for checkpointed in [false, true] {
            for reason in [CommandAdmissionRejectionReason.updateInstalling, .authorityStarting, .updateWaiting, .storageUnavailable,
                           .policyRejected, .invalidRequest, .unsupported, .capacityExceeded] {
                let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true), reply = try Endpoint()
                let (attempt, submission, profile) = try admissionAttempt(reply: reply, executable: "/missing-before-capture")
                let before = try fixture.auditRecordCount
                XCTAssertThrowsError(try admitAttempt(attempt, fixture: fixture, resolution: .refuse(reason))) {
                    XCTAssertEqual($0 as? CommandAdmissionControllerError, .refused(reason))
                }
                let retry = CommandAdmissionRetryClass(rawValue: reason.rawValue) ?? .never
                XCTAssertEqual(try typedOutcome(reply, submission: submission, profile: profile), .notAdmitted(reason, retry))
                XCTAssertNil(try fixture.reservation(submission.binding.id)); XCTAssertEqual(try fixture.auditRecordCount, before)
                XCTAssertEqual(try sendReferences(reply.port), 1)
            }
        }
    }

    func testAdmissionAttemptUsesActualUnpreparedJournalStateWithoutCallingResolverOrDraft() throws {
        for checkpointed in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true, ready: false), reply = try Endpoint()
            let (attempt, submission, profile) = try admissionAttempt(reply: reply)
            XCTAssertThrowsError(try XCTUnwrap(fixture.authority).admitCommandAttempt(attempt, expression: selfExpression(),
                resolve: { _ in XCTFail("Startup must refuse before policy resolution"); return .refuse(.policyRejected) },
                draft: { _ in XCTFail("Startup must refuse before capture"); throw ApprovalCoordinatorError.invalidDraft },
                now: { fixture.now() }, receiptTimeMs: nil))
            XCTAssertEqual(try typedOutcome(reply, submission: submission, profile: profile), .notAdmitted(.authorityStarting, .authorityStarting))
            XCTAssertNil(try fixture.reservation(submission.binding.id))
        }
    }

    func testAdmissionAttemptCaptureFailureKeepsPrivateReplyAfterInputCleanup() throws {
        for checkpointed in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true), reply = try Endpoint()
            let (attempt, submission, profile) = try admissionAttempt(reply: reply, executable: "/missing-before-capture")
            XCTAssertThrowsError(try admitAttempt(attempt, fixture: fixture)) { XCTAssertTrue($0 is CommandFilesystemCaptureError) }
            XCTAssertEqual(try typedOutcome(reply, submission: submission, profile: profile), .notAdmitted(.invalidRequest, .never))
            XCTAssertNil(try fixture.reservation(submission.binding.id)); XCTAssertEqual(try sendReferences(reply.port), 1)
        }
    }

    func testAdmissionCaptureClassifierNeverTreatsHostResourceOrUnknownFailuresAsInvalidCommands() {
        for code in [EMFILE, ENFILE, EIO, ENOMEM, ENOSPC, EAGAIN, EINTR, EACCES, EPERM, ESTALE, Int32.max] {
            XCTAssertNil(AuthorityJournal.commandCaptureRefusal(CommandFilesystemCaptureError.system(code)))
        }
        for error in [CommandFilesystemCaptureError.changed, .closed] {
            XCTAssertNil(AuthorityJournal.commandCaptureRefusal(error))
        }
        for code in [ENOENT, ENOTDIR, ELOOP, ENAMETOOLONG] {
            XCTAssertEqual(AuthorityJournal.commandCaptureRefusal(CommandFilesystemCaptureError.system(code)), .invalidRequest)
        }
        XCTAssertNil(AuthorityJournal.commandCaptureRefusal(ApprovalCoordinatorError.capacityExceeded))
    }

    func testAdmissionAttemptChangedExecutableDuringCaptureRemainsUncertainAndKeepsItsReply() throws {
        for checkpointed in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true), reply = try Endpoint()
            let executable = fixture.root.appendingPathComponent("capture-tool")
            try FileManager.default.copyItem(at: URL(fileURLWithPath: "/usr/bin/true"), to: executable)
            let writer = Darwin.open(executable.path, O_WRONLY | O_CLOEXEC)
            XCTAssertGreaterThanOrEqual(writer, 0); defer { _ = Darwin.close(writer) }
            let (attempt, submission, profile) = try admissionAttempt(reply: reply, executable: executable.path)
            let checks = OSAllocatedUnfairLock(initialState: 0)
            XCTAssertThrowsError(try admitAttempt(attempt, fixture: fixture, checkCancellation: {
                let count = checks.withLock { $0 += 1; return $0 }
                if count == 4 {
                    var byte: UInt8 = 0
                    XCTAssertEqual(pwrite(writer, &byte, 1, 0), 1)
                }
            })) { XCTAssertEqual($0 as? CommandFilesystemCaptureError, .changed) }
            XCTAssertEqual(try typedOutcome(reply, submission: submission, profile: profile), .uncertain(.admissionRejected))
            XCTAssertNil(try fixture.reservation(submission.binding.id)); XCTAssertEqual(try sendReferences(reply.port), 1)
        }
    }

    func testAdmissionAttemptCallbackErrorsCannotSpoofCaptureRefusalAndCannotReenterJournal() throws {
        for stage in 0..<3 {
            let fixture = try CommandRequestFixture(checkpointed: true, owned: true), reply = try Endpoint()
            let (attempt, submission, profile) = try admissionAttempt(reply: reply)
            let authority = try XCTUnwrap(fixture.authority), context = try admissionContext()
            let count = OSAllocatedUnfairLock(initialState: 0)
            XCTAssertThrowsError(try authority.admitCommandAttempt(attempt, expression: selfExpression(), resolve: { _ in
                XCTAssertThrowsError(try authority.read { _ in 0 }) { XCTAssertEqual($0 as? JournalDatabaseError, .transactionActive) }
                if stage == 0 { throw CommandFilesystemCaptureError.invalidPath }
                return .capture(context)
            }, draft: {
                if stage == 1 { throw IssuedRequestError.unsupportedContract }
                return self.admissionDraft($0, fixture: fixture)
            }, now: { fixture.now() }, receiptTimeMs: nil, checkCancellation: {
                let checks = count.withLock { $0 += 1; return $0 }
                if stage == 2 && checks >= 2 { throw CommandFilesystemCaptureError.invalidPath }
            }))
            XCTAssertEqual(try typedOutcome(reply, submission: submission, profile: profile), .uncertain(.admissionRejected))
            XCTAssertNil(try fixture.reservation(submission.binding.id)); XCTAssertEqual(try sendReferences(reply.port), 1)
        }
    }

    func testAdmissionAttemptBusyRefusalCannotContradictHistoricalIdentifierOrNonce() throws {
        for checkpointed in [false, true] {
            for nonce in [false, true] {
                let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true), reply = try Endpoint()
                let (first, original, _) = try admissionAttempt(reply: reply), request = try admitAttempt(first, fixture: fixture)
                let retiredAt = fixture.now(120)
                _ = try XCTUnwrap(fixture.authority).withRequests { try $0.retirePending(requestID: request.requestID,
                    reason: .cancelled, now: retiredAt, receiptTimeMs: nil) }
                let binding = CapturedSubmission(id: nonce ? Data(repeating: 88, count: 16) : original.binding.id,
                    nonce: nonce ? original.binding.nonce : Data(repeating: 89, count: 32), callerBinding: original.binding.callerBinding)
                let secondReply = try Endpoint(), (second, submission, profile) = try admissionAttempt(reply: secondReply, binding: binding)
                XCTAssertThrowsError(try admitAttempt(second, fixture: fixture, resolution: .refuse(.updateWaiting)))
                XCTAssertEqual(try typedOutcome(secondReply, submission: submission, profile: profile), .uncertain(.duplicateSubmission))
            }
        }
    }

    func testAdmissionAttemptProtectedReadFailureCannotGrantAutomaticRetry() throws {
        for checkpointed in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true), reply = try Endpoint()
            let (attempt, submission, profile) = try admissionAttempt(reply: reply)
            if checkpointed { try fixture.sql("UPDATE audit_epochs_v1 SET head=X'0000000000000002'") }
            else { try XCTUnwrap(fixture.authority).close() }
            XCTAssertThrowsError(try admitAttempt(attempt, fixture: fixture, resolution: .refuse(.updateWaiting)))
            XCTAssertEqual(try typedOutcome(reply, submission: submission, profile: profile), .uncertain(.storageFailure))
            XCTAssertEqual(try sendReferences(reply.port), 1)
        }
    }

    func testAdmissionAttemptRefusalRevalidatesCheckpointAfterTrustedResolution() throws {
        let fixture = try CommandRequestFixture(checkpointed: true, owned: true), reply = try Endpoint()
        let (attempt, submission, profile) = try admissionAttempt(reply: reply)
        XCTAssertThrowsError(try XCTUnwrap(fixture.authority).admitCommandAttempt(attempt, expression: selfExpression(), resolve: { _ in
            try fixture.sql("UPDATE audit_epochs_v1 SET head=X'0000000000000002'")
            return .refuse(.updateWaiting)
        }, draft: { _ in throw ApprovalCoordinatorError.invalidDraft }, now: { fixture.now() }, receiptTimeMs: nil))
        XCTAssertEqual(try typedOutcome(reply, submission: submission, profile: profile), .uncertain(.storageFailure))
        XCTAssertEqual(try sendReferences(reply.port), 1)
    }

    func testAdmissionAttemptLostAcknowledgmentPreservesCommittedRequest() throws {
        let fixture = try CommandRequestFixture(checkpointed: true, owned: true), reply = try Endpoint()
        let (attempt, submission, _) = try admissionAttempt(reply: reply)
        let port = reply.transferReceiveRight()
        XCTAssertEqual(mach_port_mod_refs(mach_task_self_, port, MACH_PORT_RIGHT_RECEIVE, -1), KERN_SUCCESS)
        let request = try admitAttempt(attempt, fixture: fixture)
        XCTAssertNotNil(try fixture.reservation(submission.binding.id))
        XCTAssertEqual(try XCTUnwrap(fixture.authority).withRequests { try $0.state(requestID: request.requestID).phase }, .queued)
    }

    func testAdmissionAttemptPublicJournalRequiresRootIdentityBeforePolicyCallbacks() throws {
        guard geteuid() != 0 else { throw XCTSkip("Normal-user fixture") }
        let fixture = try CommandRequestFixture(checkpointed: true, owned: true), reply = try Endpoint()
        let (attempt, submission, profile) = try admissionAttempt(reply: reply)
        XCTAssertThrowsError(try XCTUnwrap(fixture.authority).admitCommandAttempt(TestAttemptInspection(attempt: attempt).attempt, resolve: { _ in
            XCTFail("Unprivileged host must not resolve elevation policy"); return .refuse(.policyRejected)
        }, draft: { _ in throw ApprovalCoordinatorError.invalidDraft }, now: { fixture.now() }, receiptTimeMs: nil)) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
        XCTAssertEqual(try typedOutcome(reply, submission: submission, profile: profile), .uncertain(.storageFailure))
    }

    func testTypedDraftRejectionProvesBothIdentifiersAbsent() throws {
        for checkpointed in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed), reply = try Endpoint()
            let (command, submission, profile) = try typedRequestCommand(reply: reply)
            let before = try fixture.auditRecordCount, baseline = try sendReferences(reply.port)
            XCTAssertThrowsError(try admitCommand(command, fixture: fixture, draft: fixture.draft(command, capture: Data([0xa0]))))
            XCTAssertEqual(try typedOutcome(reply, submission: submission, profile: profile), .notAdmitted(.invalidRequest, .never))
            XCTAssertEqual(try sendReferences(reply.port), baseline - 1)
            XCTAssertEqual(try fixture.auditRecordCount, before); XCTAssertNil(try fixture.reservation(submission.binding.id))
            XCTAssertFalse(try fixture.db.read { try $0.commandSubmissionReserved(submission.binding) })
            XCTAssertThrowsError(try command.withBorrowedInputDescriptor { _ in () })
        }
    }

    func testTypedOwnedJournalRefusalKeepsItsReplyAndAllowsIndependentFreshAdmission() throws {
        for checkpointed in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true), reply = try Endpoint()
            let (command, submission, profile) = try typedRequestCommand(reply: reply)
            XCTAssertThrowsError(try admitOwnedCommand(command, fixture: fixture, draft: fixture.draft(command, capture: Data([0xa0]))))
            XCTAssertEqual(try typedOutcome(reply, submission: submission, profile: profile), .notAdmitted(.invalidRequest, .never))
            XCTAssertNil(try fixture.reservation(submission.binding.id))
            XCTAssertThrowsError(try command.withBorrowedInputDescriptor { _ in () })
            XCTAssertEqual(try sendReferences(reply.port), 1)
            let freshReply = try Endpoint()
            let binding = CapturedSubmission(id: Data(repeating: 88, count: 16), nonce: Data(repeating: 89, count: 32), callerBinding: assemblyBinding)
            let (fresh, original, selected) = try typedRequestCommand(reply: freshReply, binding: binding)
            let request = try admitOwnedCommand(fresh, fixture: fixture)
            XCTAssertNotNil(try fixture.reservation(original.binding.id))
            guard case .admitted(let identity) = try typedOutcome(freshReply, submission: original, profile: selected) else {
                return XCTFail("Fresh request was not admitted")
            }
            XCTAssertEqual(identity.requestID, request.requestID)
            try fresh.withBorrowedInputDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
        }
    }

    func testTypedCapacityRefusalPreservesExistingRequestAndStorage() throws {
        for checkpointed in [false, true] {
            for journalCapacity in [false, true] {
                let fixture = try CommandRequestFixture(maximumRequests: journalCapacity ? 8 : 1,
                    checkpointed: checkpointed, maximumSubmissions: journalCapacity ? 1 : 30)
                let firstReply = try Endpoint(), (first, _, _) = try typedRequestCommand(reply: firstReply)
                let request = try admitCommand(first, fixture: fixture), before = try fixture.auditRecordCount
                let secondReply = try Endpoint()
                let binding = CapturedSubmission(id: Data(repeating: 88, count: 16), nonce: Data(repeating: 89, count: 32), callerBinding: assemblyBinding)
                let (second, submission, profile) = try typedRequestCommand(reply: secondReply, binding: binding)
                XCTAssertThrowsError(try admitCommand(second, fixture: fixture))
                XCTAssertEqual(try typedOutcome(secondReply, submission: submission, profile: profile), .notAdmitted(.capacityExceeded, .never))
                XCTAssertEqual(try fixture.requests.state(requestID: request.requestID).phase, .queued)
                try first.withBorrowedInputDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
                XCTAssertEqual(try fixture.auditRecordCount, before)
                XCTAssertFalse(try fixture.db.read { try $0.commandSubmissionReserved(submission.binding) })
            }
        }
    }

    func testTypedRolledBackStorageFailureCanProveNoAdmission() throws {
        for checkpointed in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed), reply = try Endpoint()
            let (command, submission, profile) = try typedRequestCommand(reply: reply), before = try fixture.auditRecordCount
            try fixture.sql("CREATE TRIGGER fail_command_insert BEFORE INSERT ON audit_records_v1 BEGIN SELECT RAISE(ABORT,'fixture write failure'); END")
            XCTAssertThrowsError(try admitCommand(command, fixture: fixture))
            XCTAssertEqual(try typedOutcome(reply, submission: submission, profile: profile), .notAdmitted(.storageUnavailable, .storageUnavailable))
            XCTAssertEqual(try fixture.auditRecordCount, before)
            XCTAssertFalse(try fixture.db.read { try $0.commandSubmissionReserved(submission.binding) })
            XCTAssertThrowsError(try command.withBorrowedInputDescriptor { _ in () })
        }
    }

    func testTypedCheckpointFailureNeverClaimsNoAdmissionEvenAfterJournalCommit() throws {
        for prepare in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: true), reply = try Endpoint()
            let (command, submission, profile) = try typedRequestCommand(reply: reply), before = try fixture.auditRecordCount
            let condition = prepare ? "NEW.pending IS NOT NULL" : "NEW.pending IS NULL"
            try fixture.sql("CREATE TRIGGER fail_command_checkpoint BEFORE UPDATE ON continuity_v1 WHEN \(condition) BEGIN SELECT RAISE(ABORT,'fixture checkpoint failure'); END", continuity: true)
            XCTAssertThrowsError(try admitCommand(command, fixture: fixture))
            XCTAssertEqual(try typedOutcome(reply, submission: submission, profile: profile), .uncertain(.storageFailure))
            XCTAssertThrowsError(try command.withBorrowedInputDescriptor { _ in () })
            XCTAssertEqual(try sendReferences(reply.port), 1)
            XCTAssertEqual(try fixture.auditRecordCount, before + (prepare ? 0 : 1))
            XCTAssertTrue(try XCTUnwrap(fixture.continuity).read().pending != nil || prepare)
        }
    }

    func testTypedProtocolDraftRefusalsRequireAbsenceBeforeReportingTheirExactReason() throws {
        for checkpointed in [false, true] {
            for kind in 0..<3 {
                let fixture = try CommandRequestFixture(checkpointed: checkpointed), reply = try Endpoint()
                let (command, submission, profile) = try typedRequestCommand(reply: reply), base = fixture.draft(command)
                let contract = try kind == 0 ? RequestContract(requestKind: .command, wireVersion: 2, schemaVersion: base.contract.schemaVersion) : base.contract
                let draft = ApprovalRequestDraft(contract: contract, requiredFeatures: base.requiredFeatures, capture: base.capture, actions: base.actions,
                    firstObservedAt: base.firstObservedAt, deadlineMilliseconds: base.deadlineMilliseconds,
                    createdUnixMilliseconds: kind == 0 ? base.createdUnixMilliseconds : base.expiresUnixMilliseconds + UInt64(kind - 1),
                    expiresUnixMilliseconds: base.expiresUnixMilliseconds)
                let before = try fixture.auditRecordCount
                XCTAssertThrowsError(try admitCommand(command, fixture: fixture, draft: draft)) {
                    XCTAssertEqual($0 as? IssuedRequestError, kind == 0 ? .unsupportedContract : .invalidTimes)
                }
                XCTAssertEqual(try typedOutcome(reply, submission: submission, profile: profile),
                    .notAdmitted(kind == 0 ? .unsupported : .invalidRequest, .never))
                XCTAssertEqual(try fixture.auditRecordCount, before)
                XCTAssertFalse(try fixture.db.read { try $0.commandSubmissionReserved(submission.binding) })
                XCTAssertThrowsError(try command.withBorrowedInputDescriptor { _ in () })
            }
        }
    }

    func testTypedProtocolErrorsFromCallbacksStillCannotClaimNoAdmission() throws {
        for checkpointed in [false, true] {
            for failure: IssuedRequestError in [.unsupportedContract, .invalidTimes] {
                let fixture = try CommandRequestFixture(checkpointed: checkpointed), reply = try Endpoint()
                let (command, submission, profile) = try typedRequestCommand(reply: reply)
                XCTAssertThrowsError(try admitCommand(command, fixture: fixture, checkCancellation: { throw failure })) {
                    XCTAssertEqual($0 as? IssuedRequestError, failure)
                }
                XCTAssertEqual(try typedOutcome(reply, submission: submission, profile: profile), .uncertain(.admissionRejected))
                XCTAssertFalse(try fixture.db.read { try $0.commandSubmissionReserved(submission.binding) })
            }
        }
    }

    func testTypedUnsupportedContractRefusalUsesVerifiedRollback() throws {
        for checkpointed in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed), reply = try Endpoint()
            let (command, submission, profile) = try typedRequestCommand(reply: reply), base = fixture.draft(command)
            let draft = ApprovalRequestDraft(contract: base.contract, requiredFeatures: [999], capture: base.capture, actions: base.actions,
                firstObservedAt: base.firstObservedAt, deadlineMilliseconds: base.deadlineMilliseconds,
                createdUnixMilliseconds: base.createdUnixMilliseconds, expiresUnixMilliseconds: base.expiresUnixMilliseconds)
            XCTAssertThrowsError(try admitCommand(command, fixture: fixture, draft: draft)) {
                XCTAssertEqual($0 as? DecisionVerificationError, .unsupportedContract)
            }
            XCTAssertEqual(try typedOutcome(reply, submission: submission, profile: profile), .notAdmitted(.unsupported, .never))
            XCTAssertFalse(try fixture.db.read { try $0.commandSubmissionReserved(submission.binding) })
        }
    }

    func testTypedAbsenceProofCoversHistoricalNonceAndSubmissionSeparately() throws {
        for checkpointed in [false, true] {
            for reuseNonce in [false, true] {
                let fixture = try CommandRequestFixture(checkpointed: checkpointed), firstReply = try Endpoint()
                let (first, original, _) = try typedRequestCommand(reply: firstReply)
                let request = try admitCommand(first, fixture: fixture)
                _ = try fixture.requests.retirePending(requestID: request.requestID, reason: .cancelled, now: fixture.now(120), receiptTimeMs: nil)
                let binding = CapturedSubmission(id: reuseNonce ? Data(repeating: 88, count: 16) : original.binding.id,
                    nonce: reuseNonce ? original.binding.nonce : Data(repeating: 89, count: 32), callerBinding: assemblyBinding)
                let reply = try Endpoint(), (command, submission, profile) = try typedRequestCommand(reply: reply, binding: binding)
                XCTAssertThrowsError(try admitCommand(command, fixture: fixture, draft: fixture.draft(command, capture: Data([0xa0]))))
                XCTAssertEqual(try typedOutcome(reply, submission: submission, profile: profile), .uncertain(.duplicateSubmission))
                XCTAssertTrue(try fixture.db.read { try $0.commandSubmissionReserved(submission.binding) })
                if reuseNonce { XCTAssertNil(try fixture.reservation(submission.binding.id)) }
            }
        }
    }

    func testTypedCallbackErrorsCannotForgeAnOwnerRefusalAndRetainReplyAfterCleanup() throws {
        for checkpointed in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed), reply = try Endpoint()
            let (command, submission, profile) = try typedRequestCommand(reply: reply)
            XCTAssertThrowsError(try admitCommand(command, fixture: fixture, checkCancellation: { throw ApprovalCoordinatorError.capacityExceeded }))
            XCTAssertEqual(try typedOutcome(reply, submission: submission, profile: profile), .uncertain(.admissionRejected))
            XCTAssertThrowsError(try command.withBorrowedInputDescriptor { _ in () })
            XCTAssertEqual(try sendReferences(reply.port), 1)
            XCTAssertFalse(try fixture.db.read { try $0.commandSubmissionReserved(submission.binding) })
        }
    }

    func testTypedFailedAbsenceReadRemainsUncertainAndClosesAllResources() throws {
        for failure in 0..<3 {
            let fixture = try CommandRequestFixture(checkpointed: true), reply = try Endpoint()
            let (command, submission, profile) = try typedRequestCommand(reply: reply)
            if failure == 0 { try fixture.db.close() }
            if failure == 1 { try fixture.sql("UPDATE audit_epochs_v1 SET head=X'0000000000000002'") }
            if failure == 2 { XCTAssertEqual(chmod(fixture.root.appendingPathComponent("store/journal.sqlite").path, 0o644), 0) }
            XCTAssertThrowsError(try admitCommand(command, fixture: fixture, draft: fixture.draft(command, capture: Data([0xa0]))))
            XCTAssertEqual(try typedOutcome(reply, submission: submission, profile: profile), .uncertain(.storageFailure))
            XCTAssertThrowsError(try command.withBorrowedInputDescriptor { _ in () })
            XCTAssertEqual(try sendReferences(reply.port), 1)
        }
    }

    func testTypedAdmissionNegotiatesTheNewWireAndMatchesItsOriginalSubmission() throws {
        let endpoint = try Endpoint(), port = endpoint.port, expression = try selfExpression(), user = geteuid()
        let mac = handshakeMac, account = handshakeAccount
        let completed = DispatchSemaphore(value: 0), result = OSAllocatedUnfairLock(initialState: Result<Void, Error>?.none)
        DispatchQueue.global().async {
            defer { completed.signal() }
            result.withLock { output in output = Result {
                let receiver = try MachCommandCallerReceiver(receivePort: port, expression: expression, userID: user,
                    auditSessionID: nil, maxPayloadBytes: 8192)
                let session = try RetainedCommandHandshake(hello: receiver.receiveHello(timeoutMilliseconds: 5000),
                    capabilities: .admissionResults, macID: mac, accountID: account, expression: expression, userID: user, auditSessionID: nil)
                defer { session.close() }
                let input = try receiver.receiveAdmissionInput(timeoutMilliseconds: 5000)
                defer { input.closeIfUnclaimed() }
                let submission = try CommandSubmission(canonicalBytes: input.payload,
                    limits: CBORLimits(maxBytes: 8192, maxDepth: 16, maxItems: 1024), expectedSchemaVersion: 1)
                let payload = CommandAdmissionResultPayload(profile: session.profile, submission: submission.binding,
                    submissionDigest: Data(SHA256.hash(data: submission.canonicalBytes)), outcome: .uncertain(.admissionRejected))
                try input.sendAdmissionReply(payload.canonicalBytes)
            } }
        }
        let handshake = try MachCommandHandshakeClient.negotiate(authorityPort: port, expression: expression, userID: user,
            auditSessionID: nil, macID: mac, accountID: account, capabilities: .admissionResults)
        defer { handshake.close() }
        var pipeFDs: [Int32] = [-1, -1]
        XCTAssertEqual(pipe(&pipeFDs), 0); defer { for fd in pipeFDs { _ = Darwin.close(fd) } }
        XCTAssertEqual(Darwin.write(pipeFDs[1], "queued", 6), 6)
        let submission = try commandSubmission(binding: .init(id: Data(repeating: 2, count: 16), nonce: Data(repeating: 3, count: 32),
            callerBinding: handshake.profile.callerBinding))
        let response = try MachCommandAdmissionClient.submit(submission, inputDescriptor: pipeFDs[0],
            handshake: handshake, expression: expression, userID: user, auditSessionID: nil, maximumPayloadBytes: 8192, typedResult: true)
        XCTAssertEqual(response.profile, handshake.profile)
        let verified = try XCTUnwrap(response.verifiedResult)
        XCTAssertEqual(verified.outcome, .uncertain(.admissionRejected)); XCTAssertEqual(verified.retryClass, .never)
        XCTAssertEqual(verified.submission, submission.binding)
        XCTAssertEqual(completed.wait(timeout: .now() + 5), .success); try result.withLock { try $0?.get() }
        var bytes = [UInt8](repeating: 0, count: 6)
        XCTAssertEqual(Darwin.read(pipeFDs[0], &bytes, 6), 6); XCTAssertEqual(Data(bytes), Data("queued".utf8))
    }

    func testAdmissionClientNegotiatesAndAuthenticatesReplyWithoutReadingInput() throws {
        let endpoint = try Endpoint(), port = endpoint.port, expression = try selfExpression(), user = geteuid()
        let mac = handshakeMac, account = handshakeAccount
        let completed = DispatchSemaphore(value: 0), result = OSAllocatedUnfairLock(initialState: Result<Void, Error>?.none)
        DispatchQueue.global().async {
            defer { completed.signal() }
            result.withLock { output in output = Result {
                let receiver = try MachCommandCallerReceiver(receivePort: port, expression: expression, userID: user,
                    auditSessionID: nil, maxPayloadBytes: 8192)
                let session = try RetainedCommandHandshake(hello: receiver.receiveHello(timeoutMilliseconds: 5000),
                    capabilities: .admissionReplies, macID: mac, accountID: account, expression: expression, userID: user, auditSessionID: nil)
                defer { session.close() }
                let input = try receiver.receiveAdmissionInput(timeoutMilliseconds: 5000)
                defer { input.closeIfUnclaimed() }
                _ = try CommandSubmission(canonicalBytes: input.payload,
                    limits: CBORLimits(maxBytes: 8192, maxDepth: 16, maxItems: 1024), expectedSchemaVersion: 1)
                try input.sendAdmissionReply(Data([0xa0]))
            } }
        }
        let handshake = try MachCommandHandshakeClient.negotiate(authorityPort: port, expression: expression, userID: user,
            auditSessionID: nil, macID: mac, accountID: account, capabilities: .admissionReplies)
        defer { handshake.close() }
        var pipeFDs: [Int32] = [-1, -1]
        XCTAssertEqual(pipe(&pipeFDs), 0); defer { for fd in pipeFDs { _ = Darwin.close(fd) } }
        XCTAssertEqual(Darwin.write(pipeFDs[1], "queued", 6), 6)
        let submission = try commandSubmission(binding: .init(id: Data(repeating: 2, count: 16), nonce: Data(repeating: 3, count: 32),
            callerBinding: handshake.profile.callerBinding))
        let response = try MachCommandAdmissionClient.submit(submission, inputDescriptor: pipeFDs[0],
            handshake: handshake, expression: expression, userID: user, auditSessionID: nil, maximumPayloadBytes: 8192)
        XCTAssertEqual(response.payload, Data([0xa0])); XCTAssertEqual(response.profile, handshake.profile)
        XCTAssertEqual(completed.wait(timeout: .now() + 5), .success); try result.withLock { try $0?.get() }
        var bytes = [UInt8](repeating: 0, count: 6)
        XCTAssertEqual(Darwin.read(pipeFDs[0], &bytes, 6), 6); XCTAssertEqual(Data(bytes), Data("queued".utf8))
    }

    func testAdmissionClientRejectsLegacyBindingAndCurrentAuthorityFailureBeforeExposure() throws {
        let endpoint = try Endpoint(), fd = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(fd, 0); defer { _ = Darwin.close(fd) }
        let old = try admissionClientFixture(endpoint.port, input: 2), current = try admissionClientFixture(endpoint.port)
        defer { old.close(); current.close() }
        for handshake in [old, current] {
            let submission = try commandSubmission(binding: .init(id: Data(repeating: 2, count: 16), nonce: Data(repeating: 3, count: 32),
                callerBinding: Data(repeating: 9, count: 16)))
            XCTAssertThrowsError(try MachCommandAdmissionClient.submit(submission, inputDescriptor: fd,
                handshake: handshake, expression: selfExpression(), userID: geteuid(), auditSessionID: nil, maximumPayloadBytes: 8192))
        }
        XCTAssertThrowsError(try MachCommandAdmissionClient.submit(commandSubmission(), inputDescriptor: fd,
            handshake: current, expression: selfExpression(), userID: geteuid() ^ 1, auditSessionID: nil, maximumPayloadBytes: 8192))
        XCTAssertThrowsError(try receiver(endpoint).receiveAdmissionInput(timeoutMilliseconds: 10)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .timeout)
        }
    }

    func testAdmissionReplyMustMatchTheRetainedAuthorityIncarnation() throws {
        let endpoint = try Endpoint(), handshake = try admissionClientFixture(endpoint.port), peer = try Peer(endpoint: endpoint)
        defer { handshake.close() }
        let reply = try receiver(endpoint, expression: "true").receive(timeoutMilliseconds: 5000)
        defer { reply.caller.close() }
        XCTAssertThrowsError(try handshake.authenticateReply(reply.caller, expression: "true", userID: geteuid(), auditSessionID: nil)) {
            XCTAssertEqual($0 as? MachCommandHandshakeError, .wrongBinding)
        }
        try peer.advance()
        let replacement = try receiver(endpoint, expression: "true").receive(timeoutMilliseconds: 5000)
        replacement.caller.close()
        try peer.stop()
    }

    private func serveAdmission(_ port: mach_port_t, response: Data?) throws -> (DispatchSemaphore, OSAllocatedUnfairLock<Result<Void, Error>?>) {
        let expression = try selfExpression(), user = geteuid(), completed = DispatchSemaphore(value: 0)
        let result = OSAllocatedUnfairLock(initialState: Result<Void, Error>?.none)
        DispatchQueue.global().async {
            defer { completed.signal() }
            result.withLock { output in output = Result {
                let receiver = try MachCommandCallerReceiver(receivePort: port, expression: expression, userID: user,
                    auditSessionID: nil, maxPayloadBytes: 8192)
                let input = try receiver.receiveAdmissionInput(timeoutMilliseconds: 5000)
                defer { input.closeIfUnclaimed() }
                if let response { try input.sendAdmissionReply(response) }
            } }
        }
        return (completed, result)
    }

    func testAdmissionClientLostReplyKeepsInputAndBorrowedAuthorityRight() throws {
        let endpoint = try Endpoint(), handshake = try admissionClientFixture(endpoint.port)
        defer { handshake.close() }
        var pipeFDs: [Int32] = [-1, -1]
        XCTAssertEqual(pipe(&pipeFDs), 0); defer { for fd in pipeFDs { _ = Darwin.close(fd) } }
        XCTAssertEqual(Darwin.write(pipeFDs[1], "queued", 6), 6)
        let baseline = try sendReferences(endpoint.port), server = try serveAdmission(endpoint.port, response: nil)
        XCTAssertThrowsError(try MachCommandAdmissionClient.submit(commandSubmission(), inputDescriptor: pipeFDs[0],
            handshake: handshake, expression: selfExpression(), userID: geteuid(), auditSessionID: nil,
            maximumPayloadBytes: 8192, timeoutMilliseconds: 1000)) { XCTAssertEqual($0 as? MachCommandCallerError, .timeout) }
        XCTAssertEqual(server.0.wait(timeout: .now() + 5), .success); try server.1.withLock { try $0?.get() }
        XCTAssertEqual(try sendReferences(endpoint.port), baseline)
        var bytes = [UInt8](repeating: 0, count: 6)
        XCTAssertEqual(Darwin.read(pipeFDs[0], &bytes, 6), 6); XCTAssertEqual(Data(bytes), Data("queued".utf8))
    }

    func testAdmissionClientContinuousDeadlineAndCancellationDoNotExposeInputEarly() throws {
        let endpoint = try Endpoint(), handshake = try admissionClientFixture(endpoint.port), fd = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(fd, 0); defer { handshake.close(); _ = Darwin.close(fd) }
        var tick: UInt64 = 0
        XCTAssertThrowsError(try MachCommandAdmissionClient.submit(commandSubmission(), inputDescriptor: fd,
            handshake: handshake, expression: selfExpression(), userID: geteuid(), auditSessionID: nil,
            maximumPayloadBytes: 8192, timeoutMilliseconds: 10, clock: { defer { tick += 10 }; return tick })) {
            XCTAssertEqual($0 as? MachCommandCallerError, .timeout)
        }
        XCTAssertThrowsError(try MachCommandAdmissionClient.submit(commandSubmission(), inputDescriptor: fd,
            handshake: handshake, expression: selfExpression(), userID: geteuid(), auditSessionID: nil, maximumPayloadBytes: 8192,
            checkCancellation: { throw MachCommandHandshakeError.retired }))
        XCTAssertThrowsError(try receiver(endpoint).receiveAdmissionInput(timeoutMilliseconds: 10)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .timeout)
        }
    }

    func testAdmissionClientCancellationDuringReplyWaitPreservesTheSingleSubmission() throws {
        let endpoint = try Endpoint(), handshake = try admissionClientFixture(endpoint.port)
        defer { handshake.close() }
        let fd = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(fd, 0); defer { _ = Darwin.close(fd) }
        let server = try serveAdmission(endpoint.port, response: nil)
        var checks = 0
        XCTAssertThrowsError(try MachCommandAdmissionClient.submit(commandSubmission(), inputDescriptor: fd,
            handshake: handshake, expression: selfExpression(), userID: geteuid(), auditSessionID: nil,
            maximumPayloadBytes: 8192, timeoutMilliseconds: 5000, checkCancellation: {
                checks += 1
                if checks == 4 { throw MachCommandHandshakeError.retired }
            })) { XCTAssertEqual($0 as? MachCommandHandshakeError, .retired) }
        XCTAssertEqual(checks, 4)
        XCTAssertEqual(server.0.wait(timeout: .now() + 5), .success); try server.1.withLock { try $0?.get() }
        XCTAssertThrowsError(try receiver(endpoint).receiveAdmissionInput(timeoutMilliseconds: 10)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .timeout)
        }
    }

    func testAdmissionClientRejectsAnAuthenticatedReplyAtTheFinalDeadline() throws {
        let endpoint = try Endpoint(), handshake = try admissionClientFixture(endpoint.port)
        defer { handshake.close() }
        let fd = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(fd, 0); defer { _ = Darwin.close(fd) }
        let server = try serveAdmission(endpoint.port, response: Data([0xa0]))
        var samples = 0
        XCTAssertThrowsError(try MachCommandAdmissionClient.submit(commandSubmission(), inputDescriptor: fd,
            handshake: handshake, expression: selfExpression(), userID: geteuid(), auditSessionID: nil,
            maximumPayloadBytes: 8192, timeoutMilliseconds: 1000, clock: {
                samples += 1
                return samples < 5 ? 0 : 1000
            })) { XCTAssertEqual($0 as? MachCommandCallerError, .timeout) }
        XCTAssertEqual(samples, 5)
        XCTAssertEqual(server.0.wait(timeout: .now() + 5), .success); try server.1.withLock { try $0?.get() }
    }

    func testAdmissionClientRetainsNegotiatedDestinationAndClosurePreventsSubmission() throws {
        let endpoint = try Endpoint(), baseline = try sendReferences(endpoint.port)
        let handshake = try admissionClientFixture(endpoint.port)
        XCTAssertEqual(try sendReferences(endpoint.port), baseline + 1)
        XCTAssertEqual(try handshake.borrowedAuthorityPort(), endpoint.port)
        handshake.close(); handshake.close()
        XCTAssertEqual(try sendReferences(endpoint.port), baseline)
        let fd = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(fd, 0); defer { _ = Darwin.close(fd) }
        XCTAssertThrowsError(try MachCommandAdmissionClient.submit(commandSubmission(), inputDescriptor: fd,
            handshake: handshake, expression: selfExpression(), userID: geteuid(), auditSessionID: nil, maximumPayloadBytes: 8192))
        XCTAssertThrowsError(try receiver(endpoint).receiveAdmissionInput(timeoutMilliseconds: 10)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .timeout)
        }
    }

    func testPublicAdmissionClientRequiresRootReleasePolicyBeforeSubmission() throws {
        let endpoint = try Endpoint(), handshake = try admissionClientFixture(endpoint.port)
        defer { handshake.close() }
        let policy = try XPCPeerPolicy(teamID: "TEAMID1234", componentIdentifier: "dev.remozio.fixture",
            approvedCodeDirectoryHashes: [Data(repeating: 1, count: 20)], expectedUserID: 1)
        XCTAssertThrowsError(try MachCommandAdmissionClient.submit(commandSubmission(), inputDescriptor: -1,
            handshake: handshake, authorityPolicy: policy, maximumPayloadBytes: 8192)) {
            XCTAssertEqual($0 as? MachCommandHandshakeError, .invalidConfiguration)
        }
        XCTAssertThrowsError(try receiver(endpoint).receiveAdmissionInput(timeoutMilliseconds: 10)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .timeout)
        }
    }

    func testAdmissionWireFullQueueCleanupPreservesBorrowedRightsAndInput() throws {
        let endpoint = try Endpoint(), reply = try Endpoint(), fd = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(fd, 0); defer { _ = Darwin.close(fd) }
        var attributes = mach_port_limits_t(mpl_qlimit: 1)
        XCTAssertEqual(withUnsafeMutablePointer(to: &attributes) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: 1) {
                mach_port_set_attributes(mach_task_self_, endpoint.port, MACH_PORT_LIMITS_INFO, $0, mach_msg_type_number_t(MemoryLayout<mach_port_limits_t>.size / MemoryLayout<natural_t>.size))
            }
        }, KERN_SUCCESS)
        try endpoint.send(Data([1]))
        let baseline = try sendReferences(reply.port), authorityBaseline = try sendReferences(endpoint.port), flags = fcntl(fd, F_GETFL)
        XCTAssertThrowsError(try MachCommandAdmissionWire.send(Data([1]), inputDescriptor: fd, destination: endpoint.port,
            replyPort: reply.port, maximumPayloadBytes: 8192, timeoutMilliseconds: 10)) {
            guard case .mach(let result) = $0 as? MachCommandCallerError else { return XCTFail("Wrong failure") }
            XCTAssertEqual(result & ~MACH_MSG_MASK, MACH_SEND_TIMED_OUT)
        }
        XCTAssertEqual(try sendReferences(reply.port), baseline); XCTAssertEqual(try sendReferences(endpoint.port), authorityBaseline)
        XCTAssertEqual(fcntl(fd, F_GETFL), flags)
        let filler = try receiver(endpoint).receive(timeoutMilliseconds: 1000); filler.caller.close()
        let input = try admissionInput(endpoint, reply: reply, descriptor: fd, payload: Data([2])); input.closeIfUnclaimed()
        XCTAssertEqual(try sendReferences(reply.port), baseline)
    }

    func testRejectedComplexPacketReleasesImportedSendRight() throws {
        let endpoint = try Endpoint(), carried = try Endpoint(), receiver = try receiver(endpoint)
        var baseline: mach_port_urefs_t = 0
        XCTAssertEqual(mach_port_get_refs(mach_task_self_, carried.port, MACH_PORT_RIGHT_SEND, &baseline), KERN_SUCCESS)
        try endpoint.sendPort(carried.port)
        XCTAssertThrowsError(try receiver.receive(timeoutMilliseconds: 1000)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .malformed)
        }
        var final: mach_port_urefs_t = 0
        XCTAssertEqual(mach_port_get_refs(mach_task_self_, carried.port, MACH_PORT_RIGHT_SEND, &final), KERN_SUCCESS)
        XCTAssertEqual(final, baseline)
        try endpoint.send(Data([1]))
        XCTAssertEqual(try receiver.receive(timeoutMilliseconds: 1000).payload, Data([1]))
    }

    private func sendReferences(_ port: mach_port_t) throws -> mach_port_urefs_t {
        var count: mach_port_urefs_t = 0
        let result = mach_port_get_refs(mach_task_self_, port, MACH_PORT_RIGHT_SEND, &count)
        guard result == KERN_SUCCESS else { throw MachCommandCallerError.mach(result) }
        return count
    }

    func testPreviewRetainsQueueHeadAndDoesNotImportSendRights() throws {
        let endpoint = try Endpoint(), carried = try Endpoint()
        let baseline = try sendReferences(carried.port)
        try endpoint.sendPort(carried.port, outOfLineBytes: 65536)
        var first = remozio_mach_preview_t(), second = remozio_mach_preview_t()
        XCTAssertEqual(remozio_preview_audit(endpoint.port, 1000, &first), KERN_SUCCESS)
        XCTAssertEqual(remozio_preview_audit(endpoint.port, 1000, &second), KERN_SUCCESS)
        XCTAssertEqual(first.sequence, second.sequence)
        XCTAssertEqual(first.identifier, MachCommandCallerReceiver.messageID)
        XCTAssertEqual(audit_token_to_pid(first.token), getpid())
        XCTAssertEqual(audit_token_to_euid(first.token), geteuid())
        XCTAssertEqual(try sendReferences(carried.port), baseline)
        let capacity = Int(first.size) + MemoryLayout<mach_msg_audit_trailer_t>.size
        let storage = UnsafeMutableRawPointer.allocate(byteCount: capacity, alignment: 8)
        defer { storage.deallocate() }
        storage.initializeMemory(as: UInt8.self, repeating: 0, count: capacity)
        let header = storage.bindMemory(to: mach_msg_header_t.self, capacity: 1)
        let result = remozio_receive_audit(header, UInt32(capacity), endpoint.port, 1000)
        XCTAssertEqual(result, KERN_SUCCESS)
        guard result == KERN_SUCCESS else { return }
        XCTAssertEqual(try sendReferences(carried.port), baseline + 1)
        let trailer = storage.loadUnaligned(fromByteOffset: Int(first.size), as: mach_msg_audit_trailer_t.self)
        XCTAssertEqual(trailer.msgh_seqno, first.sequence)
        var receivedToken = trailer.msgh_audit, previewToken = first.token
        XCTAssertTrue(withUnsafeBytes(of: &receivedToken) { a in
            withUnsafeBytes(of: &previewToken) { b in a.elementsEqual(b) }
        })
        let outOfLine = storage.loadUnaligned(fromByteOffset: MemoryLayout<mach_msg_header_t>.size +
            MemoryLayout<mach_msg_body_t>.size + MemoryLayout<mach_msg_port_descriptor_t>.size,
            as: mach_msg_ool_descriptor_t.self)
        XCTAssertEqual(outOfLine.size, 65536)
        XCTAssertEqual(outOfLine.type, UInt32(MACH_MSG_OOL_DESCRIPTOR))
        if let address = outOfLine.address {
            XCTAssertEqual(Data(bytes: address, count: Int(outOfLine.size)), Data(repeating: 0x5a, count: 65536))
        } else { XCTFail("The received out-of-line buffer is missing") }
        mach_msg_destroy(header)
        XCTAssertEqual(try sendReferences(carried.port), baseline)
    }

    func testWrongSenderPolicyDiscardsComplexPacketBeforeImport() throws {
        let endpoint = try Endpoint(), carried = try Endpoint()
        let baseline = try sendReferences(carried.port)
        let rejected = try receiver(endpoint, user: geteuid() ^ 1)
        try endpoint.sendPort(carried.port, outOfLineBytes: 65536)
        XCTAssertThrowsError(try rejected.receive(timeoutMilliseconds: 1000)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .wrongPeer)
        }
        XCTAssertEqual(try sendReferences(carried.port), baseline)
        try endpoint.send(Data([4]))
        XCTAssertEqual(try receiver(endpoint).receive(timeoutMilliseconds: 1000).payload, Data([4]))
    }

    func testDiscardConsumesOnlyThePreviewedQueueHead() throws {
        let endpoint = try Endpoint(), carried = try Endpoint()
        let baseline = try sendReferences(carried.port)
        try endpoint.sendPort(carried.port, outOfLineBytes: 65536)
        try endpoint.send(Data([5]))
        var first = remozio_mach_preview_t(), second = remozio_mach_preview_t()
        XCTAssertEqual(remozio_preview_audit(endpoint.port, 1000, &first), KERN_SUCCESS)
        XCTAssertEqual(remozio_discard_message(endpoint.port), MACH_RCV_TOO_LARGE)
        XCTAssertEqual(try sendReferences(carried.port), baseline)
        XCTAssertEqual(remozio_preview_audit(endpoint.port, 1000, &second), KERN_SUCCESS)
        XCTAssertEqual(second.sequence, first.sequence + 1)
        XCTAssertEqual(try receiver(endpoint).receive(timeoutMilliseconds: 1000).payload, Data([5]))
    }

    func testBareHeaderRemainsQueuedUntilExplicitDiscard() throws {
        let endpoint = try Endpoint()
        try endpoint.sendBareHeader()
        var preview = remozio_mach_preview_t()
        XCTAssertEqual(remozio_preview_audit(endpoint.port, 1000, &preview), KERN_SUCCESS)
        XCTAssertEqual(preview.size, UInt32(MemoryLayout<mach_msg_header_t>.size))
        XCTAssertThrowsError(try receiver(endpoint).receive(timeoutMilliseconds: 1000)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .malformed)
        }
        try endpoint.send(Data([6]))
        XCTAssertEqual(try receiver(endpoint).receive(timeoutMilliseconds: 1000).payload, Data([6]))
    }

    func testInputCarrierRetainsActualPipeAfterSenderClosesItsHandles() throws {
        let endpoint = try Endpoint(), receiver = try receiver(endpoint)
        var descriptors: [Int32] = [-1, -1]
        guard pipe(&descriptors) == 0 else { throw MachCommandCallerError.unavailable }
        defer { for fd in descriptors where fd >= 0 { _ = Darwin.close(fd) } }
        let initialFlags = fcntl(descriptors[0], F_GETFL)
        XCTAssertEqual(fcntl(descriptors[0], F_SETFL, initialFlags | O_NONBLOCK), 0)
        let queued = Data("queued".utf8)
        XCTAssertEqual(queued.withUnsafeBytes { Darwin.write(descriptors[1], $0.baseAddress, $0.count) }, queued.count)
        var fileport: mach_port_t = UInt32(MACH_PORT_NULL)
        XCTAssertEqual(fileport_makeport(descriptors[0], &fileport), 0)
        defer { if fileport != MACH_PORT_NULL { _ = mach_port_deallocate(mach_task_self_, fileport) } }
        let payload = Data([0xff, 0, 3])
        try endpoint.sendInput(payload, fileport: fileport)
        XCTAssertEqual(mach_port_deallocate(mach_task_self_, fileport), KERN_SUCCESS)
        fileport = UInt32(MACH_PORT_NULL)
        XCTAssertEqual(Darwin.close(descriptors[0]), 0)
        descriptors[0] = -1
        let submission = try receiver.receiveInput(timeoutMilliseconds: 1000)
        XCTAssertEqual(submission.payload, payload)
        XCTAssertEqual(submission.caller.requester.pid, UInt32(getpid()))
        let capture = try submission.input.capture(streamBinding: Data(repeating: 0xa1, count: 16))
        XCTAssertEqual(capture.kind, .pipe)
        XCTAssertEqual(capture.kind.minimumSchemaVersion, 1)
        XCTAssertEqual(capture.streamBinding, Data(repeating: 0xa1, count: 16))
        XCTAssertNil(capture.observedPath)
        let later = Data("later".utf8)
        XCTAssertEqual(later.withUnsafeBytes { Darwin.write(descriptors[1], $0.baseAddress, $0.count) }, later.count)
        var imported: Int32 = -1
        try submission.input.withBorrowedDescriptor { fd in
            imported = fd
            XCTAssertNotEqual(fcntl(fd, F_GETFD) & FD_CLOEXEC, 0)
            XCTAssertEqual(fcntl(fd, F_GETFL), initialFlags | O_NONBLOCK)
            var bytes = [UInt8](repeating: 0, count: queued.count + later.count)
            XCTAssertEqual(Darwin.read(fd, &bytes, bytes.count), bytes.count)
            XCTAssertEqual(Data(bytes), queued + later)
        }
        submission.input.close(); submission.input.close()
        XCTAssertEqual(fcntl(imported, F_GETFD), -1)
        XCTAssertEqual(errno, EBADF)
        XCTAssertThrowsError(try submission.input.withBorrowedDescriptor { _ in XCTFail("A retired descriptor was borrowed") }) {
            XCTAssertEqual($0 as? RetainedCommandInputError, .closed)
        }
    }

    func testOrdinaryMachRightCannotBecomeInputAndNextPacketWorks() throws {
        let endpoint = try Endpoint(), carried = try Endpoint(), receiver = try receiver(endpoint)
        let baseline = try sendReferences(carried.port)
        try endpoint.sendInput(Data([1]), fileport: carried.port)
        XCTAssertThrowsError(try receiver.receiveInput(timeoutMilliseconds: 1000)) {
            XCTAssertEqual($0 as? RetainedCommandInputError, .system(EINVAL))
        }
        XCTAssertEqual(try sendReferences(carried.port), baseline)
        try endpoint.send(Data([2]))
        XCTAssertEqual(try receiver.receive(timeoutMilliseconds: 1000).payload, Data([2]))
    }

    func testInputCarrierRejectsCountsVersionsAndWrongPeerWithoutPoisoningQueue() throws {
        let endpoint = try Endpoint(), receiver = try receiver(endpoint)
        let fd = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        guard fd >= 0 else { throw MachCommandCallerError.unavailable }
        defer { _ = Darwin.close(fd) }
        var fileport: mach_port_t = UInt32(MACH_PORT_NULL)
        XCTAssertEqual(fileport_makeport(fd, &fileport), 0)
        defer { _ = mach_port_deallocate(mach_task_self_, fileport) }
        let baseline = try sendReferences(fileport)
        for count in [0, 2] {
            try endpoint.sendInput(Data([1]), fileport: fileport, descriptorCount: count)
            XCTAssertThrowsError(try receiver.receiveInput(timeoutMilliseconds: 1000))
            XCTAssertEqual(try sendReferences(fileport), baseline)
        }
        try endpoint.sendInput(Data([1]), fileport: fileport, version: 3)
        XCTAssertThrowsError(try receiver.receiveInput(timeoutMilliseconds: 1000)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .version)
        }
        try endpoint.sendInput(Data([1]), fileport: fileport)
        XCTAssertThrowsError(try self.receiver(endpoint, user: geteuid() ^ 1).receiveInput(timeoutMilliseconds: 1000)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .wrongPeer)
        }
        XCTAssertEqual(try sendReferences(fileport), baseline)
        try endpoint.sendInput(Data([2]), fileport: fileport)
        let submission = try receiver.receiveInput(timeoutMilliseconds: 1000)
        XCTAssertEqual(submission.payload, Data([2]))
        XCTAssertEqual(try sendReferences(fileport), baseline)
        try submission.input.withBorrowedDescriptor { fd in
            var byte: UInt8 = 0
            XCTAssertEqual(Darwin.read(fd, &byte, 1), 0)
        }
    }

    func testCarrierVersionsCannotSilentlyDowngradeEachOther() throws {
        let endpoint = try Endpoint(), receiver = try receiver(endpoint)
        let fd = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        guard fd >= 0 else { throw MachCommandCallerError.unavailable }
        defer { _ = Darwin.close(fd) }
        var fileport: mach_port_t = UInt32(MACH_PORT_NULL)
        XCTAssertEqual(fileport_makeport(fd, &fileport), 0)
        defer { _ = mach_port_deallocate(mach_task_self_, fileport) }
        try endpoint.sendInput(Data([1]), fileport: fileport)
        XCTAssertThrowsError(try receiver.receive(timeoutMilliseconds: 1000))
        try endpoint.send(Data([1]))
        XCTAssertThrowsError(try receiver.receiveInput(timeoutMilliseconds: 1000))
        try endpoint.sendInput(Data([2]), fileport: fileport)
        XCTAssertEqual(try receiver.receiveInput(timeoutMilliseconds: 1000).payload, Data([2]))
    }

    func testInputCarrierPreservesRegularFileIdentityAndOffset() throws {
        let endpoint = try Endpoint(), receiver = try receiver(endpoint)
        let path = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).path
        let fd = Darwin.open(path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw MachCommandCallerError.unavailable }
        defer { _ = Darwin.close(fd); _ = Darwin.unlink(path) }
        let contents = Data("012345".utf8)
        XCTAssertEqual(contents.withUnsafeBytes { Darwin.write(fd, $0.baseAddress, $0.count) }, contents.count)
        XCTAssertEqual(lseek(fd, 2, SEEK_SET), 2)
        var original = stat()
        XCTAssertEqual(fstat(fd, &original), 0)
        var fileport: mach_port_t = UInt32(MACH_PORT_NULL)
        XCTAssertEqual(fileport_makeport(fd, &fileport), 0)
        defer { _ = mach_port_deallocate(mach_task_self_, fileport) }
        try endpoint.sendInput(Data([7]), fileport: fileport)
        let submission = try receiver.receiveInput(timeoutMilliseconds: 1000)
        let capture = try submission.input.capture(streamBinding: Data(repeating: 0xa2, count: 16))
        XCTAssertEqual(capture.kind, .file)
        XCTAssertEqual(capture.kind.minimumSchemaVersion, 1)
        XCTAssertEqual(capture.identity, CapturedFileIdentity(device: UInt64(UInt32(bitPattern: original.st_dev)), inode: original.st_ino))
        XCTAssertNotNil(capture.observedPath)
        try submission.input.withBorrowedDescriptor { imported in
            var observed = stat()
            XCTAssertEqual(fstat(imported, &observed), 0)
            XCTAssertEqual(observed.st_dev, original.st_dev)
            XCTAssertEqual(observed.st_ino, original.st_ino)
            XCTAssertEqual(observed.st_mode, original.st_mode)
            XCTAssertEqual(lseek(imported, 0, SEEK_CUR), 2)
            XCTAssertEqual(lseek(fd, 0, SEEK_CUR), 2)
            var bytes = [UInt8](repeating: 0, count: 4)
            XCTAssertEqual(Darwin.read(imported, &bytes, 4), 4)
            XCTAssertEqual(Data(bytes), Data("2345".utf8))
            XCTAssertEqual(lseek(fd, 0, SEEK_CUR), 6)
        }
    }

    func testInputCarrierRejectsOutOfLineDescriptorBeforeParsingPayload() throws {
        let endpoint = try Endpoint(), receiver = try receiver(endpoint)
        try endpoint.sendOutOfLineInput()
        XCTAssertThrowsError(try receiver.receiveInput(timeoutMilliseconds: 1000)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .malformed)
        }
        try endpoint.send(Data([8]))
        XCTAssertEqual(try receiver.receive(timeoutMilliseconds: 1000).payload, Data([8]))
    }

    private func inputSubmission(_ fd: Int32, payload: Data = Data([1])) throws -> ReceivedMachCommandInputSubmission {
        let endpoint = try Endpoint()
        var fileport: mach_port_t = UInt32(MACH_PORT_NULL)
        guard fileport_makeport(fd, &fileport) == 0 else { throw RetainedCommandInputError.system(errno) }
        defer { _ = mach_port_deallocate(mach_task_self_, fileport) }
        try endpoint.sendInput(payload, fileport: fileport)
        return try receiver(endpoint, maximum: 8192).receiveInput(timeoutMilliseconds: 1000)
    }

    func testSocketCapturePreservesQueuedInputAndSharedFlags() throws {
        var pair: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0 else { throw RetainedCommandInputError.system(errno) }
        defer { for fd in pair { _ = Darwin.close(fd) } }
        let flags = fcntl(pair[0], F_GETFL)
        XCTAssertEqual(fcntl(pair[0], F_SETFL, flags | O_NONBLOCK), 0)
        let queued = Data("socket".utf8)
        XCTAssertEqual(queued.withUnsafeBytes { Darwin.write(pair[1], $0.baseAddress, $0.count) }, queued.count)
        let submission = try inputSubmission(pair[0])
        defer { submission.input.close(); submission.caller.close() }
        let capture = try submission.input.capture(streamBinding: Data(repeating: 0xa3, count: 16))
        XCTAssertEqual(capture.kind, .socket)
        XCTAssertEqual(capture.kind.minimumSchemaVersion, 2)
        XCTAssertNil(capture.observedPath)
        XCTAssertNotNil(capture.identity)
        XCTAssertEqual(fcntl(pair[0], F_GETFL), flags | O_NONBLOCK)
        try submission.input.withBorrowedDescriptor { fd in
            var bytes = [UInt8](repeating: 0, count: queued.count)
            XCTAssertEqual(Darwin.read(fd, &bytes, bytes.count), bytes.count)
            XCTAssertEqual(Data(bytes), queued)
        }
    }

    func testDirectoryAndDeviceCaptureKeepDistinctKinds() throws {
        let resources: [(String, Int32, CommandInputKind)] = [
            (FileManager.default.temporaryDirectory.path, O_RDONLY | O_DIRECTORY, .directory),
            ("/dev/zero", O_RDONLY, .device), ("/dev/null", O_RDONLY, .null),
        ]
        for (path, flags, kind) in resources {
            let fd = Darwin.open(path, flags | O_CLOEXEC)
            guard fd >= 0 else { throw RetainedCommandInputError.system(errno) }
            defer { _ = Darwin.close(fd) }
            let submission = try inputSubmission(fd)
            defer { submission.input.close(); submission.caller.close() }
            let capture = try submission.input.capture(streamBinding: Data(repeating: 0xa4, count: 16))
            XCTAssertEqual(capture.kind, kind)
            if kind == .null {
                XCTAssertNil(capture.streamBinding); XCTAssertNil(capture.observedPath); XCTAssertNil(capture.identity)
            } else {
                var original = stat()
                XCTAssertEqual(fstat(fd, &original), 0)
                XCTAssertEqual(capture.identity, CapturedFileIdentity(device: UInt64(UInt32(bitPattern: original.st_dev)), inode: original.st_ino))
                XCTAssertNotNil(capture.observedPath)
                XCTAssertEqual(capture.kind.minimumSchemaVersion, 2)
            }
            XCTAssertEqual(fcntl(fd, F_GETFL) & O_ACCMODE, O_RDONLY)
        }
    }

    func testTerminalCaptureUsesKernelTerminalObservationWithoutReadingInput() throws {
        var master: Int32 = -1, slave: Int32 = -1
        guard openpty(&master, &slave, nil, nil, nil) == 0 else { throw RetainedCommandInputError.system(errno) }
        defer { _ = Darwin.close(master); _ = Darwin.close(slave) }
        let flags = fcntl(slave, F_GETFL)
        let bytes = Data("terminal\n".utf8)
        XCTAssertEqual(bytes.withUnsafeBytes { Darwin.write(master, $0.baseAddress, $0.count) }, bytes.count)
        let submission = try inputSubmission(slave)
        defer { submission.input.close(); submission.caller.close() }
        let capture = try submission.input.capture(streamBinding: Data(repeating: 0xa5, count: 16))
        XCTAssertEqual(capture.kind, .tty)
        XCTAssertEqual(capture.kind.minimumSchemaVersion, 1)
        XCTAssertNotNil(capture.observedPath)
        XCTAssertEqual(fcntl(slave, F_GETFL), flags)
        try submission.input.withBorrowedDescriptor { fd in
            // A bounded readiness wait keeps a failed observation from blocking the test on an empty terminal.
            var ready = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            XCTAssertEqual(poll(&ready, 1, 1000), 1)
            guard ready.revents & Int16(POLLIN) != 0 else { return }
            var actual = [UInt8](repeating: 0, count: bytes.count)
            XCTAssertEqual(Darwin.read(fd, &actual, actual.count), actual.count)
            XCTAssertEqual(Data(actual), bytes)
        }
    }

    func testCaptureRejectsWriteOnlyInputAndInvalidBindingsAndRetiredOwner() throws {
        let fd = Darwin.open("/dev/null", O_WRONLY | O_CLOEXEC)
        guard fd >= 0 else { throw RetainedCommandInputError.system(errno) }
        defer { _ = Darwin.close(fd) }
        let submission = try inputSubmission(fd)
        defer { submission.input.close(); submission.caller.close() }
        for count in [0, 15, 17] {
            XCTAssertThrowsError(try submission.input.capture(streamBinding: Data(repeating: 1, count: count))) {
                XCTAssertEqual($0 as? RetainedCommandInputError, .invalidBinding)
            }
        }
        XCTAssertThrowsError(try submission.input.capture(streamBinding: Data(repeating: 1, count: 16))) {
            XCTAssertEqual($0 as? RetainedCommandInputError, .notReadable)
        }
        XCTAssertEqual(fcntl(fd, F_GETFL) & O_ACCMODE, O_WRONLY)
        submission.input.close()
        XCTAssertThrowsError(try submission.input.capture(streamBinding: Data(repeating: 1, count: 16))) {
            XCTAssertEqual($0 as? RetainedCommandInputError, .closed)
        }
    }

    func testEventOnlyInputIsNotAdvertisedAsReadable() throws {
        let path = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).path
        let created = Darwin.open(path, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0o600)
        guard created >= 0 else { throw RetainedCommandInputError.system(errno) }
        XCTAssertEqual(Darwin.close(created), 0)
        defer { _ = Darwin.unlink(path) }
        let fd = Darwin.open(path, O_EVTONLY | O_CLOEXEC)
        guard fd >= 0 else { throw RetainedCommandInputError.system(errno) }
        defer { _ = Darwin.close(fd) }
        let submission = try inputSubmission(fd)
        defer { submission.input.close(); submission.caller.close() }
        XCTAssertThrowsError(try submission.input.capture(streamBinding: Data(repeating: 1, count: 16))) {
            XCTAssertEqual($0 as? RetainedCommandInputError, .notReadable)
        }
        XCTAssertNotEqual(fcntl(fd, F_GETFL) & O_EVTONLY, 0)
    }

    func testPathReplacementCannotReplaceTheCapturedInputObject() throws {
        let path = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).path
        let original = Darwin.open(path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0o600)
        guard original >= 0 else { throw RetainedCommandInputError.system(errno) }
        defer { _ = Darwin.close(original); _ = Darwin.unlink(path) }
        let bytes = Data("original".utf8)
        XCTAssertEqual(bytes.withUnsafeBytes { Darwin.write(original, $0.baseAddress, $0.count) }, bytes.count)
        XCTAssertEqual(lseek(original, 0, SEEK_SET), 0)
        let submission = try inputSubmission(original)
        defer { submission.input.close(); submission.caller.close() }
        let first = try submission.input.capture(streamBinding: Data(repeating: 0xa6, count: 16))
        XCTAssertEqual(Darwin.unlink(path), 0)
        let replacement = Darwin.open(path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0o600)
        guard replacement >= 0 else { throw RetainedCommandInputError.system(errno) }
        defer { _ = Darwin.close(replacement) }
        var fresh = stat()
        XCTAssertEqual(fstat(replacement, &fresh), 0)
        XCTAssertNotEqual(first.identity?.inode, fresh.st_ino)
        let observed = try submission.input.capture(streamBinding: Data(repeating: 0xa6, count: 16))
        XCTAssertEqual(observed.identity, first.identity)
        try submission.input.withBorrowedDescriptor { fd in
            var actual = [UInt8](repeating: 0, count: bytes.count)
            XCTAssertEqual(Darwin.read(fd, &actual, actual.count), actual.count)
            XCTAssertEqual(Data(actual), bytes)
        }
    }

    private final class Peer {
        let directory: URL
        let expression: String
        private var child: pid_t = -1
        private var control: Int32 = -1
        var pid: pid_t { child }

        init(endpoint: Endpoint) throws {
            directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
            do {
                let binary = directory.appendingPathComponent("peer")
                let source = try XCTUnwrap(Bundle.module.url(forResource: "MachCommandCallerPeer", withExtension: "c", subdirectory: "Fixtures"))
                try Self.run("/usr/bin/xcrun", ["clang", "-arch", "arm64", "-mmacosx-version-min=26.0",
                    "-Wall", "-Wextra", "-Werror", source.path, "-o", binary.path])
                try Self.run("/usr/bin/codesign", ["--force", "--sign", "-", "--options", "runtime",
                    "--identifier", "dev.remozio.command-caller.fixture", binary.path])
                var code: SecStaticCode?, information: CFDictionary?
                guard SecStaticCodeCreateWithPath(binary as CFURL, [], &code) == errSecSuccess,
                      let code, SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
                      let values = information as? [String: Any], let hash = values[kSecCodeInfoUnique as String] as? Data else {
                    throw MachCommandCallerError.unavailable
                }
                expression = "identifier \"dev.remozio.command-caller.fixture\" and cdhash H\"" +
                    hash.map { String(format: "%02x", $0) }.joined() + "\""
                var pipeFDs: [Int32] = [-1, -1]
                guard pipe(&pipeFDs) == 0 else { throw MachCommandCallerError.unavailable }
                defer { Darwin.close(pipeFDs[0]); if control < 0 { Darwin.close(pipeFDs[1]) } }
                var attributes: posix_spawnattr_t?, actions: posix_spawn_file_actions_t?
                guard posix_spawnattr_init(&attributes) == 0 else { throw MachCommandCallerError.unavailable }
                defer { posix_spawnattr_destroy(&attributes) }
                guard posix_spawn_file_actions_init(&actions) == 0 else { throw MachCommandCallerError.unavailable }
                defer { posix_spawn_file_actions_destroy(&actions) }
                guard posix_spawnattr_setspecialport_np(&attributes, endpoint.port, TASK_BOOTSTRAP_PORT) == 0,
                      posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_CLOEXEC_DEFAULT)) == 0,
                      posix_spawn_file_actions_adddup2(&actions, pipeFDs[0], STDIN_FILENO) == 0,
                      posix_spawn_file_actions_addclose(&actions, pipeFDs[1]) == 0,
                      posix_spawn_file_actions_addclose(&actions, pipeFDs[0]) == 0 else {
                    throw MachCommandCallerError.unavailable
                }
                let words = [strdup(binary.path), strdup("first")]
                defer { words.forEach { free($0) } }
                var arguments = words + [nil], environment: [UnsafeMutablePointer<CChar>?] = [nil]
                let result = arguments.withUnsafeMutableBufferPointer { arguments in
                    environment.withUnsafeMutableBufferPointer { environment in
                        posix_spawn(&child, binary.path, &actions, &attributes, arguments.baseAddress!, environment.baseAddress!)
                    }
                }
                guard result == 0 else { throw MachCommandCallerError.unavailable }
                control = pipeFDs[1]
            } catch {
                try? FileManager.default.removeItem(at: directory)
                throw error
            }
        }

        private static func run(_ program: String, _ arguments: [String]) throws {
            let process = Process(), output = Pipe()
            process.executableURL = URL(fileURLWithPath: program); process.arguments = arguments
            process.environment = ["PATH": "/usr/bin:/bin"]
            if let developer = ProcessInfo.processInfo.environment["DEVELOPER_DIR"] { process.environment?["DEVELOPER_DIR"] = developer }
            process.standardOutput = output; process.standardError = output
            try process.run()
            let deadline = ProcessInfo.processInfo.systemUptime + 60
            while process.isRunning && ProcessInfo.processInfo.systemUptime < deadline { usleep(10000) }
            if process.isRunning { kill(process.processIdentifier, SIGKILL) }
            process.waitUntilExit()
            guard process.terminationStatus == 0 else {
                XCTFail(String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self))
                throw MachCommandCallerError.unavailable
            }
        }

        func advance() throws {
            var byte: UInt8 = 0x78
            guard write(control, &byte, 1) == 1 else { throw MachCommandCallerError.unavailable }
        }

        func stop() throws {
            if control >= 0 { Darwin.close(control); control = -1 }
            let deadline = ProcessInfo.processInfo.systemUptime + 5
            var status: Int32 = 0
            while ProcessInfo.processInfo.systemUptime < deadline {
                let result = waitpid(child, &status, WNOHANG)
                if result == child {
                    child = -1
                    guard status == 0 else { throw MachCommandCallerError.unavailable }
                    return
                }
                if result < 0 && errno != EINTR { throw MachCommandCallerError.unavailable }
                usleep(10000)
            }
            throw MachCommandCallerError.timeout
        }

        deinit {
            if control >= 0 { Darwin.close(control) }
            if child > 0 { kill(child, SIGKILL); while waitpid(child, nil, 0) < 0 && errno == EINTR {} }
            try? FileManager.default.removeItem(at: directory)
        }
    }

    func testRealPeerExecAndExitRetireOldIncarnations() throws {
        let endpoint = try Endpoint(), peer = try Peer(endpoint: endpoint)
        let receiver = try receiver(endpoint, expression: peer.expression)
        let first = try receiver.receive(timeoutMilliseconds: 5000)
        XCTAssertEqual(first.payload, Data("pid=123".utf8))
        XCTAssertEqual(first.caller.requester.pid, UInt32(peer.pid))
        XCTAssertEqual(first.caller.requester.signing.status, .adHoc)
        XCTAssertEqual(first.caller.requester.signing.identifier, "dev.remozio.command-caller.fixture")
        try first.caller.recheck(expression: peer.expression, userID: geteuid(), auditSessionID: nil)
        try peer.advance()
        let second = try receiver.receive(timeoutMilliseconds: 5000)
        XCTAssertEqual(second.payload, Data("next".utf8))
        XCTAssertEqual(second.caller.requester.pid, first.caller.requester.pid)
        XCTAssertNotEqual(second.caller.requester.pidVersion, first.caller.requester.pidVersion)
        XCTAssertThrowsError(try first.caller.recheck(expression: peer.expression, userID: geteuid(), auditSessionID: nil))
        XCTAssertThrowsError(try first.caller.recheck(expression: peer.expression, userID: geteuid(), auditSessionID: nil)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .retired)
        }
        try second.caller.recheck(expression: peer.expression, userID: geteuid(), auditSessionID: nil)
        try peer.stop()
        XCTAssertThrowsError(try second.caller.recheck(expression: peer.expression, userID: geteuid(), auditSessionID: nil))
        XCTAssertThrowsError(try second.caller.recheck(expression: peer.expression, userID: geteuid(), auditSessionID: nil)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .retired)
        }
    }

    func testAncestryUsesActualParentIncarnationAndKeepsItsBoundedPrefix() throws {
        let endpoint = try Endpoint(), peer = try Peer(endpoint: endpoint)
        let submission = try receiver(endpoint, expression: peer.expression).receive(timeoutMilliseconds: 5000)
        defer { submission.caller.close() }
        var selfToken = audit_token_t(), missing = false
        XCTAssertEqual(remozio_pid_audit_token(getpid(), &selfToken, &missing), KERN_SUCCESS)
        let capture = try submission.caller.captureAncestry(expression: peer.expression, userID: geteuid(),
            auditSessionID: nil, maximumEntries: 1)
        XCTAssertEqual(capture.entries.count, 1)
        XCTAssertEqual(capture.entries.first?.pid, UInt32(getpid()))
        XCTAssertEqual(capture.entries.first?.pidVersion, UInt32(bitPattern: audit_token_to_pidversion(selfToken)))
        XCTAssertEqual(capture.entries.first?.uid, geteuid())
        XCTAssertNotNil(capture.entries.first?.executablePath)
        XCTAssertEqual(capture.completeness, .partial)
        XCTAssertEqual(capture.reason, .truncated)
        let disabled = try submission.caller.captureAncestry(expression: peer.expression, userID: geteuid(),
            auditSessionID: nil, maximumEntries: 0)
        XCTAssertEqual(disabled.completeness, .unavailable)
        XCTAssertEqual(disabled.reason, .truncated)
        XCTAssertTrue(disabled.entries.isEmpty)
        try peer.advance()
        let next = try receiver(endpoint, expression: peer.expression).receive(timeoutMilliseconds: 5000)
        defer { next.caller.close() }
        XCTAssertEqual(next.caller.requester.pid, submission.caller.requester.pid)
        XCTAssertNotEqual(next.caller.requester.pidVersion, submission.caller.requester.pidVersion)
        XCTAssertThrowsError(try submission.caller.captureAncestry(expression: peer.expression, userID: geteuid(), auditSessionID: nil))
        XCTAssertThrowsError(try submission.caller.captureAncestry(expression: peer.expression, userID: geteuid(), auditSessionID: nil)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .retired)
        }
        try peer.stop()
        XCTAssertThrowsError(try next.caller.captureAncestry(expression: peer.expression, userID: geteuid(), auditSessionID: nil))
        XCTAssertThrowsError(try next.caller.captureAncestry(expression: peer.expression, userID: geteuid(), auditSessionID: nil)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .retired)
        }
    }

    func testAncestryRechecksCurrentPolicyAndPropagatesCancellation() throws {
        enum Cancelled: Error { case test }
        let endpoint = try Endpoint(), receiver = try receiver(endpoint)
        try endpoint.send(Data([1]))
        let submission = try receiver.receive(timeoutMilliseconds: 1000)
        for limit in [-1, 65] {
            XCTAssertThrowsError(try submission.caller.captureAncestry(expression: selfExpression(), userID: geteuid(),
                auditSessionID: nil, maximumEntries: limit)) { XCTAssertEqual($0 as? MachCommandCallerError, .configuration) }
        }
        XCTAssertThrowsError(try submission.caller.captureAncestry(expression: selfExpression(), userID: geteuid(),
            auditSessionID: nil, checkCancellation: { throw Cancelled.test })) { XCTAssertTrue($0 is Cancelled) }
        try submission.caller.recheck(expression: selfExpression(), userID: geteuid(), auditSessionID: nil)
        XCTAssertThrowsError(try submission.caller.captureAncestry(expression: selfExpression(), userID: geteuid() ^ 1,
            auditSessionID: nil)) { XCTAssertEqual($0 as? MachCommandCallerError, .wrongPeer) }
        XCTAssertThrowsError(try submission.caller.captureAncestry(expression: selfExpression(), userID: geteuid(),
            auditSessionID: nil)) { XCTAssertEqual($0 as? MachCommandCallerError, .retired) }
    }

    private var assemblyLimits: CBORLimits { get throws { try CBORLimits(maxBytes: 8192, maxDepth: 16, maxItems: 1024) } }
    private var assemblyBinding: Data { Data(repeating: 0xb1, count: 16) }
    private var assemblyTarget: CommandTarget {
        .init(uid: geteuid(), gid: getegid(), supplementaryGroups: [getegid()], observedName: nil)
    }
    private var assemblyEnvironment: [CapturedEnvironmentEntry] {
        [.init(name: Data("PATH".utf8), value: Data("/synthetic/baseline".utf8), source: .minimal),
         .init(name: Data("HOME".utf8), value: Data("/synthetic/home".utf8), source: .minimal)]
    }
    private func commandSubmission(executablePath: String = "/usr/bin/true", binding: CapturedSubmission? = nil) throws -> CommandSubmission {
        try CommandSubmission(schemaVersion: 1, executablePath: Data(executablePath.utf8),
            arguments: [Data("custom argv0".utf8), Data(), Data([0xff, 0x0a, 0x22])],
            directoryPath: Data(FileManager.default.temporaryDirectory.path.utf8), requestedTargetUID: geteuid(),
            environmentAdditions: [.init(name: Data("HOME".utf8), value: Data("/synthetic/requested".utf8)),
                .init(name: Data("RAW".utf8), value: Data([0xfe, 0x0a]))],
            ioMode: .pipes, disconnectBehavior: .terminate, unverifiedRationale: "pid=123, caller claim",
            binding: binding ?? .init(id: Data(repeating: 0xb2, count: 16), nonce: Data(repeating: 0xb3, count: 32), callerBinding: assemblyBinding),
            limits: assemblyLimits)
    }
    private func assemble(_ received: ReceivedMachCommandInputSubmission, binding: Data? = nil, schema: UInt64 = 1,
                          submissionSchema: UInt64 = 1, target: CommandTarget? = nil, minimal: [CapturedEnvironmentEntry]? = nil,
                          limits: CBORLimits? = nil, checkCancellation: @Sendable () throws -> Void = {},
                           admissionProfile: CommandHandshakeProfile? = nil) throws -> RetainedCommandCapture {
        try RetainedCommandCapture(received: TestInputInspection(received: received).received, expectedCallerBinding: binding ?? assemblyBinding,
            submissionSchemaVersion: submissionSchema, captureSchemaVersion: schema, expression: selfExpression(),
            userID: geteuid(), auditSessionID: nil, resolvedTarget: target ?? assemblyTarget,
            minimalEnvironment: minimal ?? assemblyEnvironment, streamBinding: Data(repeating: 0xb4, count: 16),
            submissionLimits: assemblyLimits, captureLimits: limits ?? assemblyLimits, maximumAncestryEntries: 1,
            checkCancellation: checkCancellation, admissionProfile: admissionProfile)
    }
    private func expectAssemblyResourcesRetired(_ received: ReceivedMachCommandInputSubmission) throws {
        XCTAssertThrowsError(try received.input.withBorrowedDescriptor { _ in () }) {
            XCTAssertEqual($0 as? RetainedCommandInputError, .closed)
        }
        XCTAssertThrowsError(try received.caller.recheck(expression: selfExpression(), userID: geteuid(), auditSessionID: nil)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .retired)
        }
    }

    func testAssembledCommandPreservesInvocationAndUnreadOriginalInput() throws {
        var pipeFDs: [Int32] = [-1, -1]
        XCTAssertEqual(pipe(&pipeFDs), 0)
        defer { for fd in pipeFDs { _ = Darwin.close(fd) } }
        let queued = Data("unconsumed source".utf8)
        XCTAssertEqual(queued.withUnsafeBytes { Darwin.write(pipeFDs[1], $0.baseAddress, $0.count) }, queued.count)
        let claims = try commandSubmission(), received = try inputSubmission(pipeFDs[0], payload: claims.canonicalBytes)
        let owner = try assemble(received)
        defer { owner.close() }
        let value = owner.capture
        XCTAssertEqual(value.arguments, claims.arguments)
        XCTAssertEqual(value.target, assemblyTarget)
        XCTAssertEqual(value.requester, received.caller.requester)
        XCTAssertEqual(value.requester.pid, UInt32(getpid()))
        XCTAssertEqual(value.unverifiedRationale, claims.unverifiedRationale)
        XCTAssertEqual(value.submission, claims.binding)
        XCTAssertEqual(value.input.kind, .pipe)
        XCTAssertEqual(value.input.streamBinding, Data(repeating: 0xb4, count: 16))
        XCTAssertEqual(value.environment.map(\.name), ["HOME", "PATH", "RAW"].map { Data($0.utf8) })
        XCTAssertEqual(value.environment.map(\.source), [.requested, .minimal, .requested])
        XCTAssertEqual(value.environment.map(\.value), [Data("/synthetic/requested".utf8), Data("/synthetic/baseline".utf8), Data([0xfe, 0x0a])])
        let decoded = try CommandCapture(canonicalBytes: value.canonicalBytes, limits: assemblyLimits)
        XCTAssertEqual(decoded, value)
        try owner.withBorrowedDirectoryDescriptor { fd in
            var directory = stat()
            XCTAssertEqual(fstat(fd, &directory), 0)
            XCTAssertEqual(directory.st_ino, value.directory.identity.inode)
            XCTAssertEqual(UInt64(UInt32(bitPattern: directory.st_dev)), value.directory.identity.device)
        }
        let issued = try IssuedRequestPayload(contract: RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1),
            macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16), requestID: Data(repeating: 3, count: 16),
            challenge: Data(repeating: 4, count: 32), requiredFeatures: [], createdUnixMilliseconds: 10, expiresUnixMilliseconds: 20,
            canonicalCapture: value.canonicalBytes, permittedActions: [.init(choice: .execute, scope: .currentRequest)],
            bodyLimits: assemblyLimits, captureLimits: assemblyLimits)
        let issuedAgain = try IssuedRequestPayload.decode(issued.encode(limits: assemblyLimits), bodyLimits: assemblyLimits,
            captureLimits: assemblyLimits, localCapabilities: ContractCapabilities(contracts: [issued.contract: []]))
        XCTAssertEqual(issuedAgain.canonicalCapture, value.canonicalBytes)
        try owner.recheck(expression: selfExpression(), userID: geteuid(), auditSessionID: nil)
        try owner.withBorrowedInputDescriptor { fd in
            var bytes = [UInt8](repeating: 0, count: queued.count)
            XCTAssertEqual(Darwin.read(fd, &bytes, bytes.count), bytes.count)
            XCTAssertEqual(Data(bytes), queued)
        }
        owner.close(); owner.close()
        XCTAssertThrowsError(try owner.withBorrowedInputDescriptor { _ in () }) {
            XCTAssertEqual($0 as? RetainedCommandCaptureError, .closed)
        }
        XCTAssertThrowsError(try owner.withBorrowedDirectoryDescriptor { _ in () }) {
            XCTAssertEqual($0 as? RetainedCommandCaptureError, .closed)
        }
        try expectAssemblyResourcesRetired(received)
    }

    func testAssemblyRejectsWrongBindingsSchemasTargetsAndInvalidMinimalEnvironment() throws {
        let fd = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(fd, 0)
        defer { _ = Darwin.close(fd) }
        let claims = try commandSubmission()
        let cases: [(ReceivedMachCommandInputSubmission) throws -> RetainedCommandCapture] = [
            { try self.assemble($0, binding: Data(repeating: 0xcc, count: 16)) },
            { try self.assemble($0, binding: Data()) }, { try self.assemble($0, schema: 3) },
            { try self.assemble($0, submissionSchema: 2) },
            { try self.assemble($0, target: .init(uid: self.assemblyTarget.uid ^ 1, gid: 0, supplementaryGroups: [], observedName: nil)) },
            { try self.assemble($0, minimal: self.assemblyEnvironment + self.assemblyEnvironment) },
            { try self.assemble($0, minimal: [.init(name: Data("PATH".utf8), value: Data(), source: .requested)]) },
            { try self.assemble($0, minimal: [.init(name: Data("INVALID=NAME".utf8), value: Data(), source: .minimal)]) }
        ]
        for build in cases {
            let received = try inputSubmission(fd, payload: claims.canonicalBytes)
            XCTAssertThrowsError(try build(received))
            try expectAssemblyResourcesRetired(received)
        }
        let malformed = try inputSubmission(fd, payload: Data([1]))
        XCTAssertThrowsError(try assemble(malformed))
        try expectAssemblyResourcesRetired(malformed)
    }

    func testAssemblyDoesNotDowngradeSocketInputToSchemaOne() throws {
        var pair: [Int32] = [-1, -1]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &pair), 0)
        defer { for fd in pair { _ = Darwin.close(fd) } }
        let claims = try commandSubmission()
        let old = try inputSubmission(pair[0], payload: claims.canonicalBytes)
        XCTAssertThrowsError(try assemble(old)) { XCTAssertEqual($0 as? CommandCaptureError, .enumeration) }
        try expectAssemblyResourcesRetired(old)
        let received = try inputSubmission(pair[0], payload: claims.canonicalBytes)
        let owner = try assemble(received, schema: 2)
        defer { owner.close() }
        XCTAssertEqual(owner.capture.schemaVersion, 2)
        XCTAssertEqual(owner.capture.input.kind, .socket)
        XCTAssertNil(owner.capture.input.observedPath)
        XCTAssertEqual(try CommandCapture(canonicalBytes: owner.capture.canonicalBytes, limits: assemblyLimits, expectedSchemaVersion: 2), owner.capture)
    }

    func testAssemblyOverflowAndCancellationRetireResourcesWithoutReadingInput() throws {
        enum Cancelled: Error { case test }
        let fd = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(fd, 0)
        defer { _ = Darwin.close(fd) }
        let claims = try commandSubmission()
        let oversized = try inputSubmission(fd, payload: claims.canonicalBytes)
        XCTAssertThrowsError(try assemble(oversized, limits: CBORLimits(maxBytes: 20, maxDepth: 16, maxItems: 1024))) {
            XCTAssertEqual($0 as? CBORError, .limitExceeded(.bytes))
        }
        try expectAssemblyResourcesRetired(oversized)
        let cancelled = try inputSubmission(fd, payload: claims.canonicalBytes)
        let checks = OSAllocatedUnfairLock(initialState: 0)
        XCTAssertThrowsError(try assemble(cancelled, checkCancellation: {
            if checks.withLock({ $0 += 1; return $0 }) == 2 { throw Cancelled.test }
        })) {
            XCTAssertTrue($0 is Cancelled)
        }
        try expectAssemblyResourcesRetired(cancelled)
    }

    func testAssemblyRecheckRetiresOwnerAfterExecutableReplacementOrPolicyFailure() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let program = directory.appendingPathComponent("program")
        try Data("#!/bin/sh\nexit 0\n".utf8).write(to: program)
        XCTAssertEqual(chmod(program.path, 0o755), 0)
        let claims = try commandSubmission(executablePath: program.path)
        let fd = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(fd, 0)
        defer { _ = Darwin.close(fd) }
        let received = try inputSubmission(fd, payload: claims.canonicalBytes), owner = try assemble(received)
        let captured = owner.capture
        try FileManager.default.removeItem(at: program)
        try Data("#!/bin/sh\nexit 1\n".utf8).write(to: program)
        XCTAssertEqual(chmod(program.path, 0o755), 0)
        XCTAssertThrowsError(try owner.recheck(expression: selfExpression(), userID: geteuid(), auditSessionID: nil))
        XCTAssertEqual(owner.capture, captured)
        try expectAssemblyResourcesRetired(received)
        XCTAssertThrowsError(try owner.recheck(expression: selfExpression(), userID: geteuid(), auditSessionID: nil)) {
            XCTAssertEqual($0 as? RetainedCommandCaptureError, .closed)
        }
        let nextReceived = try inputSubmission(fd, payload: claims.canonicalBytes), next = try assemble(nextReceived)
        XCTAssertThrowsError(try next.recheck(expression: selfExpression(), userID: geteuid() ^ 1, auditSessionID: nil))
        try expectAssemblyResourcesRetired(nextReceived)
    }

    private final class CommandRequestFixture {
        let root: URL
        let db: JournalDatabase
        let writer: AuditEpochWriter
        private let standaloneRequests: ApprovalRequestCoordinator?
        var requests: ApprovalRequestCoordinator { standaloneRequests! }
        let authority: AuthorityJournal?
        let clock = UUID()
        let biometric = P256.Signing.PrivateKey()
        let decision = P256.Signing.PrivateKey()
        let limits: CBORLimits
        let contract: RequestContract
        var continuity: ContinuityStore?
        init(maximumRequests: Int = 8, checkpointed: Bool = false, owned: Bool = false, ready: Bool = true, commandSchema: UInt64 = 1,
             installReplay: Bool = true, maximumSubmissions: Int = 30) throws {
            limits = try CBORLimits(maxBytes: 8192, maxDepth: 16, maxItems: 1024)
            contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: commandSchema)
            guard let canonical = realpath(FileManager.default.temporaryDirectory.path, nil) else { throw MachCommandCallerError.unavailable }
            defer { free(canonical) }
            root = URL(fileURLWithPath: String(cString: canonical)).appendingPathComponent(UUID().uuidString)
            let directory = root.appendingPathComponent("store")
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            for name in ["writer.lock", "journal.sqlite"] {
                let fd = Darwin.open(directory.appendingPathComponent(name).path, O_CREAT | O_EXCL | O_WRONLY, 0o600)
                guard fd >= 0 else { throw MachCommandCallerError.unavailable }; _ = Darwin.close(fd)
            }
            let mac = Data(repeating: 1, count: 16), account = Data(repeating: 2, count: 16), epoch = Data(repeating: 3, count: 16)
            db = try JournalDatabase(lease: ProtectedJournalLease(anchor: root.path, relativeDirectory: "store", owner: getuid()),
                macID: mac, accountID: account, recordLimits: limits, descriptorLimits: limits, decisionLimits: limits,
                maximumConsumptions: 30, busyMilliseconds: 100, initialize: true, maximumCommandSubmissions: maximumSubmissions)
            if installReplay {
                let policy = try AuthorityCodePolicy(entries: [AuthorityCodeEntry(role: .commandFrontend, teamID: "TEAMID1234",
                    identifier: "dev.remozio.test.frontend", installedGeneration: 1, minimumGeneration: 1,
                    codeDirectoryHash: Data(repeating: 1, count: 20), active: true)])
                try db.write { transaction in
                    _ = try transaction.installCodePolicy(policy, expectedRevision: nil)
                    try transaction.installCommandSubmissionReplay()
                }
            }
            let contract = self.contract
            let capabilities = ContractCapabilities(contracts: [contract: []])
            let revision = try db.write { try $0.configureApprovalAuthority(capabilities: capabilities, allowedContracts: [contract]) }
            let descriptor = try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
                0: .unsigned(1), 1: .bytes(mac), 2: .bytes(account), 3: .bytes(epoch), 4: .unsigned(1),
                5: .unsigned(1), 6: .null, 7: .null, 8: .null,
            ]), limits: limits), limits: limits)
            let writer = try db.write { try $0.createEpoch(descriptor) }
            self.writer = writer
            let enrollment = try StoredApprovalEnrollment(epoch: Data(repeating: 9, count: 16), notificationTag: Data(repeating: 10, count: 32),
                identityPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
                approval: ApprovalEnrollment(phoneID: Data(repeating: 5, count: 16), active: true, capabilities: capabilities, keys: [
                    EnrolledApprovalKey(id: Data(repeating: 6, count: 16), keyClass: .biometric, publicKey: biometric.publicKey.x963Representation),
                    EnrolledApprovalKey(id: Data(repeating: 7, count: 16), keyClass: .decision, publicKey: decision.publicKey.x963Representation),
                ]))
            _ = try db.write { try $0.addApprovalEnrollment(enrollment, expectedTrustRevision: revision,
                eventID: Data(repeating: 30, count: 16), receiptTimeMs: nil, writer: writer, expectedAuditHead: 0) }
            if checkpointed {
                let directory = root.appendingPathComponent("continuity")
                try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
                for name in ["writer.lock", "continuity.sqlite"] {
                    let fd = Darwin.open(directory.appendingPathComponent(name).path, O_CREAT | O_EXCL | O_WRONLY, 0o600)
                    guard fd >= 0 else { throw MachCommandCallerError.unavailable }; _ = Darwin.close(fd)
                }
                let initial = try db.read { try CheckpointedJournal.checkpoint(transaction: $0, epoch: writer.epoch,
                    generation: 1, authorityGeneration: 1) }
                let store = try ContinuityStore(lease: ProtectedContinuityLease(anchor: root.path, relativeDirectory: "continuity", owner: getuid()),
                    macID: mac, accountID: account, initialize: initial)
                continuity = store
                if owned {
                    try db.close(); store.close()
                    let anchor = root.path, limits = self.limits
                    let storage = try AuthorityStorage(openJournal: {
                        try JournalDatabase(lease: ProtectedJournalLease(anchor: anchor, relativeDirectory: "store", owner: getuid()),
                            macID: mac, accountID: account, recordLimits: limits, descriptorLimits: limits, decisionLimits: limits,
                            maximumConsumptions: 30, busyMilliseconds: 100, initialize: false, maximumCommandSubmissions: maximumSubmissions)
                    }, openContinuity: { _ in
                        try ContinuityStore(lease: ProtectedContinuityLease(anchor: anchor, relativeDirectory: "continuity", owner: getuid()),
                            macID: mac, accountID: account, initialize: nil)
                    })
                    let authority = try AuthorityJournal(storage: storage)
                    if ready { try authority.prepareRequests(clockEpoch: clock, maximumPayloadBytes: 16384) }
                    self.authority = authority
                    standaloneRequests = nil
                } else {
                    authority = nil
                    standaloneRequests = try ApprovalRequestCoordinator(database: db, continuity: store, writer: writer, clockEpoch: clock,
                        maximumRequests: maximumRequests, maximumRetainedBytes: 65536, requestLimits: limits, captureLimits: limits,
                        decisionLimits: limits, signingLimits: limits, auditLimits: limits)
                }
            } else {
                if owned {
                    try db.close()
                    let ownedDatabase = try JournalDatabase(lease: ProtectedJournalLease(anchor: root.path, relativeDirectory: "store", owner: getuid()),
                        macID: mac, accountID: account, recordLimits: limits, descriptorLimits: limits, decisionLimits: limits,
                        maximumConsumptions: 30, busyMilliseconds: 100, initialize: false, maximumCommandSubmissions: maximumSubmissions)
                    let ownedDescriptor = try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
                        0: .unsigned(1), 1: .bytes(mac), 2: .bytes(account), 3: .bytes(Data(repeating: 4, count: 16)),
                        4: .unsigned(1), 5: .unsigned(1), 6: .null, 7: .null, 8: .null,
                    ]), limits: limits), limits: limits)
                    if ready {
                        let ownedWriter = try ownedDatabase.write { try $0.createEpoch(ownedDescriptor) }
                        let requests = try ApprovalRequestCoordinator(database: ownedDatabase, writer: ownedWriter, clockEpoch: clock,
                            maximumRequests: maximumRequests, maximumRetainedBytes: 65536, requestLimits: limits, captureLimits: limits,
                            decisionLimits: limits, signingLimits: limits, auditLimits: limits)
                        authority = AuthorityJournal(requests: requests)
                    } else {
                        authority = AuthorityJournal(database: ownedDatabase)
                    }
                    standaloneRequests = nil
                } else {
                    authority = nil
                    standaloneRequests = try ApprovalRequestCoordinator(database: db, writer: writer, clockEpoch: clock,
                        maximumRequests: maximumRequests, maximumRetainedBytes: 65536, requestLimits: limits, captureLimits: limits,
                        decisionLimits: limits, signingLimits: limits, auditLimits: limits)
                }
            }
        }
        deinit { try? authority?.close(); try? db.close(); continuity?.close(); try? FileManager.default.removeItem(at: root) }
        func now(_ milliseconds: UInt64 = 110) -> AuthorityMoment { .init(epoch: clock, milliseconds: milliseconds) }
        func draft(_ command: RetainedCommandCapture, capture: Data? = nil, contract: RequestContract? = nil,
                   actions: [CapturedAction]? = nil) -> ApprovalRequestDraft {
            .init(contract: contract ?? self.contract, requiredFeatures: [], capture: capture ?? command.capture.canonicalBytes,
                actions: actions ?? [.init(choice: .execute, scope: .currentRequest), .init(choice: .decline, scope: .currentRequest)],
                firstObservedAt: now(100), deadlineMilliseconds: 200, createdUnixMilliseconds: 1000, expiresUnixMilliseconds: 1100)
        }
        func consume(_ request: IssuedRequestPayload, decline: Bool = false) throws -> ConsumptionReceipt {
            let body = try DecisionPayload(macID: request.macID, accountID: request.accountID, requestID: request.requestID,
                requestDigest: request.requestDigest(bodyLimits: limits, signingLimits: limits), challenge: request.challenge,
                phoneID: Data(repeating: 5, count: 16), keyID: Data(repeating: decline ? 7 : 6, count: 16),
                action: request.permittedActions.first { $0.choice == (decline ? .decline : .execute) }!).encode(limits: limits)
            let signature = try (decline ? decision : biometric).signature(for: SigningInput.make(wireVersion: 1, messageType: .decision,
                purpose: decline ? .cancellation : .biometricAuthorization, canonicalPayload: body, payloadLimits: limits, inputLimits: limits)).rawRepresentation
            return try requests.consume(canonicalDecision: body, signature: signature, authenticatedPhoneID: Data(repeating: 5, count: 16),
                authenticatedEnrollmentEpoch: Data(repeating: 9, count: 16), now: now(120), receiptTimeMs: nil)
        }
        var auditHead: UInt64 { get throws { try db.read { try XCTUnwrap($0.epoch(writer.epoch)).head } } }
        var auditRecordCount: Int64 {
            get throws {
                var connection: OpaquePointer?, row: OpaquePointer?
                guard sqlite3_open_v2(root.appendingPathComponent("store/journal.sqlite").path, &connection, SQLITE_OPEN_READONLY, nil) == SQLITE_OK,
                      let connection else { throw MachCommandCallerError.unavailable }
                defer { sqlite3_close(connection) }
                guard sqlite3_prepare_v2(connection, "SELECT count(*) FROM audit_records_v1", -1, &row, nil) == SQLITE_OK,
                      let row else { throw MachCommandCallerError.unavailable }
                defer { sqlite3_finalize(row) }
                guard sqlite3_step(row) == SQLITE_ROW else { throw MachCommandCallerError.unavailable }
                return sqlite3_column_int64(row, 0)
            }
        }
        func reservation(_ submissionID: Data) throws -> CommandSubmissionReservation? {
            if let authority { return try authority.read { try $0.commandSubmissionReservation(submissionID: submissionID) } }
            return try db.read { try $0.commandSubmissionReservation(submissionID: submissionID) }
        }
        func sql(_ statement: String, continuity: Bool = false) throws {
            var connection: OpaquePointer?
            guard sqlite3_open(root.appendingPathComponent(continuity ? "continuity/continuity.sqlite" : "store/journal.sqlite").path, &connection) == SQLITE_OK,
                  let connection else { throw MachCommandCallerError.unavailable }
            defer { sqlite3_close(connection) }
            guard sqlite3_exec(connection, statement, nil, nil, nil) == SQLITE_OK else { throw MachCommandCallerError.unavailable }
        }
    }
    private func admitCommand(_ command: RetainedCommandCapture, fixture: CommandRequestFixture,
                              draft: ApprovalRequestDraft? = nil, userID: uid_t? = nil, nowMilliseconds: UInt64 = 110,
                              checkCancellation: () throws -> Void = {}) throws -> IssuedRequestPayload {
        try fixture.requests.admitCommand(command, draft: draft ?? fixture.draft(command), expression: selfExpression(),
            userID: userID ?? geteuid(), auditSessionID: nil, now: { fixture.now(nowMilliseconds) }, receiptTimeMs: nil, checkCancellation: checkCancellation)
    }
    private func requestCommand(binding: CapturedSubmission? = nil, inputFD: Int32? = nil) throws -> (ReceivedMachCommandInputSubmission, RetainedCommandCapture) {
        let fd = inputFD ?? Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        guard fd >= 0 else { throw MachCommandCallerError.unavailable }
        defer { if inputFD == nil { _ = Darwin.close(fd) } }
        let received = try inputSubmission(fd, payload: commandSubmission(binding: binding).canonicalBytes)
        return (received, try assemble(received))
    }

    func testCommandReplayAdmissionCommitsOriginalBindingAndCaptureDigest() throws {
        for checkpointed in [false, true] {
            for owned in [false, true] {
                let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: owned)
                let (_, command) = try requestCommand(), capture = command.capture, head = try fixture.auditRecordCount
                let request = try owned ? admitOwnedCommand(command, fixture: fixture) : admitCommand(command, fixture: fixture)
                let reserved = try XCTUnwrap(fixture.reservation(capture.submission.id))
                XCTAssertEqual(reserved.macID, request.macID); XCTAssertEqual(reserved.accountID, request.accountID)
                XCTAssertEqual(reserved.submission, capture.submission)
                XCTAssertEqual(reserved.captureDigest, Data(SHA256.hash(data: capture.canonicalBytes)))
                XCTAssertEqual(try fixture.auditRecordCount, head + 1)
                if let store = fixture.continuity, !owned {
                    let checkpoint = try store.read()
                    XCTAssertNil(checkpoint.pending)
                    XCTAssertEqual(checkpoint.committed.journalHead, UInt64(head + 1))
                }
                try command.withBorrowedInputDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
            }
        }
    }

    func testCommandReplayAdmissionRejectsIndependentIDAndNonceReuseWithoutRetiringFirstRequest() throws {
        for checkpointed in [false, true] {
            for owned in [false, true] {
                for reusedID in [false, true] {
                    let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: owned)
                    var descriptors: [Int32] = [-1, -1]
                    XCTAssertEqual(pipe(&descriptors), 0)
                    defer { for fd in descriptors { _ = Darwin.close(fd) } }
                    let queued = Data("original unread input".utf8)
                    XCTAssertEqual(queued.withUnsafeBytes { Darwin.write(descriptors[1], $0.baseAddress, $0.count) }, queued.count)
                    let (received, first) = try requestCommand(inputFD: descriptors[0]), binding = first.capture.submission
                    let request = try owned ? admitOwnedCommand(first, fixture: fixture) : admitCommand(first, fixture: fixture)
                    let before = try fixture.reservation(binding.id), head = try fixture.auditRecordCount
                    let replay = CapturedSubmission(id: reusedID ? binding.id : Data(repeating: 0xc2, count: 16),
                        nonce: reusedID ? Data(repeating: 0xc3, count: 32) : binding.nonce, callerBinding: binding.callerBinding)
                    let (incoming, second) = try requestCommand(binding: replay)
                    XCTAssertThrowsError(try owned ? admitOwnedCommand(second, fixture: fixture) : admitCommand(second, fixture: fixture)) {
                        XCTAssertEqual($0 as? CommandSubmissionReplayError, .alreadyReserved)
                    }
                    try expectAssemblyResourcesRetired(incoming)
                    XCTAssertEqual(try fixture.auditRecordCount, head)
                    XCTAssertEqual(try fixture.reservation(binding.id), before)
                    if !reusedID { XCTAssertNil(try fixture.reservation(replay.id)) }
                    let state: ApprovalRequestState
                    if let authority = fixture.authority {
                        state = try authority.withRequests { try $0.state(requestID: request.requestID) }
                    } else { state = try fixture.requests.state(requestID: request.requestID) }
                    XCTAssertEqual(state.phase, .queued)
                    try received.caller.recheck(expression: selfExpression(), userID: geteuid(), auditSessionID: nil)
                    try first.withBorrowedInputDescriptor { fd in
                        var bytes = [UInt8](repeating: 0, count: queued.count)
                        XCTAssertEqual(Darwin.read(fd, &bytes, bytes.count), queued.count)
                        XCTAssertEqual(Data(bytes), queued)
                    }
                }
            }
        }
    }

    func testCommandReplayAdmissionAuditFailureRollsBackReservationAndAllowsFreshCapture() throws {
        for checkpointed in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed), (received, command) = try requestCommand()
            let binding = command.capture.submission, head = try fixture.auditRecordCount
            let boundary = try fixture.continuity?.read()
            try fixture.sql("CREATE TRIGGER reject_replay_admission BEFORE INSERT ON audit_records_v1 BEGIN SELECT RAISE(ABORT,'injected'); END")
            XCTAssertThrowsError(try admitCommand(command, fixture: fixture))
            try expectAssemblyResourcesRetired(received)
            XCTAssertNil(try fixture.reservation(binding.id)); XCTAssertEqual(try fixture.auditRecordCount, head)
            if let boundary { XCTAssertEqual(try fixture.continuity?.read(), boundary) }
            try fixture.sql("DROP TRIGGER reject_replay_admission")
            let (_, fresh) = try requestCommand(binding: binding)
            _ = try admitCommand(fresh, fixture: fixture)
            XCTAssertNotNil(try fixture.reservation(binding.id)); XCTAssertEqual(try fixture.auditRecordCount, head + 1)
        }
    }

    func testCommandReplayAdmissionCapacityDoesNotEvictEvidenceOrCloseEarlierCommand() throws {
        for checkpointed in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed, maximumSubmissions: 1)
            let (_, first) = try requestCommand(), original = first.capture.submission
            let request = try admitCommand(first, fixture: fixture), head = try fixture.auditRecordCount
            let binding = CapturedSubmission(id: Data(repeating: 0xc2, count: 16), nonce: Data(repeating: 0xc3, count: 32),
                callerBinding: original.callerBinding)
            let (incoming, second) = try requestCommand(binding: binding)
            XCTAssertThrowsError(try admitCommand(second, fixture: fixture)) {
                XCTAssertEqual($0 as? CommandSubmissionReplayError, .capacityExceeded)
            }
            try expectAssemblyResourcesRetired(incoming)
            XCTAssertEqual(try fixture.auditRecordCount, head); XCTAssertNil(try fixture.reservation(binding.id))
            XCTAssertNotNil(try fixture.reservation(original.id))
            XCTAssertEqual(try fixture.requests.state(requestID: request.requestID).phase, .queued)
            try first.withBorrowedInputDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
        }
    }

    func testCommandReplayAdmissionRequiresExplicitInstalledStoreBeforePublication() throws {
        for checkpointed in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed, installReplay: false)
            let (received, command) = try requestCommand(), head = try fixture.auditRecordCount
            XCTAssertThrowsError(try admitCommand(command, fixture: fixture)) {
                XCTAssertEqual($0 as? CommandSubmissionReplayError, .unavailable)
            }
            try expectAssemblyResourcesRetired(received)
            XCTAssertEqual(try fixture.auditRecordCount, head)
            XCTAssertNil(try fixture.db.read { try $0.codePolicy() })
        }
    }

    func testCommandReplayAdmissionPendingRetirementNeverFreesIDOrNonce() throws {
        for checkpointed in [false, true] {
            for decline in [false, true] {
                let fixture = try CommandRequestFixture(checkpointed: checkpointed), (_, command) = try requestCommand()
                let binding = command.capture.submission, request = try admitCommand(command, fixture: fixture)
                if decline { _ = try fixture.consume(request, decline: true) }
                else { _ = try fixture.requests.retirePending(requestID: request.requestID, reason: .cancelled, now: fixture.now(120), receiptTimeMs: nil) }
                let reserved = try fixture.reservation(binding.id), head = try fixture.auditRecordCount
                let (received, replay) = try requestCommand(binding: binding)
                XCTAssertThrowsError(try admitCommand(replay, fixture: fixture, nowMilliseconds: 120)) {
                    XCTAssertEqual($0 as? CommandSubmissionReplayError, .alreadyReserved)
                }
                try expectAssemblyResourcesRetired(received)
                XCTAssertEqual(try fixture.reservation(binding.id), reserved); XCTAssertNotNil(reserved)
                XCTAssertEqual(try fixture.auditRecordCount, head)
            }
        }
    }

    func testCommandReplayAdmissionRestartReconcilesAuditAndReservationTogether() throws {
        for stage in 0..<3 {
            let fixture = try CommandRequestFixture(checkpointed: true), (received, command) = try requestCommand()
            let binding = command.capture.submission, captureDigest = Data(SHA256.hash(data: command.capture.canonicalBytes))
            let originalStore = try XCTUnwrap(fixture.continuity), before = try originalStore.read().committed
            let count = try fixture.auditRecordCount
            var issued: IssuedRequestPayload?
            if stage == 0 {
                issued = try admitCommand(command, fixture: fixture)
            } else {
                let condition = stage == 1 ? "NEW.pending IS NOT NULL" : "NEW.pending IS NULL"
                try fixture.sql("CREATE TRIGGER reject_admission_checkpoint BEFORE UPDATE ON continuity_v1 WHEN \(condition) BEGIN SELECT RAISE(ABORT,'injected'); END", continuity: true)
                XCTAssertThrowsError(try issued = admitCommand(command, fixture: fixture))
                XCTAssertNil(issued)
                try expectAssemblyResourcesRetired(received)
                try fixture.sql("DROP TRIGGER reject_admission_checkpoint", continuity: true)
            }
            let state = try originalStore.read()
            XCTAssertEqual(state.pending != nil, stage == 2)
            fixture.requests.close()
            try expectAssemblyResourcesRetired(received)
            try fixture.db.close(); originalStore.close()
            let journal = try JournalDatabase(lease: ProtectedJournalLease(anchor: fixture.root.path, relativeDirectory: "store", owner: getuid()),
                macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16), recordLimits: fixture.limits,
                descriptorLimits: fixture.limits, decisionLimits: fixture.limits, maximumConsumptions: 30, busyMilliseconds: 100, initialize: false)
            let store = try ContinuityStore(lease: ProtectedContinuityLease(anchor: fixture.root.path, relativeDirectory: "continuity", owner: getuid()),
                macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16), initialize: nil)
            defer { try? journal.close(); store.close() }
            let recovered = try JournalCheckpointRecovery.reconcile(journal: journal, continuity: store)
            if stage == 2 { XCTAssertEqual(recovered, .finalized(try XCTUnwrap(state.pending))) }
            else { XCTAssertEqual(recovered, .unchanged(stage == 0 ? state.committed : before)) }
            let reservation = try journal.read { try $0.commandSubmissionReservation(submissionID: binding.id) }
            XCTAssertEqual(reservation != nil, stage != 1)
            XCTAssertEqual(try fixture.auditRecordCount, count + (stage == 1 ? 0 : 1))
            if let reservation {
                XCTAssertEqual(reservation.submission, binding); XCTAssertEqual(reservation.captureDigest, captureDigest)
                let commits = CheckpointedJournal(journal: journal, continuity: store)
                XCTAssertThrowsError(try commits.write(epoch: fixture.writer.epoch, recoverRejectedBody: true) { try $0.reserveCommandSubmission(reservation) }) {
                    XCTAssertEqual($0 as? CommandSubmissionReplayError, .alreadyReserved)
                }
                XCTAssertFalse(commits.retired)
            }
        }
    }

    func testCommandAdmissionRetainsExactCaptureThroughBiometricConsumptionAndTerminalOutcome() throws {
        let fixture = try CommandRequestFixture(), (received, command) = try requestCommand()
        let request = try admitCommand(command, fixture: fixture)
        XCTAssertEqual(request.canonicalCapture, command.capture.canonicalBytes)
        XCTAssertEqual(try fixture.requests.pendingRequest(requestID: request.requestID, now: fixture.now(), receiptTimeMs: nil).payload, request)
        try command.withBorrowedInputDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
        _ = try fixture.requests.markPresented(requestID: request.requestID, now: fixture.now(), receiptTimeMs: nil)
        let receipt = try fixture.consume(request)
        XCTAssertEqual(receipt.decision.requestDigest, try request.requestDigest(bodyLimits: fixture.limits, signingLimits: fixture.limits))
        XCTAssertEqual(try fixture.requests.consumedRequest(requestID: request.requestID, now: fixture.now(120)).payload.canonicalCapture,
            command.capture.canonicalBytes)
        try received.caller.recheck(expression: selfExpression(), userID: geteuid(), auditSessionID: nil)
        _ = try fixture.requests.recordOutcome(requestID: request.requestID, expectedRevision: 0, event: .beginDispatch,
            now: fixture.now(120), receiptTimeMs: nil)
        try command.withBorrowedDirectoryDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
        _ = try fixture.requests.recordOutcome(requestID: request.requestID, expectedRevision: 1, event: .verifySuccess,
            now: fixture.now(130), receiptTimeMs: nil)
        try expectAssemblyResourcesRetired(received)
        XCTAssertThrowsError(try command.withBorrowedDirectoryDescriptor { _ in () })
        XCTAssertEqual(try fixture.requests.historicalOutcome(requestID: request.requestID)?.phase, .succeeded)
        XCTAssertNotNil(try fixture.reservation(command.capture.submission.id))
    }

    func testCommandDeclineAndPendingRetirementCloseOriginalObjects() throws {
        for reason in [PendingRequestRetirement.cancelled, .deadlineElapsed, .targetTimedOut, .targetDisappeared, .authorityRestart] {
            let fixture = try CommandRequestFixture(), (received, command) = try requestCommand()
            let request = try admitCommand(command, fixture: fixture)
            _ = try fixture.requests.retirePending(requestID: request.requestID, reason: reason,
                now: fixture.now(reason == .deadlineElapsed ? 200 : 120), receiptTimeMs: nil)
            try expectAssemblyResourcesRetired(received)
            XCTAssertThrowsError(try command.withBorrowedDirectoryDescriptor { _ in () })
        }
        let fixture = try CommandRequestFixture(), (received, command) = try requestCommand()
        let request = try admitCommand(command, fixture: fixture)
        _ = try fixture.consume(request, decline: true)
        XCTAssertEqual(try fixture.requests.state(requestID: request.requestID).phase, .declined)
        try expectAssemblyResourcesRetired(received)
    }

    func testCommandExpirySweepAndExplicitCloseRetireResources() throws {
        for sweep in [true, false] {
            let fixture = try CommandRequestFixture(), (received, command) = try requestCommand()
            let request = try admitCommand(command, fixture: fixture)
            if sweep { XCTAssertEqual(try fixture.requests.expirePending(now: fixture.now(200), receiptTimeMs: nil).first?.requestID, request.requestID) }
            else {
                fixture.requests.close(); fixture.requests.close()
                XCTAssertThrowsError(try fixture.requests.state(requestID: request.requestID))
            }
            try expectAssemblyResourcesRetired(received)
            XCTAssertNotNil(try fixture.reservation(command.capture.submission.id))
        }
    }

    func testCommandAdmissionRejectsCaptureActionSchemaAndPeerChangesWithoutAudit() throws {
        enum Cancelled: Error { case test }
        for variant in 0..<6 {
            let fixture = try CommandRequestFixture(), (received, command) = try requestCommand(), head = try fixture.auditHead
            let draft: ApprovalRequestDraft
            switch variant {
            case 0: draft = fixture.draft(command, capture: Data([0xa0]))
            case 1: draft = try fixture.draft(command, contract: RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 2))
            case 2: draft = fixture.draft(command, actions: [.init(choice: .execute, scope: .currentRequest)])
            case 3: draft = fixture.draft(command, actions: [.init(choice: .execute, scope: .currentRequest), .init(choice: .execute, scope: .currentRequest)])
            default: draft = fixture.draft(command)
            }
            XCTAssertThrowsError(try admitCommand(command, fixture: fixture, draft: draft,
                userID: variant == 4 ? geteuid() ^ 1 : nil, checkCancellation: { if variant == 5 { throw Cancelled.test } }))
            XCTAssertEqual(try fixture.auditHead, head)
            XCTAssertNil(try fixture.reservation(command.capture.submission.id))
            try expectAssemblyResourcesRetired(received)
        }
    }

    func testCommandDuplicateOwnershipAndCapacityFailureKeepFirstRequestIntact() throws {
        let fixture = try CommandRequestFixture(maximumRequests: 1), (firstReceived, first) = try requestCommand()
        let request = try admitCommand(first, fixture: fixture), head = try fixture.auditHead
        XCTAssertThrowsError(try admitCommand(first, fixture: fixture)) { XCTAssertEqual($0 as? RetainedCommandCaptureError, .alreadyOwned) }
        XCTAssertEqual(try fixture.auditHead, head)
        try first.withBorrowedInputDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
        let (secondReceived, second) = try requestCommand()
        XCTAssertThrowsError(try admitCommand(second, fixture: fixture)) { XCTAssertEqual($0 as? ApprovalCoordinatorError, .capacityExceeded) }
        try expectAssemblyResourcesRetired(secondReceived)
        XCTAssertEqual(try fixture.requests.state(requestID: request.requestID).phase, .queued)
        try firstReceived.caller.recheck(expression: selfExpression(), userID: geteuid(), auditSessionID: nil)
        fixture.requests.close()
        try expectAssemblyResourcesRetired(firstReceived)
    }

    func testCommandAdmissionSamplesClockAfterRecheckAndRejectsElapsedDeadline() throws {
        let fixture = try CommandRequestFixture(), (received, command) = try requestCommand(), head = try fixture.auditHead
        var rechecked = false, clockSampled = false
        XCTAssertThrowsError(try fixture.requests.admitCommand(command, draft: fixture.draft(command), expression: selfExpression(),
            userID: geteuid(), auditSessionID: nil, now: {
                XCTAssertTrue(rechecked); clockSampled = true
                return fixture.now(200)
            }, receiptTimeMs: nil, checkCancellation: { rechecked = true })) {
            XCTAssertEqual($0 as? ApprovalCoordinatorError, .invalidDraft)
        }
        XCTAssertTrue(clockSampled)
        XCTAssertEqual(try fixture.auditHead, head)
        try expectAssemblyResourcesRetired(received)
    }

    func testCommandCheckpointFailureClosesResourcesBeforeTheFailingOperationReturns() throws {
        for read in [true, false] {
            let fixture = try CommandRequestFixture(checkpointed: true), (received, command) = try requestCommand()
            let request = try admitCommand(command, fixture: fixture)
            try XCTUnwrap(fixture.continuity).close()
            if read { XCTAssertThrowsError(try fixture.requests.state(requestID: request.requestID)) }
            else {
                XCTAssertThrowsError(try fixture.requests.retirePending(requestID: request.requestID, reason: .cancelled,
                    now: fixture.now(120), receiptTimeMs: nil))
            }
            // No additional coordinator call can trigger deferred cleanup before these assertions.
            try expectAssemblyResourcesRetired(received)
            XCTAssertThrowsError(try command.withBorrowedDirectoryDescriptor { _ in () })
        }
    }

    func testCommandFatalJournalOperationsCloseResourcesWithoutAnotherCoordinatorCall() throws {
        for checkpointed in [true, false] {
            for closed in [true, false] {
                for read in [true, false] {
                    let fixture = try CommandRequestFixture(checkpointed: checkpointed), (received, command) = try requestCommand()
                    let request = try admitCommand(command, fixture: fixture)
                    if closed { try fixture.db.close() }
                    else { XCTAssertEqual(chmod(fixture.root.appendingPathComponent("store/journal.sqlite").path, 0o644), 0) }
                    if read { XCTAssertThrowsError(try fixture.requests.state(requestID: request.requestID)) }
                    else {
                        XCTAssertThrowsError(try fixture.requests.retirePending(requestID: request.requestID, reason: .cancelled,
                            now: fixture.now(120), receiptTimeMs: nil))
                    }
                    try expectAssemblyResourcesRetired(received)
                    XCTAssertThrowsError(try command.withBorrowedDirectoryDescriptor { _ in () })
                }
            }
        }
    }

    func testCommandOrdinaryJournalReadCallbackFailurePreservesLiveResources() throws {
        for checkpointed in [true, false] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed), (received, command) = try requestCommand()
            let request = try admitCommand(command, fixture: fixture)
            XCTAssertThrowsError(try fixture.requests.historicalOutcome(requestID: Data())) {
                XCTAssertEqual($0 as? ConsumptionJournalError, .wrongScope)
            }
            try command.withBorrowedInputDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
            try command.withBorrowedDirectoryDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
            try received.caller.recheck(expression: selfExpression(), userID: geteuid(), auditSessionID: nil)
            XCTAssertEqual(try fixture.requests.state(requestID: request.requestID).phase, .queued)
        }
    }

    // Deliberate aliases let invalid callback tests inspect cleanup. Normal journal admission needs no wrapper.
    private struct TestCommandInspection: @unchecked Sendable { let command: RetainedCommandCapture }
    private func admitOwnedCommand(_ command: RetainedCommandCapture, fixture: CommandRequestFixture,
                                   draft: ApprovalRequestDraft? = nil, now: (() throws -> AuthorityMoment)? = nil,
                                   checkCancellation: () throws -> Void = {}) throws -> IssuedRequestPayload {
        let authority = try XCTUnwrap(fixture.authority)
        return try authority.admitCommand(command, draft: draft ?? fixture.draft(command), expression: selfExpression(), userID: geteuid(),
            auditSessionID: nil, now: now ?? { fixture.now() }, receiptTimeMs: nil, checkCancellation: checkCancellation)
    }

    func testJournalCommandTransferRetainsExactRequestUntilCommittedCancellation() throws {
        for checkpointed in [true, false] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true)
            let authority = try XCTUnwrap(fixture.authority), (received, command) = try requestCommand()
            let request = try admitOwnedCommand(command, fixture: fixture)
            XCTAssertEqual(request.canonicalCapture, command.capture.canonicalBytes)
            XCTAssertEqual(try authority.withRequests { try $0.state(requestID: request.requestID).phase }, .queued)
            try command.withBorrowedInputDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
            try command.withBorrowedDirectoryDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
            let now = fixture.now(120)
            _ = try authority.withRequests { try $0.retirePending(requestID: request.requestID, reason: .cancelled, now: now, receiptTimeMs: nil) }
            try expectAssemblyResourcesRetired(received)
            XCTAssertThrowsError(try command.withBorrowedDirectoryDescriptor { _ in () })
        }
    }

    func testJournalCommandPreflightFailureReleasesFirstTransfer() throws {
        for checkpointed in [true, false] {
            for failure in 0..<3 {
                let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true, ready: failure != 0)
                let authority = try XCTUnwrap(fixture.authority), (received, command) = try requestCommand()
                if failure == 1 { try authority.close() }
                if failure == 2 { XCTAssertEqual(chmod(fixture.root.appendingPathComponent("store/journal.sqlite").path, 0o644), 0) }
                XCTAssertThrowsError(try admitOwnedCommand(command, fixture: fixture)) {
                    if failure == 0 { XCTAssertEqual($0 as? ApprovalCoordinatorError, .unavailable) }
                }
                try expectAssemblyResourcesRetired(received)
                XCTAssertThrowsError(try command.withBorrowedDirectoryDescriptor { _ in () })
            }
        }
    }

    func testJournalCommandDuplicateAndCallbackReentryPreserveExistingOwner() throws {
        for checkpointed in [true, false] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true)
            let authority = try XCTUnwrap(fixture.authority), (received, command) = try requestCommand()
            let request = try admitOwnedCommand(command, fixture: fixture)
            XCTAssertThrowsError(try admitOwnedCommand(command, fixture: fixture)) {
                XCTAssertEqual($0 as? RetainedCommandCaptureError, .alreadyOwned)
            }
            let inspection = TestCommandInspection(command: command)
            let draft = fixture.draft(command), expression = try selfExpression(), uid = geteuid(), now = fixture.now()
            try authority.withRequests { _ in
                XCTAssertThrowsError(try authority.admitCommand(inspection.command, draft: draft, expression: expression,
                    userID: uid, auditSessionID: nil, now: { now }, receiptTimeMs: nil)) {
                    XCTAssertEqual($0 as? JournalDatabaseError, .transactionActive)
                }
            }
            try command.withBorrowedInputDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
            try command.withBorrowedDirectoryDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
            try received.caller.recheck(expression: expression, userID: uid, auditSessionID: nil)
            XCTAssertEqual(try authority.withRequests { try $0.state(requestID: request.requestID).phase }, .queued)
        }
    }

    func testJournalCommandTransactionReentryClosesOnlyRejectedTransfer() throws {
        for checkpointed in [true, false] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true)
            let authority = try XCTUnwrap(fixture.authority), (originalReceived, original) = try requestCommand()
            let request = try admitOwnedCommand(original, fixture: fixture)
            let (received, command) = try requestCommand(), inspection = TestCommandInspection(command: command)
            let draft = fixture.draft(command), expression = try selfExpression(), uid = geteuid(), now = fixture.now()
            try authority.read { _ in
                XCTAssertThrowsError(try authority.admitCommand(inspection.command, draft: draft, expression: expression,
                    userID: uid, auditSessionID: nil, now: { now }, receiptTimeMs: nil)) {
                    XCTAssertEqual($0 as? JournalDatabaseError, .transactionActive)
                }
            }
            try expectAssemblyResourcesRetired(received)
            XCTAssertThrowsError(try command.withBorrowedDirectoryDescriptor { _ in () })
            try original.withBorrowedInputDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
            try originalReceived.caller.recheck(expression: expression, userID: uid, auditSessionID: nil)
            XCTAssertEqual(try authority.withRequests { try $0.state(requestID: request.requestID).phase }, .queued)
        }
    }

    func testJournalCommandClockCallbackCannotReenterAndFailureResetsAdmission() throws {
        for checkpointed in [true, false] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true)
            let authority = try XCTUnwrap(fixture.authority), (received, command) = try requestCommand()
            XCTAssertThrowsError(try admitOwnedCommand(command, fixture: fixture, now: {
                try authority.read { _ in () }
                return fixture.now()
            })) { XCTAssertEqual($0 as? JournalDatabaseError, .transactionActive) }
            try expectAssemblyResourcesRetired(received)
            let (nextReceived, next) = try requestCommand()
            _ = try admitOwnedCommand(next, fixture: fixture)
            try next.withBorrowedInputDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
            try nextReceived.caller.recheck(expression: selfExpression(), userID: geteuid(), auditSessionID: nil)
        }
    }

    func testCommandOwnerStorageFailureClosesResourcesBeforeReturning() throws {
        for checkpointed in [true, false] {
            for replaced in [true, false] {
                for operation in checkpointed ? [0, 1, 3] : [0, 1, 2] {
                    let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true)
                    let authority = try XCTUnwrap(fixture.authority), (received, command) = try requestCommand()
                    _ = try admitOwnedCommand(command, fixture: fixture)
                    let path = fixture.root.appendingPathComponent("store/journal.sqlite").path
                    if replaced { XCTAssertEqual(Darwin.rename(path, path + ".removed"), 0) }
                    else { XCTAssertEqual(chmod(path, 0o644), 0) }
                    switch operation {
                    case 0: XCTAssertThrowsError(try authority.read { _ in () })
                    case 1: XCTAssertThrowsError(try authority.withRequests { _ in XCTFail("fatal storage entered callback") })
                    case 2: XCTAssertThrowsError(try authority.write { _ in () })
                    default: XCTAssertThrowsError(try authority.prepareRequests(clockEpoch: UUID(), maximumPayloadBytes: 16384))
                    }
                    try expectAssemblyResourcesRetired(received)
                    XCTAssertThrowsError(try command.withBorrowedDirectoryDescriptor { _ in () })
                }
            }
        }
    }

    func testCommandOwnerContinuityFailureClosesResourcesBeforeReturning() throws {
        for failure in 0..<4 {
            let fixture = try CommandRequestFixture(checkpointed: true, owned: true)
            let authority = try XCTUnwrap(fixture.authority), (received, command) = try requestCommand()
            _ = try admitOwnedCommand(command, fixture: fixture)
            let path = fixture.root.appendingPathComponent("continuity/continuity.sqlite").path
            switch failure {
            case 0: XCTAssertEqual(Darwin.rename(path, path + ".removed"), 0)
            case 1: XCTAssertEqual(chmod(path, 0o644), 0)
            case 2: try fixture.sql("UPDATE continuity_v1 SET repair=1 WHERE id=1", continuity: true)
            default: try fixture.sql("UPDATE audit_epochs_v1 SET head=X'0000000000000002'")
            }
            XCTAssertThrowsError(try authority.read { _ in () })
            try expectAssemblyResourcesRetired(received)
            XCTAssertThrowsError(try command.withBorrowedDirectoryDescriptor { _ in () })
        }
    }

    func testCommandOwnerTemporaryStorageContentionPreservesResources() throws {
        for checkpointed in [true, false] {
            for continuity in checkpointed ? [true, false] : [false] {
                let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true)
                let authority = try XCTUnwrap(fixture.authority), (received, command) = try requestCommand()
                let request = try admitOwnedCommand(command, fixture: fixture)
                var connection: OpaquePointer?
                let path = fixture.root.appendingPathComponent(continuity ? "continuity/continuity.sqlite" : "store/journal.sqlite").path
                guard sqlite3_open(path, &connection) == SQLITE_OK, let connection else { throw MachCommandCallerError.unavailable }
                do {
                    defer { sqlite3_exec(connection, "ROLLBACK", nil, nil, nil); sqlite3_close(connection) }
                    XCTAssertEqual(sqlite3_exec(connection, "BEGIN EXCLUSIVE", nil, nil, nil), SQLITE_OK)
                    XCTAssertThrowsError(try authority.read { _ = try $0.approvalTrustSnapshot() })
                }
                try command.withBorrowedInputDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
                try command.withBorrowedDirectoryDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
                try received.caller.recheck(expression: selfExpression(), userID: geteuid(), auditSessionID: nil)
                XCTAssertEqual(try authority.withRequests { try $0.state(requestID: request.requestID).phase }, .queued)
            }
        }
    }

    func testCommandOwnerCallbackRejectionAndReentryPreserveResources() throws {
        for checkpointed in [true, false] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true)
            let authority = try XCTUnwrap(fixture.authority), (received, command) = try requestCommand()
            let request = try admitOwnedCommand(command, fixture: fixture)
            XCTAssertThrowsError(try authority.read { _ in throw JournalDatabaseError.unavailable }) {
                XCTAssertEqual($0 as? JournalDatabaseError, .unavailable)
            }
            if !checkpointed {
                XCTAssertThrowsError(try authority.write { _ in throw JournalDatabaseError.unavailable })
            }
            XCTAssertThrowsError(try authority.withRequests { _ in throw JournalDatabaseError.unavailable })
            try authority.read { _ in
                XCTAssertThrowsError(try authority.withRequests { _ in () }) {
                    XCTAssertEqual($0 as? JournalDatabaseError, .transactionActive)
                }
            }
            try authority.withRequests { _ in
                XCTAssertThrowsError(try authority.read { _ in () }) {
                    XCTAssertEqual($0 as? JournalDatabaseError, .transactionActive)
                }
            }
            try command.withBorrowedInputDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
            try command.withBorrowedDirectoryDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
            try received.caller.recheck(expression: selfExpression(), userID: geteuid(), auditSessionID: nil)
            XCTAssertEqual(try authority.withRequests { try $0.state(requestID: request.requestID).phase }, .queued)
        }
    }

    func testCommandCoordinatorDestructionClosesAnExternallyRetainedCapture() throws {
        let (received, command) = try requestCommand()
        do {
            let fixture = try CommandRequestFixture()
            _ = try admitCommand(command, fixture: fixture)
            try command.withBorrowedInputDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
        }
        try expectAssemblyResourcesRetired(received)
        XCTAssertThrowsError(try command.withBorrowedDirectoryDescriptor { _ in () })
    }

    func testCommandClockFailureClosesOriginalObjects() throws {
        let fixture = try CommandRequestFixture(), (received, command) = try requestCommand()
        let request = try admitCommand(command, fixture: fixture)
        XCTAssertThrowsError(try fixture.requests.markPresented(requestID: request.requestID, now: fixture.now(109), receiptTimeMs: nil)) {
            XCTAssertEqual($0 as? ApprovalCoordinatorError, .invalidClock)
        }
        try expectAssemblyResourcesRetired(received)
    }

    func testCommandAdmissionAuditFailureReleasesObjectsAndRetirementRollbackKeepsThem() throws {
        for variant in 0..<4 {
            let admissionFailure = variant % 2 == 0
            let fixture = try CommandRequestFixture(checkpointed: variant >= 2), (received, command) = try requestCommand()
            let request = try admissionFailure ? nil : admitCommand(command, fixture: fixture)
            let head = try fixture.auditHead
            try fixture.sql("CREATE TRIGGER reject_command_event BEFORE INSERT ON audit_records_v1 BEGIN SELECT RAISE(ABORT,'injected'); END")
            if admissionFailure {
                XCTAssertThrowsError(try admitCommand(command, fixture: fixture))
                try expectAssemblyResourcesRetired(received)
            } else {
                let request = try XCTUnwrap(request)
                XCTAssertThrowsError(try fixture.requests.retirePending(requestID: request.requestID, reason: .cancelled,
                    now: fixture.now(120), receiptTimeMs: nil))
                XCTAssertEqual(try fixture.requests.state(requestID: request.requestID).phase, .queued)
                try command.withBorrowedInputDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
                try command.withBorrowedDirectoryDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
                try fixture.sql("DROP TRIGGER reject_command_event")
                _ = try fixture.requests.retirePending(requestID: request.requestID, reason: .cancelled,
                    now: fixture.now(120), receiptTimeMs: nil)
                try expectAssemblyResourcesRetired(received)
            }
            if admissionFailure { XCTAssertEqual(try fixture.auditHead, head) }
            else { XCTAssertEqual(try fixture.auditHead, head + 1) }
        }
    }

    func testIOCarrierRetainsOriginalOutputPipesAndClosesOnlyImportedDescriptors() throws {
        let endpoint = try Endpoint(), admission = try Endpoint(), terminal = try Endpoint()
        var input: [Int32] = [-1, -1], output: [Int32] = [-1, -1], error: [Int32] = [-1, -1]
        XCTAssertEqual(pipe(&input), 0); XCTAssertEqual(pipe(&output), 0); XCTAssertEqual(pipe(&error), 0)
        defer { for fd in input + output + error { _ = Darwin.close(fd) } }
        XCTAssertEqual(Darwin.write(input[1], "unread", 6), 6)
        let flags = [input[0], output[1], error[1]].map { fcntl($0, F_GETFL) }
        try MachCommandIOWire.send(Data([0xa0]), inputDescriptor: input[0], outputDescriptor: output[1], errorDescriptor: error[1],
            destination: endpoint.port, admissionReply: admission.port, terminalReply: terminal.port,
            maximumPayloadBytes: 8192, timeoutMilliseconds: 1000)
        let received = try receiver(endpoint, maximum: 8192).receiveIOInput(timeoutMilliseconds: 1000)
        let channels = try XCTUnwrap(received.outputs)
        XCTAssertEqual([input[0], output[1], error[1]].map { fcntl($0, F_GETFL) }, flags)
        XCTAssertEqual(received.carrierVersion, 4); XCTAssertEqual(received.payload, Data([0xa0]))
        try channels.recheck()
        try channels.output.withBorrowedDescriptor { XCTAssertEqual(Darwin.write($0, "out", 3), 3) }
        try channels.error.withBorrowedDescriptor { XCTAssertEqual(Darwin.write($0, "err", 3), 3) }
        received.closeIfUnclaimed()
        XCTAssertThrowsError(try channels.recheck())
        var control: [Int32] = [-1, -1]; XCTAssertEqual(pipe(&control), 0)
        defer { for fd in control { _ = Darwin.close(fd) } }
        XCTAssertEqual(Darwin.write(control[1], "out", 3), 3)
        XCTAssertEqual(fcntl(input[0], F_GETFL), flags[0])
        XCTAssertEqual(fcntl(output[1], F_GETFL), fcntl(control[1], F_GETFL))
        XCTAssertEqual(fcntl(error[1], F_GETFL), fcntl(control[1], F_GETFL))
        for (fd, expected) in [(input[0], "unread"), (output[0], "out"), (error[0], "err")] {
            var bytes = [UInt8](repeating: 0, count: expected.utf8.count)
            XCTAssertEqual(Darwin.read(fd, &bytes, bytes.count), bytes.count); XCTAssertEqual(Data(bytes), Data(expected.utf8))
        }
        XCTAssertEqual(try sendReferences(admission.port), 1); XCTAssertEqual(try sendReferences(terminal.port), 1)
    }

    func testIOCarrierRejectsReadOnlyOutputsWithoutSendingOrChangingInput() throws {
        let endpoint = try Endpoint(), admission = try Endpoint(), terminal = try Endpoint()
        let input = Darwin.open("/dev/null", O_RDONLY), output = Darwin.open("/dev/null", O_WRONLY)
        defer { _ = Darwin.close(input); _ = Darwin.close(output) }
        for descriptor in [input, -1] {
            XCTAssertThrowsError(try MachCommandIOWire.send(Data([0xa0]), inputDescriptor: input, outputDescriptor: output,
                errorDescriptor: descriptor, destination: endpoint.port, admissionReply: admission.port,
                terminalReply: terminal.port, maximumPayloadBytes: 8192, timeoutMilliseconds: 1000))
            XCTAssertThrowsError(try receiver(endpoint).receiveNext(timeoutMilliseconds: 10)) {
                XCTAssertEqual($0 as? MachCommandCallerError, .timeout)
            }
        }
        XCTAssertEqual(fcntl(input, F_GETFL) & O_ACCMODE, O_RDONLY)
        XCTAssertEqual(fcntl(output, F_GETFL) & O_ACCMODE, O_WRONLY)
    }

    private func selfExpression() throws -> String {
        var code: SecCode?, information: CFDictionary?
        XCTAssertEqual(SecCodeCopySelf([], &code), errSecSuccess)
        XCTAssertEqual(remozio_copy_dynamic_signing_information(try XCTUnwrap(code), &information), errSecSuccess)
        let values = try XCTUnwrap(information as? [String: Any])
        let hash = try XCTUnwrap(values[kSecCodeInfoUnique as String] as? Data)
        return "cdhash H\"" + hash.map { String(format: "%02x", $0) }.joined() + "\""
    }

    private func receiver(_ endpoint: Endpoint, expression: String? = nil, user: uid_t? = nil,
                          session: au_asid_t? = nil, maximum: Int = 64) throws -> MachCommandCallerReceiver {
        try MachCommandCallerReceiver(receivePort: endpoint.port, expression: expression ?? selfExpression(),
            userID: user ?? geteuid(), auditSessionID: session, maxPayloadBytes: maximum)
    }

    func testKernelIdentityIgnoresPayloadClaimsAndPreservesRawBytes() throws {
        let endpoint = try Endpoint(), receiver = try receiver(endpoint)
        let bytes = Data([0xff, 0x00, 0x31, 0x32, 0x33])
        try endpoint.send(bytes)
        let value = try receiver.receive(timeoutMilliseconds: 1000)
        XCTAssertEqual(value.payload, bytes)
        XCTAssertEqual(value.caller.requester.pid, UInt32(getpid()))
        XCTAssertEqual(value.caller.requester.realUID, getuid())
        XCTAssertEqual(value.caller.requester.effectiveUID, geteuid())
        XCTAssertEqual(value.caller.requester.sessionID, UInt32(getsid(getpid())))
        XCTAssertNil(value.caller.requester.ttyPath)
        try value.caller.recheck(expression: selfExpression(), userID: geteuid(), auditSessionID: value.caller.auditSessionID)
        value.caller.close(); value.caller.close()
        XCTAssertThrowsError(try value.caller.recheck(expression: selfExpression(), userID: geteuid(), auditSessionID: nil)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .retired)
        }
    }

    func testAccountSessionAndCodePolicyRejectBeforeReturningCaller() throws {
        for kind in 0..<3 {
            let endpoint = try Endpoint()
            let wrong = "cdhash H\"" + String(repeating: "0", count: 40) + "\""
            var wrongSession: au_asid_t?
            if kind == 1 {
                let baseline = try receiver(endpoint)
                try endpoint.send(Data([1]))
                wrongSession = try baseline.receive(timeoutMilliseconds: 1000).caller.auditSessionID ^ 1
            }
            let receiver = try receiver(endpoint, expression: kind == 2 ? wrong : nil,
                user: kind == 0 ? geteuid() ^ 1 : nil, session: wrongSession)
            try endpoint.send(Data([1]))
            XCTAssertThrowsError(try receiver.receive(timeoutMilliseconds: 1000))
        }
    }

    func testPublicReleasePolicyRejectsTheTestHost() throws {
        let endpoint = try Endpoint()
        let policy = try XPCPeerPolicy(teamID: "AB12345678", componentIdentifier: "dev.remozio.command",
            approvedCodeDirectoryHashes: [Data(repeating: 0, count: 20)], expectedUserID: geteuid())
        let receiver = try MachCommandCallerReceiver(receivePort: endpoint.port, policy: policy, maxPayloadBytes: 64)
        try endpoint.send(Data([1]))
        XCTAssertThrowsError(try receiver.receive(timeoutMilliseconds: 1000))
    }

    func testChangedDispatchPolicyRetiresTheCapturedCaller() throws {
        for wrongUser in [false, true] {
            let endpoint = try Endpoint(), receiver = try receiver(endpoint)
            try endpoint.send(Data([1]))
            let value = try receiver.receive(timeoutMilliseconds: 1000)
            let expression = wrongUser ? try selfExpression() : "cdhash H\"" + String(repeating: "0", count: 40) + "\""
            XCTAssertThrowsError(try value.caller.recheck(expression: expression, userID: wrongUser ? geteuid() ^ 1 : geteuid(), auditSessionID: nil))
            XCTAssertThrowsError(try value.caller.recheck(expression: selfExpression(), userID: geteuid(), auditSessionID: nil)) {
                XCTAssertEqual($0 as? MachCommandCallerError, .retired)
            }
        }
    }

    func testMalformedVersionLengthPaddingAndIDDoNotPoisonNextReceive() throws {
        let endpoint = try Endpoint(), receiver = try receiver(endpoint)
        try endpoint.send(Data([1]), version: 2)
        XCTAssertThrowsError(try receiver.receive(timeoutMilliseconds: 1000)) { XCTAssertEqual($0 as? MachCommandCallerError, .version) }
        try endpoint.send(Data([1]), claimedLength: 100)
        XCTAssertThrowsError(try receiver.receive(timeoutMilliseconds: 1000))
        try endpoint.send(Data([1]), badPadding: true)
        XCTAssertThrowsError(try receiver.receive(timeoutMilliseconds: 1000))
        try endpoint.send(Data([1]), identifier: 0)
        XCTAssertThrowsError(try receiver.receive(timeoutMilliseconds: 1000))
        try endpoint.send(Data([2]))
        XCTAssertEqual(try receiver.receive(timeoutMilliseconds: 1000).payload, Data([2]))
    }

    func testOversizedPacketFailsWithoutTruncationAndNextPacketWorks() throws {
        let endpoint = try Endpoint(), receiver = try receiver(endpoint, maximum: 4)
        for length in [5, 200] {
            try endpoint.send(Data(repeating: 1, count: length))
            XCTAssertThrowsError(try receiver.receive(timeoutMilliseconds: 1000))
        }
        try endpoint.send(Data([3]))
        XCTAssertEqual(try receiver.receive(timeoutMilliseconds: 1000).payload, Data([3]))
    }

    func testTimeoutAndInvalidConfigurationFail() throws {
        let endpoint = try Endpoint(), receiver = try receiver(endpoint)
        XCTAssertThrowsError(try receiver.receive(timeoutMilliseconds: 1)) { XCTAssertEqual($0 as? MachCommandCallerError, .timeout) }
        XCTAssertThrowsError(try receiver.receive(timeoutMilliseconds: 0))
        for maximum in [0, -1, Int(UInt32.max)] { XCTAssertThrowsError(try self.receiver(endpoint, maximum: maximum)) }
        XCTAssertThrowsError(try MachCommandCallerReceiver(receivePort: 0, expression: selfExpression(),
            userID: geteuid(), auditSessionID: nil, maxPayloadBytes: 64))
    }
    private var handshakeMac: Data { Data(repeating: 0xd1, count: 16) }
    private var handshakeAccount: Data { Data(repeating: 0xd2, count: 16) }
    private func hello(_ endpoint: Endpoint, reply: Endpoint, capabilities: CommandHandshakeCapabilities = .current) throws -> sending MachCommandHello {
        let offer = try CommandHandshakeOffer(nonce: Data(repeating: 0xd3, count: 32), capabilities: capabilities)
        try MachCommandWire.send(offer.canonicalBytes, destination: endpoint.port, replyPort: reply.port,
            identifier: MachCommandCallerReceiver.helloMessageID, timeoutMilliseconds: 1000)
        return try receiver(endpoint, maximum: 8192).receiveHello(timeoutMilliseconds: 1000)
    }
    private func serverHandshake(_ hello: MachCommandHello, expression: String? = nil) throws -> RetainedCommandHandshake {
        try RetainedCommandHandshake(hello: hello, macID: handshakeMac, accountID: handshakeAccount,
            expression: expression ?? selfExpression(), userID: geteuid(), auditSessionID: nil)
    }
    // The worker completes before tests borrow the retained session. This is not a product transfer wrapper.
    private final class HandshakeResult: @unchecked Sendable {
        let completed = DispatchSemaphore(value: 0)
        private let lock = NSLock()
        private var result: Result<RetainedCommandHandshake, Error>?
        func finish(_ result: Result<RetainedCommandHandshake, Error>) { lock.withLock { self.result = result }; completed.signal() }
        func take() throws -> RetainedCommandHandshake {
            guard completed.wait(timeout: .now() + 6) == .success else { throw MachCommandCallerError.timeout }
            return try lock.withLock { try XCTUnwrap(result).get() }
        }
    }

    func testRealMachHandshakeAuthenticatesBothSendersAndCreatesFreshBindings() throws {
        var previous: Data?
        for _ in 0..<2 {
            let endpoint = try Endpoint(), port = endpoint.port, expression = try selfExpression(), uid = geteuid()
            let mac = handshakeMac, account = handshakeAccount, result = HandshakeResult()
            DispatchQueue.global().async {
                result.finish(Result {
                    let receiver = try MachCommandCallerReceiver(receivePort: port, expression: expression,
                        userID: uid, auditSessionID: nil, maxPayloadBytes: 4096)
                    let hello = try receiver.receiveHello(timeoutMilliseconds: 5000)
                    return try RetainedCommandHandshake(hello: hello, macID: mac, accountID: account,
                        expression: expression, userID: uid, auditSessionID: nil)
                })
            }
            let client = try MachCommandHandshakeClient.negotiate(authorityPort: port, expression: expression, userID: uid,
                auditSessionID: nil, macID: mac, accountID: account)
            let server = try result.take()
            defer { client.close(); server.close() }
            XCTAssertEqual(client.profile, server.profile)
            XCTAssertEqual(server.profile.wireVersion, 1)
            XCTAssertEqual(server.profile.submissionSchemaVersion, 1)
            XCTAssertEqual(server.profile.inputCarrierVersion, 2)
            XCTAssertEqual(server.profile.callerBinding.count, 16)
            if let previous { XCTAssertNotEqual(previous, server.profile.callerBinding) }
            previous = server.profile.callerBinding
        }
    }

    func testHandshakeReplyRightOwnershipClosesOnDiscardAndNegotiationFailure() throws {
        let endpoint = try Endpoint(), reply = try Endpoint(), baseline = try sendReferences(reply.port)
        var packet: MachCommandHello? = try hello(endpoint, reply: reply)
        XCTAssertEqual(try sendReferences(reply.port), baseline + 1)
        packet?.close(); packet = nil
        XCTAssertEqual(try sendReferences(reply.port), baseline)
        let invalid = try hello(endpoint, reply: reply)
        XCTAssertThrowsError(try RetainedCommandHandshake(hello: invalid, macID: Data(), accountID: handshakeAccount,
            expression: selfExpression(), userID: geteuid(), auditSessionID: nil))
        XCTAssertEqual(try sendReferences(reply.port), baseline)
        XCTAssertThrowsError(try invalid.take()) { XCTAssertEqual($0 as? MachCommandHandshakeError, .retired) }
    }

    func testHelloRejectsWrongSenderMalformedDescriptorsCarrierAndOversizeBeforeImport() throws {
        let endpoint = try Endpoint(), reply = try Endpoint(), baseline = try sendReferences(reply.port)
        let offer = try CommandHandshakeOffer(nonce: Data(repeating: 0xd3, count: 32)).canonicalBytes
        let rejected = try receiver(endpoint, user: geteuid() ^ 1, maximum: 16384)
        try MachCommandWire.send(offer, destination: endpoint.port, replyPort: reply.port,
            identifier: MachCommandCallerReceiver.helloMessageID, timeoutMilliseconds: 1000)
        XCTAssertThrowsError(try rejected.receiveHello(timeoutMilliseconds: 1000)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .wrongPeer)
        }
        XCTAssertEqual(try sendReferences(reply.port), baseline)
        let receiver = try receiver(endpoint, maximum: 16384)
        for variant in 0..<3 {
            try endpoint.sendInput(variant == 2 ? Data(count: 4097) : offer, fileport: reply.port,
                version: variant == 0 ? 2 : 1, descriptorCount: variant == 1 ? 2 : 1,
                identifier: MachCommandCallerReceiver.helloMessageID)
            XCTAssertThrowsError(try receiver.receiveHello(timeoutMilliseconds: 1000))
            XCTAssertEqual(try sendReferences(reply.port), baseline)
        }
        let valid = try hello(endpoint, reply: reply)
        valid.close()
        XCTAssertEqual(try sendReferences(reply.port), baseline)
    }

    func testHelloAndCommandInputCarriersCannotSubstituteForEachOther() throws {
        let endpoint = try Endpoint(), reply = try Endpoint(), receiver = try receiver(endpoint)
        let offer = try CommandHandshakeOffer(nonce: Data(repeating: 0xd3, count: 32)).canonicalBytes
        try MachCommandWire.send(offer, destination: endpoint.port, replyPort: reply.port,
            identifier: MachCommandCallerReceiver.helloMessageID, timeoutMilliseconds: 1000)
        XCTAssertThrowsError(try receiver.receiveInput(timeoutMilliseconds: 1000))
        try endpoint.sendInput(offer, fileport: reply.port)
        XCTAssertThrowsError(try receiver.receiveHello(timeoutMilliseconds: 1000))
    }

    func testUnsupportedHandshakeReturnsAuthenticatedIncompatibilityWithoutDowngrade() throws {
        let endpoint = try Endpoint(), reply = try Endpoint()
        let old = try CommandHandshakeCapabilities(wireVersions: [1], submissionSchemaVersions: [1], inputCarrierVersions: [1])
        let packet = try hello(endpoint, reply: reply, capabilities: old)
        XCTAssertThrowsError(try serverHandshake(packet)) { XCTAssertEqual($0 as? MachCommandHandshakeError, .incompatible) }
        let response = try receiver(reply).receiveHelloReply(timeoutMilliseconds: 1000)
        defer { response.caller.close() }
        let offer = try CommandHandshakeOffer(nonce: Data(repeating: 0xd3, count: 32), capabilities: old)
        XCTAssertThrowsError(try CommandHandshakeReply.decode(response.payload, offer: offer, macID: handshakeMac, accountID: handshakeAccount)) {
            XCTAssertEqual($0 as? MachCommandHandshakeError, .incompatible)
        }
    }

    func testHandshakeSendTimeoutReleasesPseudoReceivedRightsAndPreservesBorrowedPorts() throws {
        let endpoint = try Endpoint(), reply = try Endpoint()
        var status = mach_port_status_t(), count = mach_msg_type_number_t(MemoryLayout<mach_port_status_t>.size / MemoryLayout<integer_t>.size)
        XCTAssertEqual(withUnsafeMutablePointer(to: &status) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                mach_port_get_attributes(mach_task_self_, endpoint.port, Int32(MACH_PORT_RECEIVE_STATUS), $0, &count)
            }
        }, KERN_SUCCESS)
        for _ in 0..<status.mps_qlimit { try endpoint.send(Data([1])) }
        let endpointBaseline = try sendReferences(endpoint.port), replyBaseline = try sendReferences(reply.port)
        for _ in 0..<3 {
            XCTAssertThrowsError(try MachCommandWire.send(Data([1]), destination: endpoint.port, replyPort: reply.port,
                identifier: MachCommandCallerReceiver.helloMessageID, timeoutMilliseconds: 10)) {
                XCTAssertEqual($0 as? MachCommandCallerError, .mach(MACH_SEND_TIMED_OUT))
            }
            XCTAssertEqual(try sendReferences(endpoint.port), endpointBaseline)
            XCTAssertEqual(try sendReferences(reply.port), replyBaseline)
        }
        let receiver = try receiver(endpoint)
        for _ in 0..<status.mps_qlimit { let value = try receiver.receive(timeoutMilliseconds: 1000); value.caller.close() }
        XCTAssertEqual(try sendReferences(endpoint.port), endpointBaseline)
    }

    func testClientTimeoutAndCancellationRetainBorrowedAuthorityRight() throws {
        let endpoint = try Endpoint(), baseline = try sendReferences(endpoint.port)
        XCTAssertThrowsError(try MachCommandHandshakeClient.negotiate(authorityPort: endpoint.port, expression: selfExpression(),
            userID: geteuid(), auditSessionID: nil, macID: handshakeMac, accountID: handshakeAccount, timeoutMilliseconds: 10))
        XCTAssertEqual(try sendReferences(endpoint.port), baseline)
        XCTAssertThrowsError(try MachCommandHandshakeClient.negotiate(authorityPort: endpoint.port, expression: selfExpression(),
            userID: geteuid(), auditSessionID: nil, macID: handshakeMac, accountID: handshakeAccount,
            checkCancellation: { throw MachCommandHandshakeError.retired }))
        XCTAssertEqual(try sendReferences(endpoint.port), baseline)
    }

    func testNegotiatedSenderAssemblesExactCaptureAndRejectsOtherBindingWithoutReadingInput() throws {
        let endpoint = try Endpoint(), reply = try Endpoint(), session = try serverHandshake(hello(endpoint, reply: reply))
        defer { session.close() }
        var pipeFDs: [Int32] = [-1, -1]
        XCTAssertEqual(pipe(&pipeFDs), 0)
        defer { for fd in pipeFDs { _ = Darwin.close(fd) } }
        let pending = Data("unread".utf8)
        XCTAssertEqual(pending.withUnsafeBytes { Darwin.write(pipeFDs[1], $0.baseAddress, $0.count) }, pending.count)
        let original = try commandSubmission()
        let claims = try CommandSubmission(schemaVersion: 1, executablePath: original.executablePath, arguments: original.arguments,
            directoryPath: original.directoryPath, requestedTargetUID: original.requestedTargetUID, environmentAdditions: original.environmentAdditions,
            ioMode: original.ioMode, disconnectBehavior: original.disconnectBehavior, unverifiedRationale: original.unverifiedRationale,
            binding: .init(id: original.binding.id, nonce: original.binding.nonce, callerBinding: session.profile.callerBinding), limits: assemblyLimits)
        let received = try inputSubmission(pipeFDs[0], payload: claims.canonicalBytes)
        let command = try session.assemble(received: TestInputInspection(received: received).received, expression: selfExpression(), userID: geteuid(), auditSessionID: nil,
            captureSchemaVersion: 2, resolvedTarget: assemblyTarget, minimalEnvironment: assemblyEnvironment,
            streamBinding: Data(repeating: 0xd4, count: 16), submissionLimits: assemblyLimits, captureLimits: assemblyLimits)
        defer { command.close() }
        XCTAssertEqual(command.capture.submission, claims.binding)
        XCTAssertEqual(command.capture.arguments, claims.arguments)
        try command.withBorrowedInputDescriptor { fd in
            var bytes = [UInt8](repeating: 0, count: pending.count)
            XCTAssertEqual(Darwin.read(fd, &bytes, bytes.count), bytes.count)
            XCTAssertEqual(Data(bytes), pending)
        }
        let wrong = try inputSubmission(pipeFDs[0], payload: original.canonicalBytes)
        XCTAssertThrowsError(try session.assemble(received: TestInputInspection(received: wrong).received, expression: selfExpression(), userID: geteuid(), auditSessionID: nil,
            captureSchemaVersion: 2, resolvedTarget: assemblyTarget, minimalEnvironment: assemblyEnvironment,
            streamBinding: Data(repeating: 0xd4, count: 16), submissionLimits: assemblyLimits, captureLimits: assemblyLimits))
        try expectAssemblyResourcesRetired(wrong)
        try command.withBorrowedDirectoryDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
        session.close()
        let afterClose = try inputSubmission(pipeFDs[0], payload: claims.canonicalBytes)
        XCTAssertThrowsError(try session.assemble(received: TestInputInspection(received: afterClose).received, expression: selfExpression(), userID: geteuid(), auditSessionID: nil,
            captureSchemaVersion: 2, resolvedTarget: assemblyTarget, minimalEnvironment: assemblyEnvironment,
            streamBinding: Data(repeating: 0xd4, count: 16), submissionLimits: assemblyLimits, captureLimits: assemblyLimits)) {
            XCTAssertEqual($0 as? MachCommandHandshakeError, .retired)
        }
        try expectAssemblyResourcesRetired(afterClose)
    }

    func testHandshakeAuditBindingRejectsAnotherRealProcessAndExecIncarnation() throws {
        let endpoint = try Endpoint(), peer = try Peer(endpoint: endpoint)
        let receiver = try receiver(endpoint, expression: peer.expression)
        let first = try receiver.receive(timeoutMilliseconds: 5000)
        defer { first.caller.close() }
        let parentEndpoint = try Endpoint()
        try parentEndpoint.send(Data([1]))
        let parent = try self.receiver(parentEndpoint).receive(timeoutMilliseconds: 1000)
        defer { parent.caller.close() }
        XCTAssertFalse(first.caller.hasSameAuditBinding(as: parent.caller))
        XCTAssertTrue(first.caller.hasSameAuditBinding(as: first.caller))
        try peer.advance()
        let second = try receiver.receive(timeoutMilliseconds: 5000)
        defer { second.caller.close() }
        XCTAssertEqual(first.caller.requester.pid, second.caller.requester.pid)
        XCTAssertNotEqual(first.caller.requester.pidVersion, second.caller.requester.pidVersion)
        XCTAssertFalse(first.caller.hasSameAuditBinding(as: second.caller))
        try peer.stop()
    }

    func testSessionAssemblyRejectsAnotherKernelSenderEvenWithTheCorrectBinding() throws {
        let endpoint = try Endpoint(), peer = try Peer(endpoint: endpoint), reply = try Endpoint()
        let verified = try receiver(endpoint, expression: peer.expression).receive(timeoutMilliseconds: 5000)
        XCTAssertEqual(mach_port_mod_refs(mach_task_self_, reply.port, MACH_PORT_RIGHT_SEND, 1), KERN_SUCCESS)
        let offer = try CommandHandshakeOffer(nonce: Data(repeating: 0xd3, count: 32))
        let hello = MachCommandHello(payload: try offer.canonicalBytes, caller: verified.caller, reply: MachCommandReplyRight(taking: reply.port))
        let session = try serverHandshake(hello, expression: "true")
        defer { session.close() }
        let original = try commandSubmission()
        let claims = try CommandSubmission(schemaVersion: 1, executablePath: original.executablePath, arguments: original.arguments,
            directoryPath: original.directoryPath, requestedTargetUID: original.requestedTargetUID, environmentAdditions: original.environmentAdditions,
            ioMode: original.ioMode, disconnectBehavior: original.disconnectBehavior, unverifiedRationale: original.unverifiedRationale,
            binding: .init(id: original.binding.id, nonce: original.binding.nonce, callerBinding: session.profile.callerBinding), limits: assemblyLimits)
        let fd = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(fd, 0)
        defer { _ = Darwin.close(fd) }
        let incoming = try inputSubmission(fd, payload: claims.canonicalBytes)
        XCTAssertThrowsError(try session.assemble(received: TestInputInspection(received: incoming).received, expression: "true", userID: geteuid(), auditSessionID: nil,
            captureSchemaVersion: 2, resolvedTarget: assemblyTarget, minimalEnvironment: assemblyEnvironment,
            streamBinding: Data(repeating: 0xd4, count: 16), submissionLimits: assemblyLimits, captureLimits: assemblyLimits)) {
            XCTAssertEqual($0 as? MachCommandHandshakeError, .wrongBinding)
        }
        try expectAssemblyResourcesRetired(incoming)
        try peer.advance()
        let replacement = try receiver(endpoint, expression: peer.expression).receive(timeoutMilliseconds: 5000)
        replacement.caller.close()
        try peer.stop()
    }

    func testPublicClientRequiresRootPolicyBeforeSendingAnyHello() throws {
        let endpoint = try Endpoint()
        let policy = try XPCPeerPolicy(teamID: "ABCD123456", componentIdentifier: "dev.remozio.authority",
            approvedCodeDirectoryHashes: [Data(repeating: 1, count: 20)], expectedUserID: geteuid())
        XCTAssertThrowsError(try MachCommandHandshakeClient.negotiate(authorityPort: endpoint.port, authorityPolicy: policy,
            macID: handshakeMac, accountID: handshakeAccount)) {
            XCTAssertEqual($0 as? MachCommandHandshakeError, .invalidConfiguration)
        }
        XCTAssertThrowsError(try receiver(endpoint).receiveHello(timeoutMilliseconds: 10)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .timeout)
        }
    }

    func testClientRejectsActualReplySenderWithWrongCredentialsBeforeDecodingItsPayload() throws {
        let reply = try Endpoint()
        try reply.send(Data([0]), identifier: MachCommandCallerReceiver.helloReplyMessageID)
        XCTAssertThrowsError(try receiver(reply, user: geteuid() ^ 1).receiveHelloReply(timeoutMilliseconds: 1000)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .wrongPeer)
        }
    }


    // Serialized test inspection deliberately retains aliases. Product callers must use the sending APIs.
    private struct TestAttemptInspection: @unchecked Sendable { let attempt: RetainedCommandAdmissionAttempt }
    private struct TestInputInspection: @unchecked Sendable { let received: ReceivedMachCommandInputSubmission }
    // Callbacks execute synchronously in these fixtures. The wrapper permits deliberate reentry and alias inspection.
    private struct TestRegistryInspection: @unchecked Sendable {
        let tests: MachCommandCallerReceiverTests
        let owner: CommandSessionRegistry
        let received: ReceivedMachCommandInputSubmission
    }
    private let registryRevision = UUID()
    private func registry(_ maximum: Int = 4) throws -> CommandSessionRegistry {
        try CommandSessionRegistry(macID: handshakeMac, accountID: handshakeAccount, userID: geteuid(), maximumSessions: maximum)
    }
    private func registryContext(expression: String? = nil, revision: UUID? = nil) throws -> CommandSessionRegistry.Context {
        try .init(expression: expression ?? selfExpression(), roleRevision: revision ?? registryRevision)
    }
    private func registrySession(_ owner: CommandSessionRegistry, context: CommandSessionRegistry.Context? = nil) throws -> CommandHandshakeProfile {
        let endpoint = try Endpoint(), reply = try Endpoint(), context = try context ?? registryContext()
        let profile = try owner.accept(hello: hello(endpoint, reply: reply), context: { context })
        let response = try receiver(reply, maximum: 4096).receiveHelloReply(timeoutMilliseconds: 1000)
        defer { response.caller.close() }
        XCTAssertEqual(try CommandHandshakeReply.decode(response.payload,
            offer: CommandHandshakeOffer(nonce: Data(repeating: 0xd3, count: 32)), macID: handshakeMac, accountID: handshakeAccount), profile)
        return profile
    }
    private func registrySubmission(_ binding: Data, descriptor: Int32? = nil) throws -> ReceivedMachCommandInputSubmission {
        let original = try commandSubmission()
        let claims = try CommandSubmission(schemaVersion: 1, executablePath: original.executablePath, arguments: original.arguments,
            directoryPath: original.directoryPath, requestedTargetUID: original.requestedTargetUID, environmentAdditions: original.environmentAdditions,
            ioMode: original.ioMode, disconnectBehavior: original.disconnectBehavior, unverifiedRationale: original.unverifiedRationale,
            binding: .init(id: original.binding.id, nonce: original.binding.nonce, callerBinding: binding), limits: assemblyLimits)
        let fd = descriptor ?? Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        guard fd >= 0 else { throw RetainedCommandInputError.system(errno) }
        defer { if descriptor == nil { _ = Darwin.close(fd) } }
        return try inputSubmission(fd, payload: claims.canonicalBytes)
    }
    private func registryCapture(_ owner: CommandSessionRegistry, received: ReceivedMachCommandInputSubmission,
                                 context: CommandSessionRegistry.Context? = nil, checkCancellation: @Sendable () throws -> Void = {}) throws -> RetainedCommandCapture {
        let context = try context ?? registryContext()
        return try owner.assemble(received: TestInputInspection(received: received).received, context: { context }, captureSchemaVersion: 2, resolvedTarget: assemblyTarget,
            minimalEnvironment: assemblyEnvironment, streamBinding: Data(repeating: 0xe4, count: 16),
            submissionLimits: assemblyLimits, captureLimits: assemblyLimits, checkCancellation: checkCancellation)
    }

    func testUnifiedReceiverRoutesInterleavedHelloAndOriginalInputOnOneQueue() throws {
        let endpoint = try Endpoint(), reply = try Endpoint(), receiver = try receiver(endpoint, maximum: 8192)
        let fd = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(fd, 0)
        defer { _ = Darwin.close(fd) }
        var fileport: mach_port_t = 0
        XCTAssertEqual(fileport_makeport(fd, &fileport), 0)
        defer { _ = mach_port_deallocate(mach_task_self_, fileport) }
        let offer = try CommandHandshakeOffer(nonce: Data(repeating: 7, count: 32)).canonicalBytes
        for _ in 0..<2 {
            try MachCommandWire.send(offer, destination: endpoint.port, replyPort: reply.port,
                identifier: MachCommandCallerReceiver.helloMessageID, timeoutMilliseconds: 1000)
            try endpoint.sendInput(Data([1, 2]), fileport: fileport)
            guard case .hello(let hello) = try receiver.receiveNext(timeoutMilliseconds: 1000) else { return XCTFail("expected hello") }
            XCTAssertEqual(hello.payload, offer); hello.close()
            guard case .input(let input) = try receiver.receiveNext(timeoutMilliseconds: 1000) else { return XCTFail("expected input") }
            XCTAssertEqual(input.payload, Data([1, 2])); input.closeIfUnclaimed()
        }
    }

    func testUnifiedReceiverRejectsOtherCarriersOversizedControlAndWrongSenderWithoutLeakingRights() throws {
        let endpoint = try Endpoint(), reply = try Endpoint(), baseline = try sendReferences(reply.port)
        let receiver = try receiver(endpoint, maximum: 8192)
        for id in [MachCommandCallerReceiver.messageID, MachCommandCallerReceiver.helloReplyMessageID, mach_msg_id_t(123)] {
            try endpoint.sendInput(Data([1]), fileport: reply.port, version: 1, identifier: id)
            XCTAssertThrowsError(try receiver.receiveNext(timeoutMilliseconds: 1000))
            XCTAssertEqual(try sendReferences(reply.port), baseline)
        }
        try endpoint.sendInput(Data(count: 4097), fileport: reply.port, version: 1, identifier: MachCommandCallerReceiver.helloMessageID)
        XCTAssertThrowsError(try receiver.receiveNext(timeoutMilliseconds: 1000))
        XCTAssertEqual(try sendReferences(reply.port), baseline)
        try endpoint.sendInput(Data([1]), fileport: reply.port, version: 1, descriptorCount: 2, identifier: MachCommandCallerReceiver.helloMessageID)
        XCTAssertThrowsError(try receiver.receiveNext(timeoutMilliseconds: 1000))
        XCTAssertEqual(try sendReferences(reply.port), baseline)
        try endpoint.sendInput(Data([1]), fileport: reply.port, version: 1, identifier: MachCommandCallerReceiver.helloMessageID)
        XCTAssertThrowsError(try self.receiver(endpoint, user: geteuid() ^ 1).receiveNext(timeoutMilliseconds: 1000)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .wrongPeer)
        }
        XCTAssertEqual(try sendReferences(reply.port), baseline)
    }

    func testRegistryRejectsCapacityBeforeAcceptingProfileAndPreservesItsExistingSession() throws {
        let owner = try registry(1), first = try registrySession(owner)
        defer { owner.close() }
        let endpoint = try Endpoint(), reply = try Endpoint(), baseline = try sendReferences(reply.port)
        let packet = try hello(endpoint, reply: reply), context = try registryContext()
        XCTAssertThrowsError(try owner.accept(hello: packet, context: { context })) {
            XCTAssertEqual($0 as? CommandSessionRegistryError, .capacity)
        }
        XCTAssertEqual(owner.retainedSessionCount, 1)
        XCTAssertEqual(try sendReferences(reply.port), baseline)
        XCTAssertThrowsError(try receiver(reply).receiveHelloReply(timeoutMilliseconds: 10)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .timeout)
        }
        let capture = try registryCapture(owner, received: registrySubmission(first.callerBinding))
        capture.close()
    }

    func testRegistryCloseAndRetirementLeaveIndependentCaptureAndUnreadPipeIntact() throws {
        let owner = try registry(), profile = try registrySession(owner)
        var fds: [Int32] = [-1, -1]
        XCTAssertEqual(pipe(&fds), 0)
        defer { fds.forEach { _ = Darwin.close($0) } }
        let bytes = Data("still-unread".utf8)
        XCTAssertEqual(bytes.withUnsafeBytes { Darwin.write(fds[1], $0.baseAddress, $0.count) }, bytes.count)
        let received = try registrySubmission(profile.callerBinding, descriptor: fds[0])
        let capture = try registryCapture(owner, received: received)
        defer { capture.close() }
        try owner.retire(callerBinding: profile.callerBinding)
        XCTAssertEqual(owner.retainedSessionCount, 0)
        let rejected = try registrySubmission(profile.callerBinding)
        XCTAssertThrowsError(try registryCapture(owner, received: rejected)) {
            XCTAssertEqual($0 as? CommandSessionRegistryError, .unknownSession)
        }
        try expectAssemblyResourcesRetired(rejected)
        owner.close(); owner.close()
        XCTAssertThrowsError(try registryCapture(owner, received: received))
        try capture.withBorrowedDirectoryDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
        try received.caller.recheck(expression: selfExpression(), userID: geteuid(), auditSessionID: nil)
        try capture.withBorrowedInputDescriptor { fd in
            var actual = [UInt8](repeating: 0, count: bytes.count)
            XCTAssertEqual(Darwin.read(fd, &actual, actual.count), actual.count)
            XCTAssertEqual(Data(actual), bytes)
        }
        let restarted = try registry()
        defer { restarted.close() }
        let stale = try registrySubmission(profile.callerBinding)
        XCTAssertThrowsError(try registryCapture(restarted, received: stale))
        try expectAssemblyResourcesRetired(stale)
    }

    func testRegistryRepeatedInputAndHelloTransfersCannotCloseEarlierOwners() throws {
        let owner = try registry(), endpoint = try Endpoint(), reply = try Endpoint(), packet = try hello(endpoint, reply: reply)
        defer { owner.close() }
        let context = try registryContext(), profile = try owner.accept(hello: packet, context: { context })
        XCTAssertThrowsError(try owner.accept(hello: packet, context: { context })) {
            XCTAssertEqual($0 as? MachCommandHandshakeError, .retired)
        }
        let received = try registrySubmission(profile.callerBinding), alias = received
        let capture = try registryCapture(owner, received: received)
        defer { capture.close() }
        XCTAssertThrowsError(try registryCapture(owner, received: alias)) {
            XCTAssertEqual($0 as? RetainedCommandCaptureError, .alreadyOwned)
        }
        try capture.withBorrowedInputDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
        try capture.withBorrowedDirectoryDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
        XCTAssertEqual(owner.retainedSessionCount, 1)
    }

    func testRegistryRoleRevisionOrCurrentRequirementChangeRetiresSessionsWithoutClosingCaptures() throws {
        for revisionChanged in [true, false] {
            let owner = try registry(), profile = try registrySession(owner)
            defer { owner.close() }
            let capture = try registryCapture(owner, received: registrySubmission(profile.callerBinding))
            defer { capture.close() }
            let changed = try registryContext(expression: revisionChanged ? nil : "false", revision: revisionChanged ? UUID() : nil)
            XCTAssertEqual(try owner.prune(context: { changed }), 1)
            XCTAssertEqual(owner.retainedSessionCount, 0)
            let stale = try registrySubmission(profile.callerBinding)
            XCTAssertThrowsError(try registryCapture(owner, received: stale, context: changed))
            try expectAssemblyResourcesRetired(stale)
            try capture.withBorrowedInputDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
            try capture.withBorrowedDirectoryDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
        }
    }

    func testRegistryReentryClosesOnlyASeparateIncomingTransferAndCloseCancelsAssembly() throws {
        let owner = try registry(), profile = try registrySession(owner), original = try registrySubmission(profile.callerBinding)
        defer { owner.close() }
        let inspection = TestRegistryInspection(tests: self, owner: owner, received: original)
        let capture = try registryCapture(owner, received: original, checkCancellation: {
            XCTAssertThrowsError(try inspection.tests.registryCapture(inspection.owner, received: inspection.received)) {
                XCTAssertEqual($0 as? CommandSessionRegistryError, .operationActive)
            }
            let other = try inspection.tests.registrySubmission(profile.callerBinding)
            XCTAssertThrowsError(try inspection.tests.registryCapture(inspection.owner, received: other)) {
                XCTAssertEqual($0 as? CommandSessionRegistryError, .operationActive)
            }
            try inspection.tests.expectAssemblyResourcesRetired(other)
        })
        defer { capture.close() }
        let incoming = try registrySubmission(profile.callerBinding)
        XCTAssertThrowsError(try registryCapture(owner, received: incoming, checkCancellation: { inspection.owner.close() })) {
            XCTAssertEqual($0 as? CommandSessionRegistryError, .closed)
        }
        try expectAssemblyResourcesRetired(incoming)
        XCTAssertEqual(owner.retainedSessionCount, 0)
        try capture.withBorrowedInputDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
    }

    func testRegistryPrunesExecChangedAndExitedRealPeersAndKeepsAnotherSession() throws {
        let endpoint = try Endpoint(), peer = try Peer(endpoint: endpoint), owner = try registry()
        defer { owner.close() }
        let context = try registryContext(expression: "true"), parent = try registrySession(owner, context: context)
        let receiver = try receiver(endpoint, expression: peer.expression)
        func accept(_ verified: ReceivedMachCommandSubmission) throws -> CommandHandshakeProfile {
            let reply = try Endpoint()
            XCTAssertEqual(mach_port_mod_refs(mach_task_self_, reply.port, MACH_PORT_RIGHT_SEND, 1), KERN_SUCCESS)
            let offer = try CommandHandshakeOffer(nonce: Data(repeating: 0xd3, count: 32))
            let packet = MachCommandHello(payload: try offer.canonicalBytes, caller: verified.caller, reply: MachCommandReplyRight(taking: reply.port))
            return try owner.accept(hello: packet, context: { context })
        }
        let first = try accept(receiver.receive(timeoutMilliseconds: 5000))
        let wrongProcess = try registrySubmission(first.callerBinding)
        XCTAssertThrowsError(try registryCapture(owner, received: wrongProcess, context: context)) {
            XCTAssertEqual($0 as? MachCommandHandshakeError, .wrongBinding)
        }
        try expectAssemblyResourcesRetired(wrongProcess)
        try peer.advance()
        let second = try receiver.receive(timeoutMilliseconds: 5000)
        XCTAssertEqual(try owner.prune(context: { context }), 1)
        XCTAssertEqual(owner.retainedSessionCount, 1)
        _ = try accept(second)
        try peer.stop()
        XCTAssertEqual(try owner.prune(context: { context }), 1)
        let capture = try registryCapture(owner, received: registrySubmission(parent.callerBinding), context: context)
        capture.close()
    }

    func testRegistryRequiresActiveProtectedFrontendPolicyAndValidScope() throws {
        for maximum in [0, -1] { XCTAssertThrowsError(try registry(maximum)) }
        XCTAssertThrowsError(try CommandSessionRegistry(macID: Data(), accountID: handshakeAccount, userID: geteuid(), maximumSessions: 1))
        for disabled in [true, false] {
            let owner = try registry(), profile = try registrySession(owner)
            defer { owner.close() }
            let entry = try AuthorityCodeEntry(role: disabled ? .commandFrontend : .transport, teamID: "ABCD123456",
                identifier: "dev.remozio.command", installedGeneration: 3, minimumGeneration: 2,
                codeDirectoryHash: Data(repeating: 1, count: 20), active: !disabled)
            let snapshot = AuthorityCodePolicySnapshot(revision: UUID(), policy: try .init(entries: [entry]),
                roleRevisions: [entry.role: UUID()])
            XCTAssertThrowsError(try owner.prune(currentCodePolicy: snapshot)) {
                XCTAssertEqual($0 as? CommandSessionRegistryError, .invalidCodePolicy)
            }
            XCTAssertEqual(owner.retainedSessionCount, 0)
            let stale = try registrySubmission(profile.callerBinding)
            XCTAssertThrowsError(try registryCapture(owner, received: stale))
            try expectAssemblyResourcesRetired(stale)
        }
    }

    func testRegistryMalformedAndUnnegotiatedSubmissionsReleaseInputAndKeepLiveSession() throws {
        let owner = try registry(), profile = try registrySession(owner)
        defer { owner.close() }
        let fd = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(fd, 0)
        defer { _ = Darwin.close(fd) }
        for bytes in [Data([0]), try DeterministicCBOR.encode(.map([0: .unsigned(99)]), limits: assemblyLimits)] {
            let received = try inputSubmission(fd, payload: bytes)
            XCTAssertThrowsError(try registryCapture(owner, received: received))
            try expectAssemblyResourcesRetired(received)
            XCTAssertEqual(owner.retainedSessionCount, 1)
        }
        let capture = try registryCapture(owner, received: registrySubmission(profile.callerBinding))
        capture.close()
    }


    func testRegistryDerivesOnlyTheProtectedFrontendRoleAndDoesNotUseGlobalRevision() throws {
        let owner = try registry()
        defer { owner.close() }
        let entry = try AuthorityCodeEntry(role: .commandFrontend, teamID: "ABCD123456", identifier: "dev.remozio.command",
            installedGeneration: 3, minimumGeneration: 2, codeDirectoryHash: Data(repeating: 0xab, count: 20), active: true)
        let policy = try AuthorityCodePolicy(entries: [entry]), role = UUID()
        let first = try owner.context(.init(revision: UUID(), policy: policy, roleRevisions: [.commandFrontend: role]))
        let second = try owner.context(.init(revision: UUID(), policy: policy, roleRevisions: [.commandFrontend: role]))
        XCTAssertEqual(first.roleRevision, second.roleRevision)
        XCTAssertEqual(first.expression, second.expression)
        XCTAssertTrue(first.expression.contains("anchor apple generic"))
        XCTAssertTrue(first.expression.contains("identifier \"dev.remozio.command\""))
        XCTAssertTrue(first.expression.contains(String(repeating: "ab", count: 20)))
        XCTAssertThrowsError(try owner.context(.init(revision: UUID(), policy: policy, roleRevisions: [:])))
        let endpoint = try Endpoint(), reply = try Endpoint(), baseline = try sendReferences(reply.port)
        let packet = try hello(endpoint, reply: reply)
        let snapshot = AuthorityCodePolicySnapshot(revision: UUID(), policy: policy, roleRevisions: [.commandFrontend: role])
        // The fixture has ad-hoc code. A protected release policy must reject it before replying.
        do {
            _ = try owner.accept(hello: packet, currentCodePolicy: snapshot)
            XCTFail("release policy accepted ad-hoc fixture")
        } catch {}
        XCTAssertEqual(owner.retainedSessionCount, 0)
        XCTAssertEqual(try sendReferences(reply.port), baseline)
        XCTAssertThrowsError(try receiver(reply).receiveHelloReply(timeoutMilliseconds: 10)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .timeout)
        }
    }

    private func host(_ endpoint: Endpoint, maximum: Int = 4, wait: UInt32 = 20,
                      capabilities: CommandHandshakeCapabilities = .current, mac: Data? = nil, account: Data? = nil,
                      context: (() throws -> CommandSessionRegistry.Context)? = nil) throws -> CommandReceiveHost {
        let initial = try registryContext()
        return try CommandReceiveHost(takingReceiveRight: endpoint.transferReceiveRight(), macID: mac ?? handshakeMac,
            accountID: account ?? handshakeAccount, userID: geteuid(), auditSessionID: nil, maximumSessions: maximum,
            maximumPayloadBytes: 8192, receiveWaitMilliseconds: wait, replyTimeoutMilliseconds: 20, capabilities: capabilities,
            context: { _ in try context?() ?? initial })
    }
    private func hostSession(_ host: CommandReceiveHost, endpoint: Endpoint,
                             capabilities: CommandHandshakeCapabilities = .current) throws -> CommandHandshakeProfile {
        let reply = try Endpoint(), offer = try CommandHandshakeOffer(nonce: Data(repeating: 0xd3, count: 32), capabilities: capabilities)
        try MachCommandWire.send(offer.canonicalBytes, destination: endpoint.port, replyPort: reply.port,
            identifier: MachCommandCallerReceiver.helloMessageID, timeoutMilliseconds: 1000)
        guard case .hello(let profile) = try host.poll(handleInput: { $0.closeIfUnclaimed(); XCTFail("unexpected input") }) else {
            throw MachCommandHandshakeError.invalidMessage
        }
        let response = try receiver(reply, maximum: 4096).receiveHelloReply(timeoutMilliseconds: 1000)
        defer { response.caller.close() }
        XCTAssertEqual(try CommandHandshakeReply.decode(response.payload, offer: offer, macID: profile.macID, accountID: profile.accountID), profile)
        return profile
    }
    private func enqueueHostInput(_ endpoint: Endpoint, binding: Data, descriptor: Int32? = nil) throws {
        let original = try commandSubmission()
        let claim = try CommandSubmission(schemaVersion: 1, executablePath: original.executablePath, arguments: original.arguments,
            directoryPath: original.directoryPath, requestedTargetUID: original.requestedTargetUID,
            environmentAdditions: original.environmentAdditions, ioMode: original.ioMode,
            disconnectBehavior: original.disconnectBehavior, unverifiedRationale: original.unverifiedRationale,
            binding: .init(id: original.binding.id, nonce: original.binding.nonce, callerBinding: binding), limits: assemblyLimits)
        let fd = descriptor ?? Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        guard fd >= 0 else { throw RetainedCommandInputError.system(errno) }
        defer { if descriptor == nil { _ = Darwin.close(fd) } }
        var carried: mach_port_t = 0
        guard fileport_makeport(fd, &carried) == 0 else { throw RetainedCommandInputError.system(errno) }
        defer { _ = mach_port_deallocate(mach_task_self_, carried) }
        try endpoint.sendInput(claim.canonicalBytes, fileport: carried)
    }
    private func hostCapture(_ host: CommandReceiveHost, received: sending ReceivedMachCommandInputSubmission,
                             checkCancellation: @Sendable () throws -> Void = {}) throws -> sending RetainedCommandCapture {
        try host.assemble(received: received, captureSchemaVersion: 2, resolvedTarget: assemblyTarget,
            minimalEnvironment: assemblyEnvironment, streamBinding: Data(repeating: 0xe4, count: 16),
            submissionLimits: assemblyLimits, captureLimits: assemblyLimits, checkCancellation: checkCancellation)
    }
    private func receiveReferences(_ port: mach_port_t) -> mach_port_urefs_t {
        var count: mach_port_urefs_t = 0
        _ = mach_port_get_refs(mach_task_self_, port, MACH_PORT_RIGHT_RECEIVE, &count)
        return count
    }

    func testHostTransfersTypedAttemptToJournalAndKeepsQueueAfterPermanentRefusal() throws {
        let endpoint = try Endpoint(), host = try host(endpoint, capabilities: .admissionResults, mac: Data(repeating: 1, count: 16), account: Data(repeating: 2, count: 16))
        defer { host.close() }
        let profile = try hostSession(host, endpoint: endpoint, capabilities: .admissionResults)
        let fixture = try CommandRequestFixture(checkpointed: true, owned: true), reply = try Endpoint()
        let original = try commandSubmission(binding: .init(id: Data(repeating: 0xb2, count: 16), nonce: Data(repeating: 0xb3, count: 32),
            callerBinding: profile.callerBinding))
        let fd = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(fd, 0); defer { _ = Darwin.close(fd) }
        try MachCommandAdmissionWire.send(original.canonicalBytes, inputDescriptor: fd, destination: endpoint.port,
            replyPort: reply.port, maximumPayloadBytes: 8192, timeoutMilliseconds: 1000)
        XCTAssertEqual(try host.poll { received in
            let attempt = try host.prepareAdmission(received: received, submissionLimits: self.assemblyLimits)
            XCTAssertThrowsError(try self.admitAttempt(attempt, fixture: fixture, resolution: .refuse(.policyRejected)))
        }, .inputHandled)
        XCTAssertEqual(try typedOutcome(reply, submission: original, profile: profile), .notAdmitted(.policyRejected, .never))
        XCTAssertEqual(try host.poll { $0.closeIfUnclaimed(); XCTFail("Unexpected input") }, .idle)
        XCTAssertEqual(host.retainedSessionCount, 1)
    }

    func testHostAdmissionControllerReportsRequestFailureWithoutRetiringHealthyQueue() throws {
        guard geteuid() != 0 else { throw XCTSkip("Normal-user fixture") }
        let endpoint = try Endpoint(), host = try host(endpoint, capabilities: .admissionResults,
            mac: Data(repeating: 1, count: 16), account: Data(repeating: 2, count: 16))
        defer { host.close() }
        let profile = try hostSession(host, endpoint: endpoint, capabilities: .admissionResults)
        let fixture = try CommandRequestFixture(checkpointed: true, owned: true), reply = try Endpoint()
        let original = try commandSubmission(binding: .init(id: Data(repeating: 0xb2, count: 16), nonce: Data(repeating: 0xb3, count: 32),
            callerBinding: profile.callerBinding))
        let fd = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(fd, 0); defer { _ = Darwin.close(fd) }
        try MachCommandAdmissionWire.send(original.canonicalBytes, inputDescriptor: fd, destination: endpoint.port,
            replyPort: reply.port, maximumPayloadBytes: 8192, timeoutMilliseconds: 1000)
        var reported = false
        XCTAssertEqual(try host.pollAdmission(journal: XCTUnwrap(fixture.authority), submissionLimits: assemblyLimits,
            resolve: { _ in XCTFail("Unprivileged fixture must fail first"); return .refuse(.policyRejected) },
            draft: { _ in throw ApprovalCoordinatorError.invalidDraft }, now: { fixture.now() }, receiptTimeMs: nil,
            onResult: { result in
                reported = true
                guard case .failure(let error) = result else { return XCTFail("Unexpected success") }
                XCTAssertEqual(error as? JournalLeaseError, .rootRequired)
            }), .inputHandled)
        XCTAssertTrue(reported)
        XCTAssertEqual(try typedOutcome(reply, submission: original, profile: profile), .uncertain(.storageFailure))
        XCTAssertEqual(try host.poll { $0.closeIfUnclaimed(); XCTFail("Unexpected input") }, .idle)
        XCTAssertEqual(host.retainedSessionCount, 1)
    }

    func testHostOwnsQueueAndTransfersCaptureWithoutReadingOrClosingItsInput() throws {
        let endpoint = try Endpoint(), host = try host(endpoint), profile = try hostSession(host, endpoint: endpoint)
        var pipeFDs: [Int32] = [-1, -1]
        XCTAssertEqual(pipe(&pipeFDs), 0)
        defer { for fd in pipeFDs { _ = Darwin.close(fd) } }
        let bytes = Data("still unread".utf8)
        XCTAssertEqual(bytes.withUnsafeBytes { Darwin.write(pipeFDs[1], $0.baseAddress, $0.count) }, bytes.count)
        try enqueueHostInput(endpoint, binding: profile.callerBinding, descriptor: pipeFDs[0])
        var command: RetainedCommandCapture?
        XCTAssertEqual(try host.poll { command = try self.hostCapture(host, received: $0) }, .inputHandled)
        XCTAssertEqual(command?.capture.submission.callerBinding, profile.callerBinding)
        host.close(); host.close()
        XCTAssertEqual(receiveReferences(endpoint.port), 0)
        try XCTUnwrap(command).withBorrowedInputDescriptor { fd in
            var actual = [UInt8](repeating: 0, count: bytes.count)
            XCTAssertEqual(Darwin.read(fd, &actual, actual.count), bytes.count)
            XCTAssertEqual(Data(actual), bytes)
        }
        command?.close()
    }

    func testHostPrunesOnIdleAndInvalidTrafficWhileKeepingTheReceiveLifetimeUsable() throws {
        let endpoint = try Endpoint()
        var current = try registryContext()
        let host = try host(endpoint, context: { current })
        _ = try hostSession(host, endpoint: endpoint)
        XCTAssertEqual(host.retainedSessionCount, 1)
        current = try registryContext(revision: UUID())
        XCTAssertEqual(try host.poll { $0.closeIfUnclaimed(); XCTFail("unexpected input") }, .idle)
        XCTAssertEqual(host.retainedSessionCount, 0)
        _ = try hostSession(host, endpoint: endpoint)
        current = try registryContext(revision: UUID())
        for _ in 0..<4 {
            try endpoint.send(Data([1]))
            XCTAssertEqual(try host.poll { $0.closeIfUnclaimed(); XCTFail("unexpected input") }, .rejected(.malformed))
            XCTAssertEqual(host.retainedSessionCount, 0)
        }
        _ = try hostSession(host, endpoint: endpoint)
        XCTAssertEqual(host.retainedSessionCount, 1)
        host.close()
    }

    func testHostReloadsAfterReceiptAndClosesImportedReplyWhenPolicyReadFails() throws {
        enum Failure: Error { case policy }
        let endpoint = try Endpoint(), reply = try Endpoint(), baseline = try sendReferences(reply.port)
        let current = try registryContext()
        var reads = 0
        let host = try host(endpoint, context: { reads += 1; if reads == 2 { throw Failure.policy }; return current })
        try MachCommandWire.send(CommandHandshakeOffer(nonce: Data(repeating: 1, count: 32)).canonicalBytes,
            destination: endpoint.port, replyPort: reply.port, identifier: MachCommandCallerReceiver.helloMessageID,
            timeoutMilliseconds: 1000)
        XCTAssertThrowsError(try host.poll { $0.closeIfUnclaimed(); XCTFail("unexpected input") }) {
            XCTAssertEqual($0 as? Failure, .policy)
        }
        XCTAssertEqual(reads, 2)
        XCTAssertEqual(try sendReferences(reply.port), baseline)
        XCTAssertEqual(host.retainedSessionCount, 0)
        XCTAssertEqual(receiveReferences(endpoint.port), 0)
        XCTAssertThrowsError(try host.poll { $0.closeIfUnclaimed() }) {
            XCTAssertEqual($0 as? CommandReceiveHostError, .stopped)
        }
    }

    func testHostPolicyFailureRetiresExistingSessionsAndQueuedRightsWithoutFallback() throws {
        enum Failure: Error { case policy }
        let endpoint = try Endpoint(), reply = try Endpoint(), current = try registryContext()
        var fail = false
        let host = try host(endpoint, context: { if fail { throw Failure.policy }; return current })
        _ = try hostSession(host, endpoint: endpoint)
        let baseline = try sendReferences(reply.port)
        try endpoint.sendInput(Data([1]), fileport: reply.port)
        fail = true
        XCTAssertThrowsError(try host.poll { $0.closeIfUnclaimed(); XCTFail("unexpected input") })
        XCTAssertEqual(host.retainedSessionCount, 0)
        XCTAssertEqual(try sendReferences(reply.port), baseline)
        XCTAssertEqual(receiveReferences(endpoint.port), 0)
    }

    func testHostCapacityIncompatibilityAndMalformedHelloDoNotRetireOtherSessions() throws {
        let endpoint = try Endpoint(), host = try host(endpoint, maximum: 1), reply = try Endpoint()
        _ = try hostSession(host, endpoint: endpoint)
        let baseline = try sendReferences(reply.port)
        try MachCommandWire.send(CommandHandshakeOffer(nonce: Data(repeating: 1, count: 32)).canonicalBytes,
            destination: endpoint.port, replyPort: reply.port, identifier: MachCommandCallerReceiver.helloMessageID,
            timeoutMilliseconds: 1000)
        XCTAssertEqual(try host.poll { $0.closeIfUnclaimed() }, .rejected(.capacity))
        XCTAssertEqual(host.retainedSessionCount, 1)
        XCTAssertEqual(try sendReferences(reply.port), baseline)
        host.close()
        let next = try Endpoint(), available = try self.host(next)
        let old = try CommandHandshakeCapabilities(wireVersions: [1], submissionSchemaVersions: [1], inputCarrierVersions: [1])
        try MachCommandWire.send(CommandHandshakeOffer(nonce: Data(repeating: 1, count: 32), capabilities: old).canonicalBytes,
            destination: next.port, replyPort: reply.port, identifier: MachCommandCallerReceiver.helloMessageID,
            timeoutMilliseconds: 1000)
        XCTAssertEqual(try available.poll { $0.closeIfUnclaimed() }, .rejected(.incompatible))
        let response = try receiver(reply, maximum: 4096).receiveHelloReply(timeoutMilliseconds: 1000)
        response.caller.close()
        try MachCommandWire.send(Data([0xa0]), destination: next.port, replyPort: reply.port,
            identifier: MachCommandCallerReceiver.helloMessageID, timeoutMilliseconds: 1000)
        XCTAssertEqual(try available.poll { $0.closeIfUnclaimed() }, .rejected(.malformed))
        _ = try hostSession(available, endpoint: next)
        available.close()
    }

    func testHostStopDuringBoundedReceiveReleasesTheRightOnItsOwnerThread() throws {
        let endpoint = try Endpoint(), host = try host(endpoint, wait: 100), stop = host.stop
        let finished = DispatchSemaphore(value: 0)
        DispatchQueue.global().asyncAfter(deadline: .now() + .milliseconds(10)) { stop.requestStop(); finished.signal() }
        XCTAssertThrowsError(try host.poll { $0.closeIfUnclaimed(); XCTFail("unexpected input") }) {
            XCTAssertEqual($0 as? CommandReceiveHostError, .stopped)
        }
        XCTAssertEqual(finished.wait(timeout: .now() + 1), .success)
        XCTAssertEqual(receiveReferences(endpoint.port), 0)
    }

    func testHostRejectsNonFileportInputAndRunStillAssemblesTheNextSubmission() throws {
        let endpoint = try Endpoint(), carried = try Endpoint(), current = try registryContext()
        var reads = 0
        let host = try host(endpoint, context: { reads += 1; return current })
        let profile = try hostSession(host, endpoint: endpoint)
        let baseline = try sendReferences(carried.port), before = reads
        try endpoint.sendInput(Data([1]), fileport: carried.port)
        XCTAssertEqual(try host.poll { $0.closeIfUnclaimed(); XCTFail("malformed input reached handler") }, .rejected(.malformed))
        XCTAssertEqual(reads, before + 2)
        XCTAssertEqual(try sendReferences(carried.port), baseline)
        XCTAssertEqual(host.retainedSessionCount, 1)
        XCTAssertEqual(receiveReferences(endpoint.port), 1)
        try endpoint.sendInput(Data([2]), fileport: carried.port)
        try enqueueHostInput(endpoint, binding: profile.callerBinding)
        var command: RetainedCommandCapture?
        XCTAssertThrowsError(try host.run { received in
            XCTAssertEqual(host.retainedSessionCount, 1)
            command = try self.hostCapture(host, received: received)
            host.stop.requestStop()
        }) { XCTAssertEqual($0 as? CommandReceiveHostError, .stopped) }
        XCTAssertEqual(try sendReferences(carried.port), baseline)
        XCTAssertEqual(host.retainedSessionCount, 0)
        XCTAssertEqual(receiveReferences(endpoint.port), 0)
        try XCTUnwrap(command).withBorrowedInputDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
        command?.close()
    }

    func testHostNonFileportRejectionStillObservesPolicyReadFailure() throws {
        enum Failure: Error { case policy }
        let endpoint = try Endpoint(), carried = try Endpoint(), current = try registryContext()
        var reads = 0, failAt = Int.max
        let host = try host(endpoint, context: { reads += 1; if reads == failAt { throw Failure.policy }; return current })
        _ = try hostSession(host, endpoint: endpoint)
        let baseline = try sendReferences(carried.port)
        failAt = reads + 2
        try endpoint.sendInput(Data([1]), fileport: carried.port)
        XCTAssertThrowsError(try host.poll { $0.closeIfUnclaimed(); XCTFail("malformed input reached handler") }) {
            guard case Failure.policy = $0 else { return XCTFail("expected current policy failure: \($0)") }
        }
        XCTAssertEqual(try sendReferences(carried.port), baseline)
        XCTAssertEqual(host.retainedSessionCount, 0)
        XCTAssertEqual(receiveReferences(endpoint.port), 0)
    }

    func testHostRunOwnsTheLoopAndHandlerCanAssembleWithoutReceiveReentry() throws {
        let endpoint = try Endpoint(), host = try host(endpoint), profile = try hostSession(host, endpoint: endpoint)
        try enqueueHostInput(endpoint, binding: profile.callerBinding)
        var command: RetainedCommandCapture?
        XCTAssertThrowsError(try host.run { received in
            XCTAssertThrowsError(try host.poll { $0.closeIfUnclaimed() }) { XCTAssertEqual($0 as? CommandReceiveHostError, .operationActive) }
            XCTAssertThrowsError(try host.run { $0.closeIfUnclaimed() }) { XCTAssertEqual($0 as? CommandReceiveHostError, .operationActive) }
            command = try self.hostCapture(host, received: received)
            host.stop.requestStop()
        }) { XCTAssertEqual($0 as? CommandReceiveHostError, .stopped) }
        XCTAssertEqual(receiveReferences(endpoint.port), 0)
        try XCTUnwrap(command).withBorrowedInputDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
        command?.close()
    }

    func testHostStopDuringAssemblyCancelsAndClosesOnlyTheIncomingObjects() throws {
        let endpoint = try Endpoint(), host = try host(endpoint), profile = try hostSession(host, endpoint: endpoint)
        try enqueueHostInput(endpoint, binding: profile.callerBinding)
        var earlier: RetainedCommandCapture?
        _ = try host.poll { earlier = try self.hostCapture(host, received: $0) }
        try enqueueHostInput(endpoint, binding: profile.callerBinding)
        let stop = host.stop
        var inspection: TestInputInspection?
        XCTAssertThrowsError(try host.poll { received in
            inspection = TestInputInspection(received: received)
            _ = try self.hostCapture(host, received: TestInputInspection(received: received).received,
                checkCancellation: { stop.requestStop() })
        }) { XCTAssertEqual($0 as? CommandReceiveHostError, .stopped) }
        try expectAssemblyResourcesRetired(XCTUnwrap(inspection).received)
        try XCTUnwrap(earlier).withBorrowedInputDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
        XCTAssertEqual(receiveReferences(endpoint.port), 0)
        earlier?.close()
    }

    func testHostInvalidConfigurationAndDeinitReleaseOnlyTransferredReceiveRights() throws {
        for wait: UInt32 in [0, 60_001] {
            let endpoint = try Endpoint(), reply = try Endpoint(), baseline = try sendReferences(reply.port)
            try endpoint.sendInput(Data([1]), fileport: reply.port)
            XCTAssertThrowsError(try host(endpoint, wait: wait))
            XCTAssertEqual(receiveReferences(endpoint.port), 0)
            XCTAssertEqual(try sendReferences(reply.port), baseline)
        }
        let endpoint = try Endpoint()
        var owner: CommandReceiveHost? = try host(endpoint)
        XCTAssertNotNil(owner)
        owner = nil
        XCTAssertEqual(receiveReferences(endpoint.port), 0)
    }

    func testHostCaptureTransfersToJournalAndHostRetirementPreservesTheQueuedRequest() throws {
        let fixture = try CommandRequestFixture(owned: true, commandSchema: 2), journal = try XCTUnwrap(fixture.authority)
        let endpoint = try Endpoint(), host = try host(endpoint), profile = try hostSession(host, endpoint: endpoint)
        try enqueueHostInput(endpoint, binding: profile.callerBinding)
        var request: IssuedRequestPayload?, inspection: TestInputInspection?
        _ = try host.poll { received in
            inspection = TestInputInspection(received: received)
            let command = try self.hostCapture(host, received: TestInputInspection(received: received).received)
            request = try journal.admitCommand(command, draft: fixture.draft(command), expression: self.selfExpression(),
                userID: geteuid(), auditSessionID: nil, now: { fixture.now() }, receiptTimeMs: nil)
        }
        let id = try XCTUnwrap(request).requestID
        host.close()
        XCTAssertEqual(try journal.withRequests { try $0.state(requestID: id).phase }, .queued)
        try XCTUnwrap(inspection).received.input.withBorrowedDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
        let now = fixture.now(120)
        _ = try journal.withRequests { try $0.retirePending(requestID: id, reason: .cancelled, now: now, receiptTimeMs: nil) }
        try expectAssemblyResourcesRetired(XCTUnwrap(inspection).received)
    }

    func testHostAssemblyPreflightReentryDoesNotCloseItsActiveInput() throws {
        let endpoint = try Endpoint(), context = try registryContext()
        var reenter: (() throws -> Void)?
        let host = try host(endpoint, context: { try reenter?(); return context })
        let profile = try hostSession(host, endpoint: endpoint)
        try enqueueHostInput(endpoint, binding: profile.callerBinding)
        var command: RetainedCommandCapture?
        _ = try host.poll { received in
            let alias = TestInputInspection(received: received)
            reenter = {
                XCTAssertThrowsError(try self.hostCapture(host, received: alias.received)) {
                    XCTAssertEqual($0 as? CommandReceiveHostError, .operationActive)
                }
            }
            defer { reenter = nil }
            command = try self.hostCapture(host, received: alias.received)
        }
        try XCTUnwrap(command).withBorrowedInputDescriptor { XCTAssertGreaterThanOrEqual($0, 0) }
        host.close(); command?.close()
    }

    func testHostReplyQueueTimeoutPreservesItsReceiveQueueAndOtherSessions() throws {
        let endpoint = try Endpoint(), host = try host(endpoint), reply = try Endpoint()
        _ = try hostSession(host, endpoint: endpoint)
        var status = mach_port_status_t(), count = mach_msg_type_number_t(MemoryLayout<mach_port_status_t>.size / MemoryLayout<integer_t>.size)
        XCTAssertEqual(withUnsafeMutablePointer(to: &status) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                mach_port_get_attributes(mach_task_self_, reply.port, Int32(MACH_PORT_RECEIVE_STATUS), $0, &count)
            }
        }, KERN_SUCCESS)
        for _ in 0..<status.mps_qlimit { try reply.send(Data([1])) }
        let baseline = try sendReferences(reply.port)
        try MachCommandWire.send(CommandHandshakeOffer(nonce: Data(repeating: 1, count: 32)).canonicalBytes,
            destination: endpoint.port, replyPort: reply.port, identifier: MachCommandCallerReceiver.helloMessageID,
            timeoutMilliseconds: 1000)
        XCTAssertEqual(try host.poll { $0.closeIfUnclaimed() }, .rejected(.replyFailure))
        XCTAssertEqual(try sendReferences(reply.port), baseline)
        XCTAssertEqual(host.retainedSessionCount, 1)
        _ = try hostSession(host, endpoint: endpoint)
        host.close()
    }

    func testHostRejectedAssemblyCanKeepItsOriginalSessionAndReceiveLoopUsable() throws {
        let endpoint = try Endpoint(), host = try host(endpoint), profile = try hostSession(host, endpoint: endpoint)
        try enqueueHostInput(endpoint, binding: Data(repeating: 0, count: 16))
        var inspected: TestInputInspection?
        XCTAssertEqual(try host.poll { received in
            inspected = TestInputInspection(received: received)
            XCTAssertThrowsError(try self.hostCapture(host, received: TestInputInspection(received: received).received)) {
                XCTAssertEqual($0 as? CommandSessionRegistryError, .unknownSession)
            }
        }, .inputHandled)
        try expectAssemblyResourcesRetired(XCTUnwrap(inspected).received)
        XCTAssertEqual(host.retainedSessionCount, 1)
        try enqueueHostInput(endpoint, binding: profile.callerBinding)
        _ = try host.poll { try self.hostCapture(host, received: $0).close() }
        host.close()
    }

    func testHostStopBeforeFirstWorkDisposesWithoutWaitingForDeinit() throws {
        for run in [false, true] {
            let endpoint = try Endpoint(), host = try host(endpoint)
            host.stop.requestStop()
            if run { XCTAssertThrowsError(try host.run { $0.closeIfUnclaimed() }) }
            else { XCTAssertThrowsError(try host.poll { $0.closeIfUnclaimed() }) }
            XCTAssertEqual(receiveReferences(endpoint.port), 0)
        }
    }

}

extension MachCommandCallerReceiverTests {
    // Same-process fixtures exercise actual kernel carriers. They do not prove privileged child execution.
    private func serveIO(_ port: mach_port_t, admission: Data?, terminal: Data?, release: DispatchSemaphore,
                         writeOutput: Bool = false, expectClosed: Bool = false) throws -> (DispatchSemaphore, OSAllocatedUnfairLock<Result<Void, Error>?>) {
        let expression = try selfExpression(), user = geteuid(), completed = DispatchSemaphore(value: 0)
        let result = OSAllocatedUnfairLock(initialState: Result<Void, Error>?.none)
        DispatchQueue.global().async {
            defer { completed.signal() }
            result.withLock { output in output = Result {
                let receiver = try MachCommandCallerReceiver(receivePort: port, expression: expression,
                    userID: user, auditSessionID: nil, maxPayloadBytes: 8192)
                let input = try receiver.receiveIOInput(timeoutMilliseconds: 5000)
                defer { input.closeIfUnclaimed() }
                let channels = try XCTUnwrap(input.outputs)
                try channels.recheck()
                if let admission { try input.sendAdmissionReply(admission) }
                guard release.wait(timeout: .now() + 5) == .success else { throw MachCommandCallerError.timeout }
                if expectClosed { XCTAssertThrowsError(try channels.recheck()); return }
                if writeOutput {
                    try channels.output.withBorrowedDescriptor { XCTAssertEqual(Darwin.write($0, "stdout", 6), 6) }
                    try channels.error.withBorrowedDescriptor { XCTAssertEqual(Darwin.write($0, "stderr", 6), 6) }
                }
                if let terminal { try channels.sendTerminalResult(terminal, timeoutMilliseconds: 1000) }
            } }
        }
        return (completed, result)
    }
    private func ioPayloads(profile: CommandHandshakeProfile, submission: CommandSubmission,
                            outcome: CommandAdmissionOutcome? = nil, terminal: CommandTerminalOutcome = .exited(7)) throws -> (Data, Data) {
        let request = CommandAdmittedRequest(requestID: Data(repeating: 6, count: 16),
            requestDigest: Data(repeating: 7, count: 32), challenge: Data(repeating: 8, count: 32))
        let admission = CommandAdmissionResultPayload(profile: profile, submission: submission.binding,
            submissionDigest: Data(SHA256.hash(data: submission.canonicalBytes)), outcome: outcome ?? .admitted(request))
        return (try admission.canonicalBytes, try CommandTerminalResultPayload(profile: profile, original: submission,
            request: request, outcome: terminal).canonicalBytes)
    }
    func testIOClientKeepsSessionAfterEmptyPollAndReceivesBoundTerminalAndOriginalStreams() throws {
        let endpoint = try Endpoint(), handshake = try admissionClientFixture(endpoint.port, input: 4, wire: 3)
        let submission = try commandSubmission(), payloads = try ioPayloads(profile: handshake.profile, submission: submission)
        var input: [Int32] = [-1, -1], output: [Int32] = [-1, -1], error: [Int32] = [-1, -1]
        XCTAssertEqual(pipe(&input), 0); XCTAssertEqual(pipe(&output), 0); XCTAssertEqual(pipe(&error), 0)
        defer { for fd in input + output + error { _ = Darwin.close(fd) } }
        XCTAssertEqual(Darwin.write(input[1], "unread", 6), 6)
        let inputFlags = fcntl(input[0], F_GETFL), references = try sendReferences(endpoint.port)
        let release = DispatchSemaphore(value: 0)
        let server = try serveIO(endpoint.port, admission: payloads.0, terminal: payloads.1, release: release, writeOutput: true)
        defer { release.signal() }
        let result = try MachCommandIOClient.submit(submission, inputDescriptor: input[0], outputDescriptor: output[1], errorDescriptor: error[1],
            handshake: handshake, expression: selfExpression(), userID: geteuid(), auditSessionID: nil, maximumPayloadBytes: 8192)
        guard case .admitted(let session) = result else { return XCTFail("An admitted request must retain its terminal channel") }
        defer { session.close() }
        XCTAssertEqual(try sendReferences(endpoint.port), references)
        XCTAssertNil(try session.pollTerminalResult(timeoutMilliseconds: 250))
        release.signal()
        XCTAssertEqual(server.0.wait(timeout: .now() + 5), .success); try server.1.withLock { try $0?.get() }
        let terminal = try XCTUnwrap(session.pollTerminalResult(timeoutMilliseconds: 1000))
        XCTAssertEqual(terminal.outcome, .exited(7)); XCTAssertEqual(terminal.submission, submission.binding)
        XCTAssertEqual(try session.pollTerminalResult()?.outcome, .exited(7))
        var bytes = [UInt8](repeating: 0, count: 6)
        for (fd, expected) in [(input[0], "unread"), (output[0], "stdout"), (error[0], "stderr")] {
            XCTAssertEqual(Darwin.read(fd, &bytes, 6), 6); XCTAssertEqual(Data(bytes), Data(expected.utf8))
        }
        XCTAssertEqual(fcntl(input[0], F_GETFL), inputFlags)
        XCTAssertEqual(try sendReferences(endpoint.port), references - 1)
    }
    func testIOClientRefusalAndUncertaintyCloseTheTerminalRightWithoutResubmission() throws {
        for outcome: CommandAdmissionOutcome in [.notAdmitted(.updateWaiting, .updateWaiting), .uncertain(.storageFailure)] {
            let endpoint = try Endpoint(), handshake = try admissionClientFixture(endpoint.port, input: 4, wire: 3)
            let submission = try commandSubmission(), payloads = try ioPayloads(profile: handshake.profile, submission: submission, outcome: outcome)
            let input = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC), output = Darwin.open("/dev/null", O_WRONLY | O_CLOEXEC)
            defer { _ = Darwin.close(input); _ = Darwin.close(output) }
            let release = DispatchSemaphore(value: 0), server = try serveIO(endpoint.port, admission: payloads.0,
                terminal: nil, release: release, expectClosed: true)
            defer { release.signal() }
            let result = try MachCommandIOClient.submit(submission, inputDescriptor: input, outputDescriptor: output, errorDescriptor: output,
                handshake: handshake, expression: selfExpression(), userID: geteuid(), auditSessionID: nil, maximumPayloadBytes: 8192)
            guard case .result(let verified) = result else { return XCTFail("A refusal must not retain an execution session") }
            XCTAssertEqual(verified.outcome, outcome)
            release.signal(); XCTAssertEqual(server.0.wait(timeout: .now() + 5), .success); try server.1.withLock { try $0?.get() }
            XCTAssertThrowsError(try receiver(endpoint).receiveIOInput(timeoutMilliseconds: 10)) { XCTAssertEqual($0 as? MachCommandCallerError, .timeout) }
            XCTAssertGreaterThanOrEqual(fcntl(input, F_GETFD), 0); XCTAssertGreaterThanOrEqual(fcntl(output, F_GETFD), 0)
        }
    }
    func testIOClientMalformedTerminalRetiresSessionWithoutResubmission() throws {
        let endpoint = try Endpoint(), handshake = try admissionClientFixture(endpoint.port, input: 4, wire: 3)
        let submission = try commandSubmission(), payloads = try ioPayloads(profile: handshake.profile, submission: submission)
        let input = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC), output = Darwin.open("/dev/null", O_WRONLY | O_CLOEXEC)
        defer { _ = Darwin.close(input); _ = Darwin.close(output) }
        let release = DispatchSemaphore(value: 0), server = try serveIO(endpoint.port, admission: payloads.0, terminal: Data([0xa0]), release: release)
        defer { release.signal() }
        let result = try MachCommandIOClient.submit(submission, inputDescriptor: input, outputDescriptor: output, errorDescriptor: output,
            handshake: handshake, expression: selfExpression(), userID: geteuid(), auditSessionID: nil, maximumPayloadBytes: 8192)
        guard case .admitted(let session) = result else { return XCTFail("An admitted request must retain its terminal channel") }
        release.signal(); XCTAssertEqual(server.0.wait(timeout: .now() + 5), .success); try server.1.withLock { try $0?.get() }
        XCTAssertThrowsError(try session.pollTerminalResult(timeoutMilliseconds: 1000))
        XCTAssertThrowsError(try session.pollTerminalResult()) { XCTAssertEqual($0 as? MachCommandHandshakeError, .retired) }
        XCTAssertThrowsError(try receiver(endpoint).receiveIOInput(timeoutMilliseconds: 10)) { XCTAssertEqual($0 as? MachCommandCallerError, .timeout) }
    }
    func testIOClientCancellationClosesAdmittedTerminalBeforeAnyDispatch() throws {
        let endpoint = try Endpoint(), handshake = try admissionClientFixture(endpoint.port, input: 4, wire: 3)
        let submission = try commandSubmission(), payloads = try ioPayloads(profile: handshake.profile, submission: submission)
        let input = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC), output = Darwin.open("/dev/null", O_WRONLY | O_CLOEXEC)
        defer { _ = Darwin.close(input); _ = Darwin.close(output) }
        let release = DispatchSemaphore(value: 0), server = try serveIO(endpoint.port, admission: payloads.0, terminal: nil, release: release, expectClosed: true)
        defer { release.signal() }
        let result = try MachCommandIOClient.submit(submission, inputDescriptor: input, outputDescriptor: output, errorDescriptor: output,
            handshake: handshake, expression: selfExpression(), userID: geteuid(), auditSessionID: nil, maximumPayloadBytes: 8192)
        guard case .admitted(let session) = result else { return XCTFail("An admitted request must retain its terminal channel") }
        XCTAssertThrowsError(try session.pollTerminalResult(checkCancellation: { throw CancellationError() })) { XCTAssertTrue($0 is CancellationError) }
        release.signal(); XCTAssertEqual(server.0.wait(timeout: .now() + 5), .success); try server.1.withLock { try $0?.get() }
    }
    func testIOClientRejectsPublicNonRootPolicyAndLegacyProfileBeforeExposingStreams() throws {
        let endpoint = try Endpoint()
        let policy = try XPCPeerPolicy(teamID: "TEAMID1234", componentIdentifier: "dev.remozio.fixture",
            approvedCodeDirectoryHashes: [Data(repeating: 1, count: 20)], expectedUserID: 1)
        XCTAssertThrowsError(try MachCommandIOClient.submit(commandSubmission(), inputDescriptor: -1, outputDescriptor: -1, errorDescriptor: -1,
            handshake: admissionClientFixture(endpoint.port, input: 4, wire: 3), authorityPolicy: policy, maximumPayloadBytes: 8192)) { XCTAssertEqual($0 as? MachCommandHandshakeError, .invalidConfiguration) }
        XCTAssertThrowsError(try MachCommandIOClient.submit(commandSubmission(), inputDescriptor: -1, outputDescriptor: -1, errorDescriptor: -1,
            handshake: admissionClientFixture(endpoint.port, wire: 2), expression: selfExpression(), userID: geteuid(), auditSessionID: nil, maximumPayloadBytes: 8192)) {
            XCTAssertEqual($0 as? MachCommandHandshakeError, .incompatible)
        }
        XCTAssertThrowsError(try receiver(endpoint).receiveIOInput(timeoutMilliseconds: 10)) { XCTAssertEqual($0 as? MachCommandCallerError, .timeout) }
        XCTAssertEqual(try sendReferences(endpoint.port), 1)
    }
}


extension MachCommandCallerReceiverTests {
    func testIOAdmissionAttemptRetainsAllStreamsThroughJournalAdmissionAndRetiresOnlyCopies() throws {
        for checkpointed in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true)
            let endpoint = try Endpoint(), helloReply = try Endpoint(), admissionReply = try Endpoint(), terminalReply = try Endpoint()
            let session = try RetainedCommandHandshake(hello: hello(endpoint, reply: helloReply, capabilities: .executionChannels),
                capabilities: .executionChannels, macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16),
                expression: selfExpression(), userID: geteuid(), auditSessionID: nil)
            defer { session.close() }
            let submission = try commandSubmission(binding: .init(id: Data(repeating: 4, count: 16), nonce: Data(repeating: 5, count: 32),
                callerBinding: session.profile.callerBinding))
            var input: [Int32] = [-1, -1]; XCTAssertEqual(pipe(&input), 0)
            let output = Darwin.open("/dev/null", O_WRONLY | O_CLOEXEC)
            defer { for fd in input + [output] { _ = Darwin.close(fd) } }
            XCTAssertEqual(Darwin.write(input[1], "unread", 6), 6)
            try MachCommandIOWire.send(submission.canonicalBytes, inputDescriptor: input[0], outputDescriptor: output, errorDescriptor: output,
                destination: endpoint.port, admissionReply: admissionReply.port, terminalReply: terminalReply.port,
                maximumPayloadBytes: 8192, timeoutMilliseconds: 1000)
            let received = try receiver(endpoint, maximum: 8192).receiveIOInput(timeoutMilliseconds: 1000)
            let channels = try XCTUnwrap(received.outputs)
            let attempt = try session.prepareAdmission(received: TestInputInspection(received: received).received,
                expression: selfExpression(), userID: geteuid(), auditSessionID: nil, submissionLimits: assemblyLimits)
            received.closeIfUnclaimed()
            try channels.recheck()
            let request = try admitAttempt(attempt, fixture: fixture)
            guard case .admitted(let identity) = try typedOutcome(admissionReply, submission: submission, profile: session.profile) else {
                return XCTFail("The journal must acknowledge the exact admitted request")
            }
            XCTAssertEqual(identity.requestID, request.requestID)
            XCTAssertEqual(try sendReferences(admissionReply.port), 1); XCTAssertEqual(try sendReferences(terminalReply.port), 2)
            try channels.recheck()
            let retiredAt = fixture.now(110)
            try XCTUnwrap(fixture.authority).withRequests { _ = try $0.retirePending(requestID: request.requestID, reason: .cancelled,
                now: retiredAt, receiptTimeMs: nil) }
            XCTAssertThrowsError(try channels.recheck())
            XCTAssertEqual(try sendReferences(terminalReply.port), 1)
            var bytes = [UInt8](repeating: 0, count: 6)
            XCTAssertEqual(Darwin.read(input[0], &bytes, 6), 6); XCTAssertEqual(Data(bytes), Data("unread".utf8))
            XCTAssertGreaterThanOrEqual(fcntl(output, F_GETFD), 0)
        }
    }
    func testIOCaptureFailureClosesAllImportedChannelsAndPreservesBorrowedDescriptors() throws {
        let endpoint = try Endpoint(), admission = try Endpoint(), terminal = try Endpoint()
        let input = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC), output = Darwin.open("/dev/null", O_WRONLY | O_CLOEXEC)
        defer { _ = Darwin.close(input); _ = Darwin.close(output) }
        try MachCommandIOWire.send(commandSubmission(executablePath: "/not/a/remozio/program").canonicalBytes,
            inputDescriptor: input, outputDescriptor: output, errorDescriptor: output, destination: endpoint.port,
            admissionReply: admission.port, terminalReply: terminal.port, maximumPayloadBytes: 8192, timeoutMilliseconds: 1000)
        let received = try receiver(endpoint, maximum: 8192).receiveIOInput(timeoutMilliseconds: 1000)
        let channels = try XCTUnwrap(received.outputs)
        XCTAssertThrowsError(try assemble(received))
        try expectAssemblyResourcesRetired(received); XCTAssertThrowsError(try channels.recheck())
        XCTAssertEqual(try sendReferences(admission.port), 1); XCTAssertEqual(try sendReferences(terminal.port), 1)
        XCTAssertGreaterThanOrEqual(fcntl(input, F_GETFD), 0); XCTAssertGreaterThanOrEqual(fcntl(output, F_GETFD), 0)
    }
}


extension MachCommandCallerReceiverTests {
    func testIOClientLateTerminalOrCancellationAfterReceiptRetiresRatherThanReturningEmptyPoll() throws {
        for late in [false, true] {
            let endpoint = try Endpoint(), handshake = try admissionClientFixture(endpoint.port, input: 4, wire: 3)
            let submission = try commandSubmission(), payloads = try ioPayloads(profile: handshake.profile, submission: submission)
            let input = Darwin.open("/dev/null", O_RDONLY), output = Darwin.open("/dev/null", O_WRONLY)
            defer { _ = Darwin.close(input); _ = Darwin.close(output) }
            let release = DispatchSemaphore(value: 0), server = try serveIO(endpoint.port, admission: payloads.0, terminal: payloads.1, release: release)
            defer { release.signal() }
            let result = try MachCommandIOClient.submit(submission, inputDescriptor: input, outputDescriptor: output, errorDescriptor: output,
                handshake: handshake, expression: selfExpression(), userID: geteuid(), auditSessionID: nil, maximumPayloadBytes: 8192)
            guard case .admitted(let session) = result else { return XCTFail("Admission must retain the terminal channel") }
            release.signal(); XCTAssertEqual(server.0.wait(timeout: .now() + 5), .success); try server.1.withLock { try $0?.get() }
            var samples = 0, cancellations = 0
            XCTAssertThrowsError(try session.pollTerminalResult(timeoutMilliseconds: 1000, checkCancellation: {
                cancellations += 1
                if !late, cancellations >= 2 { throw CancellationError() }
            }, clock: { samples += 1; return late && samples >= 4 ? 1000 : 0 })) {
                if late { XCTAssertEqual($0 as? CommandTerminalResultError, .deadlineExceeded) }
                else { XCTAssertTrue($0 is CancellationError) }
            }
            XCTAssertThrowsError(try session.pollTerminalResult()) { XCTAssertEqual($0 as? MachCommandHandshakeError, .retired) }
            XCTAssertThrowsError(try receiver(endpoint).receiveIOInput(timeoutMilliseconds: 10)) { XCTAssertEqual($0 as? MachCommandCallerError, .timeout) }
        }
    }
}

extension MachCommandCallerReceiverTests {
    private func ownerIOCommand(admission: Endpoint, terminal: Endpoint) throws ->
        (ReceivedMachCommandInputSubmission, RetainedCommandCapture, CommandSubmission, CommandHandshakeProfile) {
        let endpoint = try Endpoint(), input = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC), output = Darwin.open("/dev/null", O_WRONLY | O_CLOEXEC)
        guard input >= 0, output >= 0 else { throw MachCommandCallerError.unavailable }
        defer { _ = Darwin.close(input); _ = Darwin.close(output) }
        let submission = try commandSubmission()
        let profile = CommandHandshakeProfile(wireVersion: 3, submissionSchemaVersion: 1, inputCarrierVersion: 4,
            callerBinding: submission.binding.callerBinding, macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16))
        try MachCommandIOWire.send(submission.canonicalBytes, inputDescriptor: input, outputDescriptor: output, errorDescriptor: output,
            destination: endpoint.port, admissionReply: admission.port, terminalReply: terminal.port, maximumPayloadBytes: 8192, timeoutMilliseconds: 1000)
        let received = try receiver(endpoint, maximum: 8192).receiveIOInput(timeoutMilliseconds: 1000)
        return (received, try assemble(received, admissionProfile: profile), submission, profile)
    }
    private func ownerAdmission(_ endpoint: Endpoint, submission: CommandSubmission, profile: CommandHandshakeProfile) throws -> VerifiedCommandAdmissionResult {
        let raw = try receiver(endpoint, maximum: 4096).receiveAdmissionReply(timeoutMilliseconds: 1000)
        defer { raw.caller.close() }
        return try CommandAdmissionResultPayload.decode(raw.payload, profile: profile, original: submission)
    }
    private func ownerTerminal(_ endpoint: Endpoint, submission: CommandSubmission, admission: VerifiedCommandAdmissionResult) throws -> VerifiedCommandTerminalResult {
        let raw = try receiver(endpoint, maximum: 4096).receiveTerminalReply(timeoutMilliseconds: 1000)
        defer { raw.caller.close() }
        return try CommandTerminalResultPayload.decode(raw.payload, profile: admission.profile, original: submission, admission: admission)
    }
    private func ownerDecision(_ request: IssuedRequestPayload, fixture: CommandRequestFixture, decline: Bool) throws -> ConsumptionReceipt {
        let body = try DecisionPayload(macID: request.macID, accountID: request.accountID, requestID: request.requestID,
            requestDigest: request.requestDigest(bodyLimits: fixture.limits, signingLimits: fixture.limits), challenge: request.challenge,
            phoneID: Data(repeating: 5, count: 16), keyID: Data(repeating: decline ? 7 : 6, count: 16),
            action: request.permittedActions.first { $0.choice == (decline ? .decline : .execute) }!).encode(limits: fixture.limits)
        let input = try SigningInput.make(wireVersion: 1, messageType: .decision, purpose: decline ? .cancellation : .biometricAuthorization,
            canonicalPayload: body, payloadLimits: fixture.limits, inputLimits: fixture.limits)
        let signature = try (decline ? fixture.decision : fixture.biometric).signature(for: input).rawRepresentation
        let now = fixture.now(120)
        return try XCTUnwrap(fixture.authority).withRequests {
            try $0.consume(canonicalDecision: body, signature: signature, authenticatedPhoneID: Data(repeating: 5, count: 16),
                authenticatedEnrollmentEpoch: Data(repeating: 9, count: 16), now: now, receiptTimeMs: nil)
        }
    }
    func testIOOwnerCommittedPendingRetirementSendsExactTerminalOnce() throws {
        let cases: [(PendingRequestRetirement, UInt64, CommandTerminalOutcome)] = [(.cancelled, 120, .cancelledBeforeStart),
            (.deadlineElapsed, 200, .expired), (.targetTimedOut, 120, .expired), (.targetDisappeared, 120, .unknown), (.authorityRestart, 120, .cancelledBeforeStart)]
        for checkpointed in [false, true] {
            for (reason, time, expected) in cases {
                let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true)
                let authority = try XCTUnwrap(fixture.authority), admissionPort = try Endpoint(), terminalPort = try Endpoint()
                let (received, command, submission, profile) = try ownerIOCommand(admission: admissionPort, terminal: terminalPort)
                let request = try admitOwnedCommand(command, fixture: fixture)
                let admission = try ownerAdmission(admissionPort, submission: submission, profile: profile), now = fixture.now(time)
                let state = try authority.withRequests { try $0.retirePending(requestID: request.requestID, reason: reason, now: now, receiptTimeMs: nil) }
                let terminal = try ownerTerminal(terminalPort, submission: submission, admission: admission)
                XCTAssertEqual(terminal.outcome, expected); XCTAssertEqual(terminal.request.requestID, request.requestID)
                XCTAssertEqual(terminal.request.requestDigest, state.requestDigest); XCTAssertEqual(terminal.request.challenge, state.challenge)
                XCTAssertEqual(terminal.submission, submission.binding); XCTAssertTrue(state.phase.isTerminal)
                try expectAssemblyResourcesRetired(received); XCTAssertEqual(try sendReferences(terminalPort.port), 1)
                XCTAssertThrowsError(try authority.withRequests { try $0.retirePending(requestID: request.requestID, reason: reason, now: now, receiptTimeMs: nil) })
                XCTAssertThrowsError(try receiver(terminalPort).receiveTerminalReply(timeoutMilliseconds: 10)) { XCTAssertEqual($0 as? MachCommandCallerError, .timeout) }
                XCTAssertNotNil(try fixture.reservation(submission.binding.id))
            }
        }
    }
    func testIOOwnerSignedDeclineSendsDeniedAfterDurableConsumption() throws {
        for checkpointed in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true)
            let authority = try XCTUnwrap(fixture.authority), admissionPort = try Endpoint(), terminalPort = try Endpoint()
            let (received, command, submission, profile) = try ownerIOCommand(admission: admissionPort, terminal: terminalPort)
            let request = try admitOwnedCommand(command, fixture: fixture), admission = try ownerAdmission(admissionPort, submission: submission, profile: profile)
            let receipt = try ownerDecision(request, fixture: fixture, decline: true)
            XCTAssertEqual(receipt.event.outcome, .noDispatch)
            XCTAssertEqual(try ownerTerminal(terminalPort, submission: submission, admission: admission).outcome, .denied)
            XCTAssertEqual(try authority.withRequests { try $0.historicalOutcome(requestID: request.requestID)?.phase }, .declined)
            try expectAssemblyResourcesRetired(received)
            XCTAssertThrowsError(try ownerDecision(request, fixture: fixture, decline: true))
            XCTAssertThrowsError(try receiver(terminalPort).receiveTerminalReply(timeoutMilliseconds: 10)) { XCTAssertEqual($0 as? MachCommandCallerError, .timeout) }
        }
    }
    func testIOOwnerExpirySweepDeliversCommittedExpiryOnce() throws {
        for checkpointed in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true)
            let authority = try XCTUnwrap(fixture.authority), admissionPort = try Endpoint(), terminalPort = try Endpoint()
            let (_, command, submission, profile) = try ownerIOCommand(admission: admissionPort, terminal: terminalPort)
            let request = try admitOwnedCommand(command, fixture: fixture), admission = try ownerAdmission(admissionPort, submission: submission, profile: profile)
            let now = fixture.now(200)
            XCTAssertEqual(try authority.withRequests { try $0.expirePending(now: now, receiptTimeMs: nil).map(\.requestID) }, [request.requestID])
            XCTAssertEqual(try ownerTerminal(terminalPort, submission: submission, admission: admission).outcome, .expired)
            XCTAssertTrue(try authority.withRequests { try $0.expirePending(now: now, receiptTimeMs: nil).isEmpty })
            XCTAssertThrowsError(try receiver(terminalPort).receiveTerminalReply(timeoutMilliseconds: 10)) { XCTAssertEqual($0 as? MachCommandCallerError, .timeout) }
        }
    }
    func testIOOwnerRejectedRetirementCommitCannotSendKnownNoEffect() throws {
        for checkpointed in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true)
            let authority = try XCTUnwrap(fixture.authority), admissionPort = try Endpoint(), terminalPort = try Endpoint()
            let (_, command, submission, profile) = try ownerIOCommand(admission: admissionPort, terminal: terminalPort)
            let request = try admitOwnedCommand(command, fixture: fixture), admission = try ownerAdmission(admissionPort, submission: submission, profile: profile)
            try fixture.sql("CREATE TRIGGER reject_terminal_audit BEFORE INSERT ON audit_records_v1 BEGIN SELECT RAISE(ABORT,'injected'); END")
            let now = fixture.now(120)
            XCTAssertThrowsError(try authority.withRequests { try $0.retirePending(requestID: request.requestID, reason: .cancelled, now: now, receiptTimeMs: nil) })
            XCTAssertThrowsError(try receiver(terminalPort).receiveTerminalReply(timeoutMilliseconds: 10)) { XCTAssertEqual($0 as? MachCommandCallerError, .timeout) }
            XCTAssertEqual(try authority.withRequests { try $0.state(requestID: request.requestID).phase }, .queued)
            try fixture.sql("DROP TRIGGER reject_terminal_audit")
            _ = try authority.withRequests { try $0.retirePending(requestID: request.requestID, reason: .cancelled, now: now, receiptTimeMs: nil) }
            XCTAssertEqual(try ownerTerminal(terminalPort, submission: submission, admission: admission).outcome, .cancelledBeforeStart)
        }
    }
    func testIOOwnerCheckpointPrepareOrFinalizeFailureCannotClaimKnownNoEffect() throws {
        for finalize in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: true, owned: true)
            let authority = try XCTUnwrap(fixture.authority), admissionPort = try Endpoint(), terminalPort = try Endpoint()
            let (received, command, submission, profile) = try ownerIOCommand(admission: admissionPort, terminal: terminalPort)
            let request = try admitOwnedCommand(command, fixture: fixture)
            let admission = try ownerAdmission(admissionPort, submission: submission, profile: profile)
            let condition = finalize ? "NEW.pending IS NULL" : "NEW.pending IS NOT NULL"
            try fixture.sql("CREATE TRIGGER fail_terminal_checkpoint BEFORE UPDATE ON continuity_v1 WHEN \(condition) BEGIN SELECT RAISE(ABORT,'injected'); END", continuity: true)
            let now = fixture.now(120)
            XCTAssertThrowsError(try authority.withRequests { try $0.retirePending(requestID: request.requestID, reason: .cancelled, now: now, receiptTimeMs: nil) })
            XCTAssertEqual(try ownerTerminal(terminalPort, submission: submission, admission: admission).outcome, .unknown)
            try expectAssemblyResourcesRetired(received); XCTAssertEqual(try sendReferences(terminalPort.port), 1)
            XCTAssertThrowsError(try authority.withRequests { try $0.state(requestID: request.requestID) })
            XCTAssertThrowsError(try receiver(terminalPort).receiveTerminalReply(timeoutMilliseconds: 10)) { XCTAssertEqual($0 as? MachCommandCallerError, .timeout) }
        }
    }
    func testIOOwnerFatalStorageFailureReportsOnlyUnknownAndReleasesChannels() throws {
        for checkpointed in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true)
            let authority = try XCTUnwrap(fixture.authority), admissionPort = try Endpoint(), terminalPort = try Endpoint()
            let (received, command, submission, profile) = try ownerIOCommand(admission: admissionPort, terminal: terminalPort)
            _ = try admitOwnedCommand(command, fixture: fixture)
            let admission = try ownerAdmission(admissionPort, submission: submission, profile: profile)
            XCTAssertEqual(chmod(fixture.root.appendingPathComponent("store/journal.sqlite").path, 0o644), 0)
            XCTAssertThrowsError(try authority.withRequests { _ in XCTFail("Untrusted storage must not enter the request owner") })
            XCTAssertEqual(try ownerTerminal(terminalPort, submission: submission, admission: admission).outcome, .unknown)
            try expectAssemblyResourcesRetired(received); XCTAssertEqual(try sendReferences(terminalPort.port), 1)
        }
    }
    func testIOOwnerFullTerminalQueueDoesNotDelayOrRollbackCommittedCancellation() throws {
        for checkpointed in [false, true] {
            let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true)
            let authority = try XCTUnwrap(fixture.authority), admissionPort = try Endpoint(), terminalPort = try Endpoint()
            let (received, command, submission, profile) = try ownerIOCommand(admission: admissionPort, terminal: terminalPort)
            let request = try admitOwnedCommand(command, fixture: fixture)
            _ = try ownerAdmission(admissionPort, submission: submission, profile: profile)
            for _ in 0..<5 { try terminalPort.send(Data([1]), identifier: MachCommandCallerReceiver.terminalReplyMessageID) }
            let now = fixture.now(120), started = DispatchTime.now().uptimeNanoseconds
            let state = try authority.withRequests { try $0.retirePending(requestID: request.requestID, reason: .cancelled, now: now, receiptTimeMs: nil) }
            XCTAssertLessThan(DispatchTime.now().uptimeNanoseconds - started, 2_000_000_000)
            XCTAssertEqual(state.phase, .cancelled); XCTAssertEqual(try sendReferences(terminalPort.port), 1)
            try expectAssemblyResourcesRetired(received); XCTAssertNotNil(try fixture.reservation(submission.binding.id))
            for _ in 0..<5 {
                let raw = try receiver(terminalPort).receiveTerminalReply(timeoutMilliseconds: 1000)
                raw.caller.close(); XCTAssertEqual(raw.payload, Data([1]))
            }
            XCTAssertThrowsError(try receiver(terminalPort).receiveTerminalReply(timeoutMilliseconds: 10)) { XCTAssertEqual($0 as? MachCommandCallerError, .timeout) }
            XCTAssertEqual(try authority.withRequests { try $0.state(requestID: request.requestID).phase }, .cancelled)
        }
    }
    func testIOOwnerClosureReportsUnknownOnceWithoutClaimingDurableNoEffect() throws {
        let fixture = try CommandRequestFixture(owned: true)
        let authority = try XCTUnwrap(fixture.authority), admissionPort = try Endpoint(), terminalPort = try Endpoint()
        let (received, command, submission, profile) = try ownerIOCommand(admission: admissionPort, terminal: terminalPort)
        _ = try admitOwnedCommand(command, fixture: fixture)
        let admission = try ownerAdmission(admissionPort, submission: submission, profile: profile)
        try authority.close()
        XCTAssertEqual(try ownerTerminal(terminalPort, submission: submission, admission: admission).outcome, .unknown)
        try expectAssemblyResourcesRetired(received)
        XCTAssertThrowsError(try receiver(terminalPort).receiveTerminalReply(timeoutMilliseconds: 10)) { XCTAssertEqual($0 as? MachCommandCallerError, .timeout) }
    }
    func testIOOwnerGenericVerifiedResultDoesNotInventAChildExitStatus() throws {
        for event: RequestEvent in [.verifySuccess, .verifyFailure] {
            let fixture = try CommandRequestFixture(owned: true)
            let authority = try XCTUnwrap(fixture.authority), admissionPort = try Endpoint(), terminalPort = try Endpoint()
            let (_, command, submission, profile) = try ownerIOCommand(admission: admissionPort, terminal: terminalPort)
            let request = try admitOwnedCommand(command, fixture: fixture), admission = try ownerAdmission(admissionPort, submission: submission, profile: profile)
            _ = try ownerDecision(request, fixture: fixture, decline: false)
            let now = fixture.now(130)
            _ = try authority.withRequests { try $0.recordOutcome(requestID: request.requestID, expectedRevision: 0, event: .beginDispatch, now: now, receiptTimeMs: nil) }
            _ = try authority.withRequests { try $0.recordOutcome(requestID: request.requestID, expectedRevision: 1, event: event, now: now, receiptTimeMs: nil) }
            XCTAssertEqual(try ownerTerminal(terminalPort, submission: submission, admission: admission).outcome, .unknown)
        }
    }
}

extension MachCommandCallerReceiverTests {
    func testIOOwnerClientReceivesCommittedCancellationAndExpiry() throws {
        for checkpointed in [false, true] {
            for expire in [false, true] {
                let endpoint = try Endpoint(), handshake = try admissionClientFixture(endpoint.port, input: 4, wire: 3,
                    mac: Data(repeating: 1, count: 16), account: Data(repeating: 2, count: 16))
                let profile = handshake.profile, submission = try commandSubmission(), expression = try selfExpression()
                let user = geteuid(), limits = try assemblyLimits, target = assemblyTarget, environment = assemblyEnvironment
                let port = endpoint.port, release = DispatchSemaphore(value: 0), completed = DispatchSemaphore(value: 0)
                let result = OSAllocatedUnfairLock(initialState: Result<Void, Error>?.none)
                DispatchQueue.global().async {
                    defer { completed.signal() }
                    result.withLock { output in output = Result {
                        let fixture = try CommandRequestFixture(checkpointed: checkpointed, owned: true)
                        let authority = try XCTUnwrap(fixture.authority)
                        let receiver = try MachCommandCallerReceiver(receivePort: port, expression: expression,
                            userID: user, auditSessionID: nil, maxPayloadBytes: 8192)
                        let received = try receiver.receiveIOInput(timeoutMilliseconds: 5000)
                        let command = try RetainedCommandCapture(received: received, expectedCallerBinding: profile.callerBinding,
                            submissionSchemaVersion: 1, captureSchemaVersion: 1, expression: expression, userID: user,
                            auditSessionID: nil, resolvedTarget: target, minimalEnvironment: environment,
                            streamBinding: Data(repeating: 0xb4, count: 16), submissionLimits: limits, captureLimits: limits,
                            maximumAncestryEntries: 1, admissionProfile: profile)
                        let draft = fixture.draft(command)
                        let request = try authority.admitCommand(command, draft: draft, expression: expression,
                            userID: user, auditSessionID: nil, now: { fixture.now() }, receiptTimeMs: nil)
                        guard release.wait(timeout: .now() + 5) == .success else { throw MachCommandCallerError.timeout }
                        let now = fixture.now(expire ? 200 : 120)
                        _ = try authority.withRequests { try $0.retirePending(requestID: request.requestID,
                            reason: expire ? .deadlineElapsed : .cancelled, now: now, receiptTimeMs: nil) }
                    } }
                }
                defer { release.signal() }
                let input = Darwin.open("/dev/null", O_RDONLY), output = Darwin.open("/dev/null", O_WRONLY)
                defer { _ = Darwin.close(input); _ = Darwin.close(output) }
                let admission: CommandIOAdmission
                do {
                    admission = try MachCommandIOClient.submit(submission, inputDescriptor: input, outputDescriptor: output,
                        errorDescriptor: output, handshake: handshake, expression: expression, userID: user,
                        auditSessionID: nil, maximumPayloadBytes: 8192)
                } catch {
                    release.signal(); XCTAssertEqual(completed.wait(timeout: .now() + 5), .success)
                    try result.withLock { try $0?.get() }
                    throw error
                }
                guard case .admitted(let session) = admission else { return XCTFail("The command owner must admit the original submission") }
                XCTAssertNil(try session.pollTerminalResult(timeoutMilliseconds: 10))
                release.signal(); XCTAssertEqual(completed.wait(timeout: .now() + 5), .success)
                try result.withLock { try $0?.get() }
                let terminal = try XCTUnwrap(session.pollTerminalResult(timeoutMilliseconds: 1000))
                XCTAssertEqual(terminal.outcome, expire ? .expired : .cancelledBeforeStart)
                guard case .admitted(let expected) = session.admission.outcome else { return XCTFail("The session must retain its admission") }
                XCTAssertEqual(terminal.request, expected); XCTAssertEqual(terminal.submission, submission.binding)
                XCTAssertEqual(try session.pollTerminalResult()?.outcome, terminal.outcome)
                session.close()
                XCTAssertThrowsError(try receiver(endpoint).receiveIOInput(timeoutMilliseconds: 10)) { XCTAssertEqual($0 as? MachCommandCallerError, .timeout) }
            }
        }
    }
}
