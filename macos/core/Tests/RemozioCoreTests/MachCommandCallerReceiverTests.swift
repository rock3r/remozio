import Darwin
import Foundation
import RemozioMach
import RemozioProtocol
import Security
import XCTest
@testable import RemozioCore

final class MachCommandCallerReceiverTests: XCTestCase {
    private final class Endpoint {
        var port: mach_port_t = 0
        init() throws {
            guard mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &port) == KERN_SUCCESS,
                  mach_port_insert_right(mach_task_self_, port, port, UInt32(MACH_MSG_TYPE_MAKE_SEND)) == KERN_SUCCESS else {
                throw MachCommandCallerError.configuration
            }
        }
        deinit {
            _ = mach_port_mod_refs(mach_task_self_, port, MACH_PORT_RIGHT_RECEIVE, -1)
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

        func sendInput(_ payload: Data, fileport: mach_port_t, version: UInt32 = 2, descriptorCount: Int = 1) throws {
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
            header.pointee.msgh_id = MachCommandCallerReceiver.inputMessageID
            storage.storeBytes(of: mach_msg_body_t(msgh_descriptor_count: UInt32(descriptorCount)),
                toByteOffset: headerBytes, as: mach_msg_body_t.self)
            for index in 0..<descriptorCount {
                var descriptor = mach_msg_port_descriptor_t()
                descriptor.name = fileport
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

    private func inputSubmission(_ fd: Int32) throws -> ReceivedMachCommandInputSubmission {
        let endpoint = try Endpoint()
        var fileport: mach_port_t = UInt32(MACH_PORT_NULL)
        guard fileport_makeport(fd, &fileport) == 0 else { throw RetainedCommandInputError.system(errno) }
        defer { _ = mach_port_deallocate(mach_task_self_, fileport) }
        try endpoint.sendInput(Data([1]), fileport: fileport)
        return try receiver(endpoint).receiveInput(timeoutMilliseconds: 1000)
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
        var selfToken = audit_token_t()
        XCTAssertEqual(remozio_pid_audit_token(getpid(), &selfToken), KERN_SUCCESS)
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
}
