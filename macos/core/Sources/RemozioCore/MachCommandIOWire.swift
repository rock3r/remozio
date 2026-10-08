import Darwin
import Foundation

/// Internal transport primitive. The authenticated client must verify Root before calling it.
enum MachCommandIOWire {
    static func send(_ bytes: Data, inputDescriptor: Int32, outputDescriptor: Int32, errorDescriptor: Int32,
                     destination: mach_port_t, admissionReply: mach_port_t, terminalReply: mach_port_t,
                     maximumPayloadBytes: Int, timeoutMilliseconds: UInt32) throws {
        guard [destination, admissionReply, terminalReply].allSatisfy({ $0 != MACH_PORT_NULL && $0 != UInt32.max }),
              maximumPayloadBytes > 0, maximumPayloadBytes <= Int(UInt32.max) - 1024,
              !bytes.isEmpty, bytes.count <= maximumPayloadBytes, (1...60_000).contains(timeoutMilliseconds) else {
            throw MachCommandHandshakeError.invalidConfiguration
        }
        var fileports: [mach_port_t] = []
        defer { for port in fileports { _ = mach_port_deallocate(mach_task_self_, port) } }
        for (index, descriptor) in [inputDescriptor, outputDescriptor, errorDescriptor].enumerated() {
            let flags = fcntl(descriptor, F_GETFL)
            guard flags >= 0 else { throw RetainedCommandInputError.system(errno) }
            if index == 0 {
                guard flags & O_ACCMODE != O_WRONLY, flags & O_EVTONLY == 0 else { throw RetainedCommandInputError.notReadable }
            } else {
                guard flags & O_ACCMODE != O_RDONLY, flags & O_EVTONLY == 0 else { throw RetainedCommandOutputError.notWritable }
            }
            var port: mach_port_t = 0
            guard fileport_makeport(descriptor, &port) == 0 else { throw RetainedCommandInputError.system(errno) }
            fileports.append(port)
        }
        let ports = fileports + [admissionReply, terminalReply]
        let headerBytes = MemoryLayout<mach_msg_header_t>.size, bodyBytes = MemoryLayout<mach_msg_body_t>.size
        let descriptorBytes = MemoryLayout<mach_msg_port_descriptor_t>.size
        let metadata = headerBytes + bodyBytes + ports.count * descriptorBytes
        let size = (metadata + 8 + bytes.count + 3) & ~3
        let storage = UnsafeMutableRawPointer.allocate(byteCount: size, alignment: 8)
        defer { storage.deallocate() }
        storage.initializeMemory(as: UInt8.self, repeating: 0, count: size)
        let header = storage.bindMemory(to: mach_msg_header_t.self, capacity: 1)
        header.pointee.msgh_bits = UInt32(MACH_MSG_TYPE_COPY_SEND) | MACH_MSGH_BITS_COMPLEX
        header.pointee.msgh_size = UInt32(size); header.pointee.msgh_remote_port = destination
        header.pointee.msgh_id = MachCommandCallerReceiver.ioInputMessageID
        storage.storeBytes(of: mach_msg_body_t(msgh_descriptor_count: UInt32(ports.count)), toByteOffset: headerBytes, as: mach_msg_body_t.self)
        for (index, port) in ports.enumerated() {
            var descriptor = mach_msg_port_descriptor_t()
            descriptor.name = port; descriptor.disposition = UInt32(MACH_MSG_TYPE_COPY_SEND); descriptor.type = UInt32(MACH_MSG_PORT_DESCRIPTOR)
            storage.storeBytes(of: descriptor, toByteOffset: headerBytes + bodyBytes + index * descriptorBytes, as: mach_msg_port_descriptor_t.self)
        }
        storage.storeBytes(of: MachCommandCallerReceiver.ioInputCarrierVersion.bigEndian, toByteOffset: metadata, as: UInt32.self)
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
