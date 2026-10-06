import Darwin
import Foundation
import RemozioMach
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
    }

    func testRejectedComplexPacketReleasesImportedSendRight() throws {
        let endpoint = try Endpoint(), carried = try Endpoint(), receiver = try receiver(endpoint)
        var baseline: mach_port_urefs_t = 0
        XCTAssertEqual(mach_port_get_refs(mach_task_self_, carried.port, MACH_PORT_RIGHT_SEND, &baseline), KERN_SUCCESS)
        let size = MemoryLayout<mach_msg_header_t>.size + MemoryLayout<mach_msg_body_t>.size + MemoryLayout<mach_msg_port_descriptor_t>.size
        let storage = UnsafeMutableRawPointer.allocate(byteCount: size, alignment: MemoryLayout<mach_msg_header_t>.alignment)
        defer { storage.deallocate() }
        storage.initializeMemory(as: UInt8.self, repeating: 0, count: size)
        let header = storage.bindMemory(to: mach_msg_header_t.self, capacity: 1)
        header.pointee.msgh_bits = UInt32(MACH_MSG_TYPE_COPY_SEND) | MACH_MSGH_BITS_COMPLEX
        header.pointee.msgh_size = UInt32(size)
        header.pointee.msgh_remote_port = endpoint.port
        header.pointee.msgh_id = MachCommandCallerReceiver.messageID
        storage.storeBytes(of: mach_msg_body_t(msgh_descriptor_count: 1), toByteOffset: MemoryLayout<mach_msg_header_t>.size, as: mach_msg_body_t.self)
        var descriptor = mach_msg_port_descriptor_t()
        descriptor.name = carried.port
        descriptor.disposition = UInt32(MACH_MSG_TYPE_COPY_SEND)
        descriptor.type = UInt32(MACH_MSG_PORT_DESCRIPTOR)
        storage.storeBytes(of: descriptor, toByteOffset: MemoryLayout<mach_msg_header_t>.size + MemoryLayout<mach_msg_body_t>.size, as: mach_msg_port_descriptor_t.self)
        XCTAssertEqual(mach_msg(header, MACH_SEND_MSG | MACH_SEND_TIMEOUT, UInt32(size), 0, 0, 1000, 0), KERN_SUCCESS)
        XCTAssertThrowsError(try receiver.receive(timeoutMilliseconds: 1000)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .malformed)
        }
        var final: mach_port_urefs_t = 0
        XCTAssertEqual(mach_port_get_refs(mach_task_self_, carried.port, MACH_PORT_RIGHT_SEND, &final), KERN_SUCCESS)
        XCTAssertEqual(final, baseline)
        try endpoint.send(Data([1]))
        XCTAssertEqual(try receiver.receive(timeoutMilliseconds: 1000).payload, Data([1]))
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
