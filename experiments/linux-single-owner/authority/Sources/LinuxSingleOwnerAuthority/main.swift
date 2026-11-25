import CSingleOwnerAuthority
import Foundation
import Glibc
import LinuxApprovalFixtureCore
import RemozioHostCore
import RemozioProtocol

#if !DEBUG
#error("This disposable single-owner authority is debug-only")
#endif

// The authority A of the single-owner experiment (issue #988, PR2). It speaks the line protocol of
// owner.c over an inherited SEQPACKET listener:
//
//   HELLO <boot-id> <pid> <start-time> <random>  -> OK | REFUSED   (O's generation, checked through SO_PEERPIDFD)
//   SUBMIT <nonce> <caller-pid>                  -> PERMIT <token> <uid> <gid> <mode> <count> <groups...> | REFUSED
//   OUTCOME <token> <result> <lost>              -> OK | REFUSED
//
// Each SUBMIT gets a new FixtureStore: the signed decision is verified and consumed, and the durable
// beginDispatch is written, in the store's SQLite transaction, before the one-use permit goes out. The
// capture is synthetic (the requester, streams and decision keys are fixture data); it binds the command
// image, the directory and the target identity. Reports go to stdout as JSON lines of closed-set strings.
// The authority ends at end of file on stdin.
//
// usage: LinuxSingleOwnerAuthority <listen-fd> <store-root> <owner-uid> <command> <frontend> <marker>
//                                  <target-uid> <target-gid> <groups|-> <modes>

enum Closed {
    static let modes: Set<String> = ["normal", "short", "sleep", "missing", "khang", "kpause"]
    static let results: Set<String> = ["dispatched", "execFailed", "unknown", "notStarted", "refused"]
    static let phases: Set<String> = Set(RequestPhase.allCases.map(\.rawValue))
}

extension Data {
    var hex: String { map { String(format: "%02x", $0) }.joined() }
}

func isHex32(_ text: Substring) -> Bool {
    text.utf8.count == 32 && text.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
}

func emit(_ fields: [String: String]) {
    let body = fields.keys.sorted().map { "\"\($0)\":\"\(fields[$0]!)\"" }.joined(separator: ",")
    if csa_line("{" + body + "}") != 0 { exit(2) }
}

struct Configuration {
    let listener: Int32
    let storeRoot: String
    let ownerUID: UInt32
    let command: String
    let frontend: String
    let marker: String
    let targetUID: UInt32
    let targetGID: UInt32
    let groups: [UInt32]
    let modes: [String]

    init(_ arguments: [String]) throws {
        try require(arguments.count == 11, "usage")
        guard let listener = Int32(arguments[1]), listener > 2, let owner = UInt32(arguments[3]),
              let uid = UInt32(arguments[7]), let gid = UInt32(arguments[8]) else { throw FixtureError.failed("usage") }
        var groups: [UInt32] = []
        if arguments[9] != "-" {
            for item in arguments[9].split(separator: ",") {
                guard let value = UInt32(item) else { throw FixtureError.failed("usage") }
                groups.append(value)
            }
        }
        let modes = arguments[10].split(separator: ",").map(String.init)
        try require(groups == Array(Set(groups)).sorted() && groups.count <= 64, "groups")
        try require(!modes.isEmpty && modes.count <= 4 && modes.allSatisfy { Closed.modes.contains($0) }, "modes")
        for path in [arguments[2], arguments[4], arguments[5], arguments[6]] {
            try require(path.hasPrefix("/") && !path.contains(" "), "paths")
        }
        self.listener = listener
        storeRoot = arguments[2]
        ownerUID = owner
        command = arguments[4]
        frontend = arguments[5]
        marker = arguments[6]
        targetUID = uid
        targetGID = gid
        self.groups = groups
        self.modes = modes
    }
}

struct Generation: Equatable {
    let boot: String
    let pid: Int32
    let start: UInt64
    let random: String
}

final class Connection {
    let descriptor: Int32
    let uid: UInt32
    let pid: Int32
    let pidfd: Int32
    var generation: Generation?

    init(descriptor: Int32, uid: UInt32, pid: Int32, pidfd: Int32) {
        self.descriptor = descriptor
        self.uid = uid
        self.pid = pid
        self.pidfd = pidfd
    }

    deinit {
        _ = close(pidfd)
        _ = close(descriptor)
    }
}

final class Permit {
    let generation: Generation
    let store: FixtureStore
    var used = false

    init(generation: Generation, store: FixtureStore) {
        self.generation = generation
        self.store = store
    }
}

func bootID() -> String? {
    var buffer = [CChar](repeating: 0, count: 40)
    guard csa_boot_id(&buffer, buffer.count) == 0 else { return nil }
    return String(cString: buffer)
}

func startTime(_ pid: Int32) -> UInt64? {
    var value: UInt64 = 0
    return csa_start_time(pid, &value) == 0 ? value : nil
}

/// The pidfd's process has not exited (a zombie has: its pidfd is readable), the pidfd still names the
/// generation's PID, and that PID still has the generation's start time.
func live(_ generation: Generation, _ pidfd: Int32) -> Bool {
    generation.boot == bootID() && csa_pidfd_alive(pidfd) == 1 && csa_pidfd_pid(pidfd) == generation.pid
        && startTime(generation.pid) == generation.start && csa_pidfd_pid(pidfd) == generation.pid
}

func identity(_ descriptor: Int32) throws -> CapturedFileIdentity {
    var value = stat()
    try require(fstat(descriptor, &value) == 0, "fstat")
    return .init(device: UInt64(value.st_dev), inode: UInt64(value.st_ino))
}

func identity(_ path: String) throws -> CapturedFileIdentity {
    let descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
    try require(descriptor >= 0, "openIdentity")
    defer { close(descriptor) }
    return try identity(descriptor)
}

func observeExecutable(_ path: String) throws -> CapturedExecutable {
    .init(path: Data(path.utf8), identity: try identity(path), sha256: digest(try Data(contentsOf: URL(fileURLWithPath: path))))
}

final class Authority {
    let configuration: Configuration
    let clock: LinuxAuthorityClock
    var permits: [String: Permit] = [:]
    var submissions: [String: (store: FixtureStore, material: FixtureApprovalMaterial)] = [:]
    /// Store directories are numbered by attempt, not by permit: a failed SUBMIT leaves its directory,
    /// and the next attempt must not collide with it.
    var attempts = 0
    /// Mode slots are taken by issued permits only: a SUBMIT that fails, before or after its decision is
    /// consumed, leaves the slot to the next request.
    var issued = 0

    init(_ configuration: Configuration) throws {
        self.configuration = configuration
        clock = try LinuxAuthorityClock()
    }

    /// A synthetic capture: the command image, the directory and the target are bound; the requester,
    /// the streams (identities of pipes made here) and the decision keys are fixture data.
    func capture(callerPID: UInt32, mode: String) throws -> LinuxCommandCapture {
        var pair: [Int32] = [-1, -1]
        try require(pipe(&pair) == 0, "pipe")
        defer { for fd in pair where fd >= 0 { _ = close(fd) } }
        func stream(_ fd: Int32) throws -> CapturedCommandInput {
            .init(kind: .pipe, streamBinding: randomBytes(16), observedPath: nil, identity: try identity(fd))
        }
        let input = try stream(pair[0]), output = try stream(pair[1]), error = try stream(pair[1])
        let c = configuration
        let credentials = CapturedLinuxCredentials(realUID: c.targetUID, effectiveUID: c.targetUID,
            savedUID: c.targetUID, filesystemUID: c.targetUID, realGID: c.targetGID, effectiveGID: c.targetGID,
            savedGID: c.targetGID, filesystemGID: c.targetGID, supplementaryGroups: c.groups)
        return try LinuxCommandCapture(executable: observeExecutable(c.command),
            arguments: [c.command, mode, c.marker].map { Data($0.utf8) },
            directory: .init(path: Data("/".utf8), identity: identity("/")),
            target: .init(uid: c.targetUID, gid: c.targetGID, supplementaryGroups: c.groups, observedName: nil),
            environment: [.init(name: Data("LANG".utf8), value: Data("C".utf8), source: .minimal)],
            input: input, requester: .init(pid: callerPID, processBinding: randomBytes(16),
                monitorIncarnation: randomBytes(16), execEpoch: 1,
                executable: observeExecutable(c.frontend), credentials: credentials,
                sessionID: nil, codePolicyDigest: digest(Data("synthetic single-owner policy".utf8))),
            unverifiedRationale: "Disposable single-owner fixture; synthetic requester, streams and keys",
            submission: .init(id: randomBytes(16), nonce: randomBytes(32), callerBinding: randomBytes(16)),
            stdioLayout: .init(input: .init(source: input, access: .readOnly, flags: []),
                output: .init(source: output, access: .writeOnly, flags: []),
                error: .init(source: error, access: .writeOnly, flags: []), terminal: nil, ptyMask: 0),
            limits: FixtureProtocol.limits)
    }

    func phase(_ store: FixtureStore) -> String {
        guard let value = try? store.snapshot().phase else { return "unreadable" }
        return Closed.phases.contains(value) ? value : "other"
    }

    func hello(_ connection: Connection, _ words: [Substring]) -> String {
        guard connection.generation == nil, words.count == 5, isHex32(words[4]), let pid = Int32(words[2]),
              let start = UInt64(words[3]), let boot = bootID(), String(words[1]) == boot,
              pid == connection.pid else {
            emit(["event": "hello", "result": "refused"])
            return "REFUSED"
        }
        let generation = Generation(boot: boot, pid: pid, start: start, random: String(words[4]))
        guard live(generation, connection.pidfd) else {
            emit(["event": "hello", "result": "refused"])
            return "REFUSED"
        }
        connection.generation = generation
        emit(["event": "hello", "result": "accepted"])
        return "OK"
    }

    func submit(_ connection: Connection, _ words: [Substring]) -> String {
        func refuse(_ reason: String) -> String {
            emit(["event": "submit", "result": "refused", "reason": reason])
            return "REFUSED"
        }
        guard let generation = connection.generation else { return refuse("no-generation") }
        guard words.count == 3, isHex32(words[1]), let callerPID = UInt32(words[2]), callerPID > 0 else {
            return refuse("malformed")
        }
        guard live(generation, connection.pidfd) else { return refuse("generation-lost") }
        let nonce = String(words[1])
        if let previous = submissions[nonce] {
            // A replay: the same signed decision goes to the same store again, and its ledger must refuse it.
            // Only the ledger's own refusal counts; an expired decision or a store error is "error".
            var ledger = "accepted"
            do { _ = try previous.store.consume(previous.material, validate: { _ in }, now: clock.now) }
            catch ConsumptionJournalError.alreadyConsumed { ledger = "refused" }
            catch { ledger = "error" }
            emit(["event": "submit", "result": "replay-refused", "ledger": ledger, "phase": phase(previous.store)])
            return "REFUSED"
        }
        guard issued < configuration.modes.count, attempts < 16 else { return refuse("no-more-requests") }
        let mode = configuration.modes[issued]
        attempts += 1
        // A refused SUBMIT drops its only reference to the store, and FixtureStore closes its SQLite
        // handle in deinit.
        do {
            let directory = configuration.storeRoot + "/request-\(attempts)"
            try require(mkdir(directory, 0o700) == 0, "storeDirectory")
            let store = try FixtureStore(directory: directory, reopening: false)
            let retained = try capture(callerPID: callerPID, mode: mode)
            let material = try FixtureProtocol.make(capture: retained.canonicalBytes, clock: clock)
            let pidfd = connection.pidfd
            guard let token = try store.consume(material, validate: { decoded in
                try require(decoded == retained, "retainedCaptureMismatch")
                try require(live(generation, pidfd), "generationLost")
            }, now: clock.now) else { return refuse("declined") }
            // The decision is consumed in this store: from now on a replay of the nonce must reach this
            // store's ledger, even when beginDispatch below fails and no permit goes out.
            submissions[nonce] = (store, material)
            do { try store.dispatched(token) } catch { return refuse("store") }
            issued += 1
            let permit = randomBytes(16).hex
            permits[permit] = Permit(generation: generation, store: store)
            emit(["event": "submit", "result": "permit", "phase": phase(store)])
            let c = configuration
            return (["PERMIT", permit, String(c.targetUID), String(c.targetGID), mode, String(c.groups.count)]
                    + c.groups.map(String.init)).joined(separator: " ")
        } catch {
            return refuse("store")
        }
    }

    func outcome(_ connection: Connection, _ words: [Substring]) -> String {
        guard let generation = connection.generation, words.count == 4, let permit = permits[String(words[1])] else {
            emit(["event": "outcome", "result": "refused"])
            return "REFUSED"
        }
        guard permit.generation == generation, live(generation, connection.pidfd) else {
            emit(["event": "outcome", "result": "generation-refused"])
            return "REFUSED"
        }
        let result = String(words[2]), lost = String(words[3])
        guard Closed.results.contains(result), lost == "yes" || lost == "no" else {
            emit(["event": "outcome", "result": "refused"])
            return "REFUSED"
        }
        guard !permit.used else {
            emit(["event": "outcome", "result": "replay-refused", "phase": phase(permit.store)])
            return "REFUSED"
        }
        permit.used = true
        // beginDispatch is already durable, so the request is executing. The lifecycle has no transition
        // from executing to a proved no-dispatch, so a dispatch that ended without a command is a failure.
        // The record keeps the reason: a production authority needs a distinct outcome for notStarted.
        do {
            switch result {
            case "dispatched": try permit.store.succeeded()
            case "unknown": try permit.store.lostOutcome()
            default: try permit.store.failed()
            }
        } catch {
            emit(["event": "outcome", "result": "store-refused", "reported": result, "phase": phase(permit.store)])
            return "REFUSED"
        }
        let reason = result == "dispatched" || result == "unknown" ? "none" : result
        emit(["event": "outcome", "result": "recorded", "reported": result, "reason": reason,
              "requesterLost": lost, "phase": phase(permit.store)])
        return "OK"
    }

    func handle(_ connection: Connection, _ message: String) -> String {
        guard connection.uid == configuration.ownerUID else {
            emit(["event": "message", "result": "wrong-peer"])
            return "REFUSED"
        }
        let words = message.split(separator: " ", omittingEmptySubsequences: false)
        switch words.first.map(String.init) ?? "" {
        case "HELLO": return hello(connection, words)
        case "SUBMIT": return submit(connection, words)
        case "OUTCOME": return outcome(connection, words)
        default:
            emit(["event": "message", "result": "refused"])
            return "REFUSED"
        }
    }
}

func run() throws {
    let configuration = try Configuration(CommandLine.arguments)
    let authority = try Authority(configuration)
    var connections: [Int32: Connection] = [:]
    emit(["event": "start"])
    while true {
        let descriptors: [Int32] = [0, configuration.listener] + connections.keys.sorted()
        let index = descriptors.withUnsafeBufferPointer { csa_poll($0.baseAddress, Int32($0.count), 1000) }
        try require(index != -2, "poll")
        if index < 0 { continue }
        let ready = descriptors[Int(index)]
        if ready == 0 {
            var byte: UInt8 = 0
            if read(0, &byte, 1) <= 0 {
                emit(["event": "end"])
                return
            }
        } else if ready == configuration.listener {
            let descriptor = csa_accept(configuration.listener)
            guard descriptor >= 0 else { continue }
            var uid: UInt32 = 0, pid: Int32 = 0, pidfd: Int32 = -1
            guard connections.count < 16, csa_peer(descriptor, &uid, &pid, &pidfd) == 0 else {
                emit(["event": "peer", "result": "refused"])
                _ = close(descriptor)
                continue
            }
            connections[descriptor] = Connection(descriptor: descriptor, uid: uid, pid: pid, pidfd: pidfd)
            emit(["event": "peer", "result": uid == configuration.ownerUID ? "owner" : "wrong-uid"])
        } else if let connection = connections[ready] {
            var buffer = [CChar](repeating: 0, count: 1024)
            let length = csa_recv(ready, &buffer, buffer.count)
            guard length > 0 else {
                connections[ready] = nil
                continue
            }
            let reply = authority.handle(connection, String(cString: buffer))
            if csa_send(ready, reply, reply.utf8.count) != 0 { connections[ready] = nil }
        }
    }
}

do {
    try run()
} catch {
    emit(["event": "error"])
    exit(2)
}
