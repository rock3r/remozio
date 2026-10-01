import CryptoKit
import Darwin
import Foundation
import SQLite3

enum Failure: String, Error { case usage, storage, busy, identityChanged, inconsistent, duplicate }
func require(_ condition: Bool, _ error: Failure = .storage) throws { if !condition { throw error } }
func canonicalJSON<T: Encodable>(_ value: T) throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    return try encoder.encode(value)
}
func digest(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
struct Head: Codable, Equatable {
    let sequence: Int64
    let digest: String
    static let empty = Head(sequence: 0, digest: String(repeating: "0", count: 64))
}
enum Outcome: String, Codable { case consumed, noDispatch, unknown }
struct Event: Codable, Equatable {
    let sequence: Int64
    let previousDigest: String
    let request: UUID
    let phone: UUID
    let outcome: Outcome
    var head: Head { get throws { Head(sequence: sequence, digest: digest(try canonicalJSON(self))) } }
}
struct Checkpoint: Codable { let stable: Head; let pending: Event? }
struct Consumption: Equatable { let phone: UUID; let outcome: Outcome; let sequence: Int64 }

final class Store {
    private let directory: String
    private let directoryFD: Int32
    private let lockFD: Int32
    private let dbFD: Int32
    private var db: OpaquePointer?
    private let crash: String?
    private let pause: String?
    private var head = Head.empty
    private var ledger: [UUID: Consumption] = [:]

    init(directory: String, create: Bool, crash: String?, pause: String?) throws {
        self.directory = directory
        self.crash = crash
        self.pause = pause
        if create { try require(mkdir(directory, 0o700) == 0) }
        directoryFD = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        try require(directoryFD >= 0)
        lockFD = openat(directoryFD, "writer.lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
        try require(lockFD >= 0)
        try require(flock(lockFD, LOCK_EX | LOCK_NB) == 0, .busy)
        dbFD = openat(directoryFD, "journal.sqlite", O_RDWR | O_NOFOLLOW | O_CLOEXEC | (create ? O_CREAT | O_EXCL : 0), 0o600)
        try require(dbFD >= 0)
        try checkIdentity()
        let rc = sqlite3_open_v2(directory + "/journal.sqlite", &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_NOFOLLOW, nil)
        try require(rc == SQLITE_OK)
        try exec("PRAGMA journal_mode=DELETE")
        try exec("PRAGMA synchronous=EXTRA")
        try exec("PRAGMA fullfsync=ON")
        try exec("PRAGMA trusted_schema=OFF")
        try exec("PRAGMA foreign_keys=ON")
        try require(try scalar("PRAGMA synchronous") == "3")
        try require(try scalar("PRAGMA fullfsync") == "1")
        try require(try scalar("PRAGMA journal_mode") == "delete")
        if create {
            try exec("BEGIN IMMEDIATE")
            try exec("CREATE TABLE events (sequence INTEGER PRIMARY KEY, payload TEXT NOT NULL, digest TEXT NOT NULL) STRICT")
            try exec("CREATE TABLE consumptions (request TEXT PRIMARY KEY, phone TEXT NOT NULL, outcome TEXT NOT NULL, sequence INTEGER NOT NULL REFERENCES events(sequence)) STRICT")
            try exec("PRAGMA user_version=1")
            try exec("COMMIT")
            try save(Checkpoint(stable: .empty, pending: nil))
        }
        try require(try scalar("PRAGMA user_version") == "1", .inconsistent)
        try checkIdentity()
    }
    deinit {
        sqlite3_close(db)
        close(dbFD)
        close(lockFD)
        close(directoryFD)
    }

    private func checkIdentity() throws {
        var held = stat(), named = stat()
        try require(fstat(directoryFD, &held) == 0 && lstat(directory, &named) == 0, .identityChanged)
        try require(held.st_dev == named.st_dev && held.st_ino == named.st_ino && (named.st_mode & S_IFMT) == S_IFDIR,
                    .identityChanged)
        try require(held.st_uid == getuid() && held.st_mode & 0o077 == 0, .identityChanged)
        for (fd, name) in [(lockFD, "writer.lock"), (dbFD, "journal.sqlite")] {
            try require(fstat(fd, &held) == 0 && fstatat(directoryFD, name, &named, AT_SYMLINK_NOFOLLOW) == 0, .identityChanged)
            try require(held.st_dev == named.st_dev && held.st_ino == named.st_ino && named.st_nlink == 1 &&
                named.st_mode & S_IFMT == S_IFREG && named.st_uid == getuid() && named.st_mode & 0o077 == 0, .identityChanged)
        }
    }
    private func rows(_ sql: String, _ parameters: [String] = []) throws -> [[String]] {
        var statement: OpaquePointer?
        try require(sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK)
        defer { sqlite3_finalize(statement) }
        for (index, value) in parameters.enumerated() {
            let result = value.withCString { sqlite3_bind_text(statement, Int32(index + 1), $0, -1, unsafeBitCast(-1, to: sqlite3_destructor_type.self)) }
            try require(result == SQLITE_OK)
        }
        var result: [[String]] = []
        while true {
            let status = sqlite3_step(statement)
            if status == SQLITE_DONE { return result }
            try require(status == SQLITE_ROW)
            var row: [String] = []
            for column in 0..<sqlite3_column_count(statement) {
                guard let text = sqlite3_column_text(statement, column) else { throw Failure.inconsistent }
                row.append(String(cString: text))
            }
            result.append(row)
        }
    }
    private func exec(_ sql: String, _ parameters: [String] = []) throws { _ = try rows(sql, parameters) }
    private func scalar(_ sql: String) throws -> String { try rows(sql).first?.first ?? "" }

    private func save(_ checkpoint: Checkpoint) throws {
        try checkIdentity()
        let bytes = try canonicalJSON(checkpoint)
        let name = "checkpoint-" + UUID().uuidString + ".tmp"
        let fd = openat(directoryFD, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        try require(fd >= 0)
        defer { close(fd); unlinkat(directoryFD, name, 0) }
        try bytes.withUnsafeBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                let count = write(fd, buffer.baseAddress!.advanced(by: offset), buffer.count - offset)
                if count < 0 && errno == EINTR { continue }
                try require(count > 0)
                offset += count
            }
        }
        try require(fcntl(fd, F_FULLFSYNC) == 0)
        try require(renameat(directoryFD, name, directoryFD, "checkpoint.json") == 0)
        try require(fsync(directoryFD) == 0)
        try checkIdentity()
    }
    private func checkpoint() throws -> Checkpoint {
        let fd = openat(directoryFD, "checkpoint.json", O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        try require(fd >= 0)
        defer { close(fd) }
        var info = stat()
        try require(fstat(fd, &info) == 0 && info.st_size > 0 && info.st_size <= 4096 && info.st_nlink == 1 &&
            info.st_mode & S_IFMT == S_IFREG && info.st_uid == getuid() && info.st_mode & 0o077 == 0, .inconsistent)
        var bytes = Data(count: Int(info.st_size))
        let count = bytes.withUnsafeMutableBytes { read(fd, $0.baseAddress, $0.count) }
        try require(count == bytes.count)
        let result = try JSONDecoder().decode(Checkpoint.self, from: bytes)
        try require(try canonicalJSON(result) == bytes, .inconsistent)
        return result
    }
    private func boundary(_ name: String) throws {
        if crash == name { _exit(86) }
        if pause == name {
            print("paused:" + name)
            fflush(stdout)
            var byte: UInt8 = 0
            _ = read(STDIN_FILENO, &byte, 1)
        }
        try checkIdentity()
    }
    private func apply(_ event: Event, to state: inout [UUID: Consumption]) throws {
        if event.outcome == .consumed {
            try require(state[event.request] == nil, .duplicate)
        } else {
            try require(state[event.request]?.outcome == .consumed && state[event.request]?.phone == event.phone, .inconsistent)
        }
        state[event.request] = Consumption(phone: event.phone, outcome: event.outcome, sequence: event.sequence)
    }
    private func validate() throws {
        head = .empty
        ledger = [:]
        for row in try rows("SELECT sequence,payload,digest FROM events ORDER BY sequence") {
            let bytes = Data(row[1].utf8)
            let event = try JSONDecoder().decode(Event.self, from: bytes)
            try require(head.sequence < Int64.max && event.sequence == head.sequence + 1 && row[0] == String(event.sequence) &&
                event.previousDigest == head.digest && row[2] == digest(bytes), .inconsistent)
            try require(try canonicalJSON(event) == bytes, .inconsistent)
            try apply(event, to: &ledger)
            head = try event.head
        }
        var stored: [UUID: Consumption] = [:]
        for row in try rows("SELECT request,phone,outcome,sequence FROM consumptions") {
            guard let request = UUID(uuidString: row[0]), let phone = UUID(uuidString: row[1]),
                  let outcome = Outcome(rawValue: row[2]), let sequence = Int64(row[3]) else { throw Failure.inconsistent }
            try require(stored[request] == nil, .inconsistent)
            stored[request] = Consumption(phone: phone, outcome: outcome, sequence: sequence)
        }
        try require(stored == ledger, .inconsistent)
    }
    private func checkCurrentJournal() throws {
        let expected = head
        try validate()
        try require(head == expected, .inconsistent)
    }
    private func commit(_ event: Event) throws {
        var next = ledger
        try apply(event, to: &next)
        try exec("BEGIN IMMEDIATE")
        do {
            try exec("INSERT INTO events(sequence,payload,digest) VALUES(?,?,?)", [String(event.sequence), String(decoding: canonicalJSON(event), as: UTF8.self), try event.head.digest])
            try boundary("after-audit-insert")
            if event.outcome == .consumed {
                try exec("INSERT INTO consumptions(request,phone,outcome,sequence) VALUES(?,?,?,?)", [event.request.uuidString, event.phone.uuidString, event.outcome.rawValue, String(event.sequence)])
            } else {
                try exec("UPDATE consumptions SET outcome=?,sequence=? WHERE request=? AND phone=? AND outcome='consumed'",
                    [event.outcome.rawValue, String(event.sequence), event.request.uuidString, event.phone.uuidString])
                try require(sqlite3_changes(db) == 1, .inconsistent)
            }
            try boundary("before-database-commit")
            try exec("COMMIT")
        } catch { try? exec("ROLLBACK"); throw error }
        ledger = next
        head = try event.head
    }
    private func append(request: UUID, phone: UUID, outcome: Outcome) throws {
        try checkIdentity()
        try require(head.sequence < Int64.max, .inconsistent)
        let event = Event(sequence: head.sequence + 1, previousDigest: head.digest, request: request, phone: phone, outcome: outcome)
        var next = ledger
        try apply(event, to: &next)
        try boundary("before-intent")
        try checkCurrentJournal()
        try save(Checkpoint(stable: head, pending: event))
        try boundary("after-intent")
        try commit(event)
        try boundary("after-database-commit")
        try save(Checkpoint(stable: head, pending: nil))
        try boundary("after-checkpoint")
    }
    func recover() throws {
        try validate()
        let checkpoint = try checkpoint()
        var noDispatch: UUID?
        if let pending = checkpoint.pending {
            try require(checkpoint.stable.sequence < Int64.max && pending.sequence == checkpoint.stable.sequence + 1 &&
                pending.previousDigest == checkpoint.stable.digest, .inconsistent)
            if head == checkpoint.stable {
                if pending.outcome != .consumed { try commit(pending) }
            } else {
                try require(try head == pending.head, .inconsistent)
                if pending.outcome == .consumed { noDispatch = pending.request }
            }
            if noDispatch == nil { try save(Checkpoint(stable: head, pending: nil)) }
        } else { try require(head == checkpoint.stable, .inconsistent) }
        for (request, value) in ledger.sorted(by: { $0.key.uuidString < $1.key.uuidString }) where value.outcome == .consumed {
            try append(request: request, phone: value.phone, outcome: request == noDispatch ? .noDispatch : .unknown)
        }
        try checkIdentity()
    }
    func consume(request: UUID, phone: UUID) throws {
        try append(request: request, phone: phone, outcome: .consumed)
        try boundary("before-simulated-dispatch")
        try checkCurrentJournal()
        print("simulated-permit")
    }
    func report() throws {
        try checkIdentity()
        struct Row: Encodable { let request: UUID; let phone: UUID; let outcome: Outcome }
        struct Report: Encodable { let sequence: Int64; let digest: String; let records: [Row]; let sqlite: String }
        let result = Report(sequence: head.sequence, digest: head.digest,
            records: ledger.sorted(by: { $0.key.uuidString < $1.key.uuidString }).map { Row(request: $0.key, phone: $0.value.phone, outcome: $0.value.outcome) },
            sqlite: String(cString: sqlite3_libversion()))
        print(String(decoding: try canonicalJSON(result), as: UTF8.self))
    }
}

do {
    let args = Array(CommandLine.arguments.dropFirst())
    guard args.count >= 2, ["init", "inspect", "consume"].contains(args[0]), getuid() != 0 else { throw Failure.usage }
    func option(_ name: String) -> String? { args.firstIndex(of: name).flatMap { $0 + 1 < args.count ? args[$0 + 1] : nil } }
    let store = try Store(directory: args[1], create: args[0] == "init", crash: option("--crash"), pause: option("--pause"))
    try store.recover()
    if args[0] == "consume" {
        guard args.count >= 4, let request = UUID(uuidString: args[2]), let phone = UUID(uuidString: args[3]) else { throw Failure.usage }
        try store.consume(request: request, phone: phone)
    }
    try store.report()
} catch {
    let code = (error as? Failure)?.rawValue ?? "invalid-data"
    FileHandle.standardError.write(Data((code + "\n").utf8))
    exit(1)
}
