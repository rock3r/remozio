#if !DEBUG
#error("The synthetic journal fixture must not be built for Release")
#endif

import CryptoKit
import Darwin
import Foundation
import SQLite3
@testable import RemozioCore
import RemozioProtocol

/// Normal-user disposable storage. The test controller owns and removes its parent directory.
final class JournalFixture {
    let root: String
    let limits: CBORLimits
    private(set) var database: JournalDatabase
    private(set) var writer: AuditEpochWriter

    init(directory: String, limits: CBORLimits) throws {
        guard geteuid() != 0, let canonical = realpath(directory, nil) else { throw HarnessError.invalidInput }
        defer { free(canonical) }
        root = String(cString: canonical)
        self.limits = limits
        guard mkdir(root + "/journal", 0o700) == 0 else { throw HarnessError.invalidInput }
        for name in ["writer.lock", "journal.sqlite"] {
            let fd = Darwin.open(root + "/journal/" + name, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0o600)
            guard fd >= 0 else { throw HarnessError.invalidInput }
            close(fd)
        }
        database = try Self.open(root: root, limits: limits, initialize: true)
        let descriptor = try Self.descriptor(limits: limits)
        writer = try database.write { try $0.createEpoch(descriptor) }
    }

    deinit { try? database.close() }

    /// Reopen the file and start a fresh epoch. This is not production startup recovery or a process crash.
    func reopen() throws {
        let previous = try database.read { transaction -> (Data, UInt64, Data?) in
            guard let epoch = try transaction.epoch(writer.epoch) else { throw HarnessError.invalidState }
            let last = epoch.head == 0 ? nil : try transaction.page(epoch: writer.epoch, after: epoch.head - 1,
                maximumRecords: 1, maximumBytes: limits.maxBytes).canonicalRecords.first
            return (writer.epoch, epoch.head, last.map { Data(SHA256.hash(data: $0)) })
        }
        try database.close()
        let next = try Self.open(root: root, limits: limits, initialize: false)
        let descriptor = try Self.descriptor(limits: limits, previous: previous)
        let nextWriter = try next.write { try $0.createEpoch(descriptor) }
        database = next; writer = nextWriter
    }

    func snapshot(requestID: Data) throws -> [String: String] {
        try database.read { transaction in
            guard let epoch = try transaction.epoch(writer.epoch) else { throw HarnessError.invalidState }
            var fields = ["epoch": hex(writer.epoch), "head": String(epoch.head)]
            if let outcome = try transaction.consumptionOutcome(requestID: requestID) {
                fields["consumed"] = "true"
                fields["winner"] = hex(outcome.receipt.decision.phoneID)
                fields["phase"] = outcome.phase.rawValue
                fields["outcomeRevision"] = String(outcome.revision)
                fields["consumptionEvent"] = hex(try outcome.receipt.event.encode(limits: limits))
                fields["outcomeEvent"] = hex(try outcome.event.encode(limits: limits))
            } else { fields["consumed"] = "false" }
            return fields
        }
    }

    func withAuditFailure<T>(_ enabled: Bool, operation: () throws -> T) throws -> T {
        guard enabled else { return try operation() }
        try sql("CREATE TRIGGER synthetic_audit_failure BEFORE INSERT ON audit_records_v1 BEGIN SELECT RAISE(ABORT,'synthetic'); END")
        let result = Result { try operation() }
        try sql("DROP TRIGGER synthetic_audit_failure")
        switch result {
        case .success: throw HarnessError.invalidState
        case .failure(let error):
            if case AuditJournalError.storage(let code) = error, code & 0xff == SQLITE_CONSTRAINT {
                throw HarnessError.injectedPrecommitFailure
            }
            throw error
        }
    }

    private func sql(_ text: String) throws {
        var connection: OpaquePointer?
        let result = sqlite3_open(root + "/journal/journal.sqlite", &connection)
        defer { if let connection { sqlite3_close(connection) } }
        guard result == SQLITE_OK, let connection else { throw HarnessError.invalidState }
        guard sqlite3_exec(connection, text, nil, nil, nil) == SQLITE_OK else { throw HarnessError.invalidState }
    }

    private static func open(root: String, limits: CBORLimits, initialize: Bool) throws -> JournalDatabase {
        try JournalDatabase(lease: ProtectedJournalLease(anchor: root, relativeDirectory: "journal", owner: getuid()),
            macID: id(1), accountID: id(2), recordLimits: limits, descriptorLimits: limits, decisionLimits: limits,
            maximumConsumptions: 8, busyMilliseconds: 100, initialize: initialize)
    }

    private static func descriptor(limits: CBORLimits, previous: (Data, UInt64, Data?)? = nil) throws -> AuditEpochDescriptor {
        let body = try DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(id(1)), 2: .bytes(id(2)), 3: .bytes(randomID()), 4: .unsigned(7),
            5: .unsigned(previous == nil ? AuditEpochCause.initial.rawValue : AuditEpochCause.restart.rawValue),
            6: previous.map { .bytes($0.0) } ?? .null, 7: previous.map { .unsigned($0.1) } ?? .null,
            8: previous?.2.map(CBORValue.bytes) ?? .null,
        ]), limits: limits)
        return try AuditEpochDescriptor.decode(body, limits: limits)
    }
}

func randomID() -> Data { withUnsafeBytes(of: UUID().uuid) { Data($0) } }
