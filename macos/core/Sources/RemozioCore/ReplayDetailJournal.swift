import Foundation
import RemozioHostCore
import SQLite3

/// Scoped ledger metadata for observing settlement and linking new command reservations to requests.
struct ReplayDetailJournal {
    static let table = "replay_detail_retirement_v1"
    static let definition = """
        CREATE TABLE \(table) (
            mac BLOB NOT NULL CHECK(length(mac)=16), account BLOB NOT NULL CHECK(length(account)=16),
            request BLOB NOT NULL CHECK(length(request)=16),
            submission BLOB CHECK(submission IS NULL OR length(submission)=16),
            revision BLOB CHECK(revision IS NULL OR length(revision)=8),
            watermark BLOB CHECK(watermark IS NULL OR length(watermark)=8),
            epoch BLOB CHECK(epoch IS NULL OR length(epoch)=16),
            CHECK((revision IS NULL)=(watermark IS NULL) AND (watermark IS NULL)=(epoch IS NULL)),
            PRIMARY KEY(mac,account,request)
        ) STRICT, WITHOUT ROWID
        """

    struct Mark {
        let revision: Data
        let generation: Data
        let epoch: Data

        init(revision: UInt64, generation: UInt64, epoch: Data) {
            self.revision = Self.bytes(revision)
            self.generation = Self.bytes(generation)
            self.epoch = epoch
        }

        private static func bytes(_ value: UInt64) -> Data {
            var bigEndian = value.bigEndian
            return withUnsafeBytes(of: &bigEndian) { Data($0) }
        }
    }

    private let db: OpaquePointer
    private let scope: [Data]
    private let counts: PermanentReplayCounters

    init(connection: OpaquePointer, macID: Data, accountID: Data) {
        db = connection
        scope = [macID, accountID]
        counts = PermanentReplayCounters(connection: db, macID: macID, accountID: accountID)
    }

    static func create(on db: OpaquePointer) throws {
        let code = sqlite3_exec(db, definition, nil, nil, nil)
        guard code == SQLITE_OK else { throw JournalDatabaseError.storage(code) }
    }

    func liveCount() throws -> Int {
        try withCounts { try Int(counts.count(.liveReceipts)) }
    }

    func bindSubmission(_ submission: Data, to request: Data) throws {
        try change("INSERT INTO main.\(Self.table) (mac,account,request,submission) VALUES(?,?,?,?)",
                   scope + [request, submission])
    }

    func observed(_ request: Data, before mark: Mark) throws -> Bool {
        try statement("""
            SELECT 1 FROM main.\(Self.table) WHERE mac=? AND account=? AND request=?
              AND revision=? AND watermark<? AND epoch=?
            """, scope + [request, mark.revision, mark.generation, mark.epoch]) {
            switch sqlite3_step($0) {
            case SQLITE_ROW: return true
            case SQLITE_DONE: return false
            case let code: throw JournalDatabaseError.storage(code)
            }
        }
    }

    func observe(_ request: Data, mark: Mark) throws {
        try change("""
            INSERT INTO main.\(Self.table) (mac,account,request,revision,watermark,epoch) VALUES(?,?,?,?,?,?)
            ON CONFLICT(mac,account,request) DO UPDATE
              SET revision=excluded.revision,watermark=excluded.watermark,epoch=excluded.epoch
            """, scope + [request, mark.revision, mark.generation, mark.epoch])
    }

    /// The enclosing write verified the exact checkpoint used to select these settled requests.
    /// Permanent replay keys and audit records stay in their respective tables.
    func retire(_ request: Data) throws -> Int {
        try change("""
            DELETE FROM main.command_submissions_v1 WHERE mac=? AND account=? AND submission=(
                SELECT submission FROM main.\(Self.table) WHERE mac=? AND account=? AND request=?
            )
            """, scope + scope + [request])
        let submissions = Int(sqlite3_changes(db))
        try change("DELETE FROM main.consumption_outcomes_v1 WHERE mac=? AND account=? AND request=?", scope + [request])
        try change("DELETE FROM main.consumptions_v1 WHERE mac=? AND account=? AND request=?", scope + [request])
        guard sqlite3_changes(db) == 1 else { throw JournalDatabaseError.incompatibleStore }
        try withCounts { try counts.retireReceipt() }
        try change("DELETE FROM main.\(Self.table) WHERE mac=? AND account=? AND request=?", scope + [request])
        return submissions
    }

    func recountLiveReceipts() throws {
        try withCounts { try counts.recountLiveReceipts() }
    }

    private func withCounts<Value>(_ body: () throws -> Value) throws -> Value {
        do { return try body() }
        catch PermanentReplayCounters.Failure.invalidState { throw JournalDatabaseError.incompatibleStore }
        catch PermanentReplayCounters.Failure.writeTransactionRequired { throw JournalDatabaseError.readOnly }
        catch PermanentReplayCounters.Failure.storage(let code) { throw JournalDatabaseError.storage(code) }
    }

    private func change(_ sql: String, _ values: [Data]) throws {
        try statement(sql, values) {
            let code = sqlite3_step($0)
            guard code == SQLITE_DONE else { throw JournalDatabaseError.storage(code) }
        }
    }

    private func statement<Value>(_ sql: String, _ values: [Data], _ body: (OpaquePointer) throws -> Value) throws -> Value {
        var statement: OpaquePointer?
        let code = sqlite3_prepare_v2(db, sql, -1, &statement, nil)
        guard code == SQLITE_OK, let statement else { throw JournalDatabaseError.storage(code) }
        defer { sqlite3_finalize(statement) }
        for (index, value) in values.enumerated() {
            let code = value.withUnsafeBytes {
                sqlite3_bind_blob(statement, Int32(index + 1), $0.baseAddress, Int32($0.count),
                    unsafeBitCast(-1, to: sqlite3_destructor_type.self))
            }
            guard code == SQLITE_OK else { throw JournalDatabaseError.storage(code) }
        }
        return try body(statement)
    }
}
