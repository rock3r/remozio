import RemozioHostCore
import SQLite3

/// Defines the replay tables owned by the checkpointed macOS journal format.
enum PermanentReplayJournal {
    private static let consumed = ConsumptionJournalTables.permanentReplayTable
    private static let submissions = CommandSubmissionReplayTables.permanentReplayTable
    static let tables = [consumed, submissions]

    private static let definitions = [
        """
        CREATE TABLE \(consumed) (
            mac BLOB NOT NULL CHECK(length(mac)=16), account BLOB NOT NULL CHECK(length(account)=16),
            request BLOB NOT NULL CHECK(length(request)=16), PRIMARY KEY(mac,account,request)
        ) STRICT, WITHOUT ROWID
        """,
        """
        CREATE TABLE \(submissions) (
            mac BLOB NOT NULL CHECK(length(mac)=16), account BLOB NOT NULL CHECK(length(account)=16),
            submission BLOB NOT NULL CHECK(length(submission)=16), nonce BLOB NOT NULL CHECK(length(nonce)=32),
            PRIMARY KEY(mac,account,submission), UNIQUE(mac,account,nonce)
        ) STRICT, WITHOUT ROWID
        """
    ]

    static func hasRecordedHistoryGap(on db: OpaquePointer) throws -> Bool {
        try query(db, "SELECT 1 FROM main.history_recoveries_v1 LIMIT 1") { row in
            switch sqlite3_step(row) {
            case SQLITE_DONE: return false
            case SQLITE_ROW: return true
            case let code: throw JournalDatabaseError.storage(code)
            }
        }
    }

    static func seed(on db: OpaquePointer) throws {
        guard sqlite3_txn_state(db, "main") == SQLITE_TXN_WRITE else { throw JournalDatabaseError.readOnly }
        guard try !hasRecordedHistoryGap(on: db) else { throw JournalDatabaseError.incompatibleStore }
        let sql = definitions.joined(separator: ";\n") + """
        ;
        INSERT INTO main.\(consumed) SELECT mac,account,request FROM main.consumptions_v1;
        INSERT INTO main.\(submissions) SELECT mac,account,submission,nonce FROM main.command_submissions_v1;
        """
        let result = sqlite3_exec(db, sql, nil, nil, nil)
        guard result == SQLITE_OK else { throw JournalDatabaseError.storage(result) }
        for (source, target) in [("consumptions_v1", consumed), ("command_submissions_v1", submissions)] {
            try query(db, """
                SELECT (SELECT count(*) FROM main.\(source))=(SELECT count(*) FROM main.\(target))
                  AND NOT EXISTS (
                    SELECT 1 FROM main.\(target) t
                    WHERE NOT EXISTS (SELECT 1 FROM main.journal_identity_v1 j WHERE t.mac=j.mac AND t.account=j.account)
                  )
                """) {
                let step = sqlite3_step($0)
                guard step == SQLITE_ROW else { throw JournalDatabaseError.storage(step) }
                guard sqlite3_column_int($0, 0) == 1 else { throw JournalDatabaseError.incompatibleStore }
            }
        }
    }

    static func validateStorage(on db: OpaquePointer) throws {
        try query(db, "SELECT 1 FROM main.sqlite_schema WHERE type='trigger' LIMIT 1") {
            guard sqlite3_step($0) == SQLITE_DONE else { throw JournalDatabaseError.incompatibleStore }
        }
        for (table, definition) in zip(tables, definitions) {
            try query(db, """
                SELECT type,sql FROM main.sqlite_schema
                WHERE name='\(table)'
                """) { row in
                let step = sqlite3_step(row)
                guard step == SQLITE_ROW, let type = sqlite3_column_text(row, 0),
                      let sql = sqlite3_column_text(row, 1), String(cString: type) == "table",
                      String(cString: sql) == definition, sqlite3_step(row) == SQLITE_DONE else {
                    throw JournalDatabaseError.incompatibleStore
                }
            }
        }
    }

    private static func query<T>(_ db: OpaquePointer, _ sql: String, _ body: (OpaquePointer) throws -> T) throws -> T {
        var statement: OpaquePointer?
        let code = sqlite3_prepare_v2(db, sql, -1, &statement, nil)
        guard code == SQLITE_OK, let statement else { throw JournalDatabaseError.storage(code) }
        defer { sqlite3_finalize(statement) }
        return try body(statement)
    }
}
