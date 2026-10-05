import Foundation
import SQLite3

/// Retained gap evidence shares the journal transaction and ledger digest, never the authority digest.
final class HistoryRecoveryJournal {
    private let db: OpaquePointer
    init(connection: OpaquePointer) { db = connection }

    func read(epoch: Data) throws -> HistoryRecoveryIntent? {
        guard epoch.count == 16 else { throw ContinuityStoreError.invalidCheckpoint }
        let version = try schemaVersion()
        guard (12...14).contains(version) else { throw JournalDatabaseError.incompatibleStore }
        if version < 14 { return nil }
        return try statement("SELECT evidence FROM main.history_recoveries_v1 WHERE epoch=?", values: [epoch]) { row in
            let result = sqlite3_step(row)
            if result == SQLITE_DONE { return nil }
            guard result == SQLITE_ROW else { throw JournalDatabaseError.storage(result) }
            let count = sqlite3_column_bytes(row, 0)
            guard sqlite3_column_type(row, 0) == SQLITE_BLOB, count > 0, count <= 1024,
                  let pointer = sqlite3_column_blob(row, 0) else { throw JournalDatabaseError.incompatibleStore }
            let intent = try HistoryRecoveryIntent.decode(Data(bytes: pointer, count: Int(count)))
            guard intent.recoveryEpoch == epoch else { throw JournalDatabaseError.incompatibleStore }
            return intent
        }
    }

    func insert(_ intent: HistoryRecoveryIntent) throws {
        let version = try schemaVersion()
        guard version == 13 || version == 14 else { throw JournalDatabaseError.incompatibleStore }
        guard sqlite3_txn_state(db, "main") == SQLITE_TXN_WRITE else { throw JournalDatabaseError.readOnly }
        if version == 13 {
            try exec("""
                CREATE TABLE main.history_recoveries_v1(
                    epoch BLOB PRIMARY KEY CHECK(length(epoch)=16),
                    evidence BLOB NOT NULL CHECK(length(evidence) BETWEEN 1 AND 1024)
                ) STRICT, WITHOUT ROWID;
                PRAGMA main.user_version=14;
                """)
        }
        try statement("INSERT INTO main.history_recoveries_v1 VALUES(?,?)",
            values: [intent.recoveryEpoch, try intent.bytes]) { row in
            let result = sqlite3_step(row)
            guard result == SQLITE_DONE else { throw JournalDatabaseError.storage(result) }
        }
    }

    private func schemaVersion() throws -> Int64 {
        guard sqlite3_get_autocommit(db) == 0 else { throw JournalDatabaseError.expiredTransaction }
        return try statement("PRAGMA main.user_version") { row in
            let result = sqlite3_step(row)
            guard result == SQLITE_ROW else { throw JournalDatabaseError.storage(result) }
            return sqlite3_column_int64(row, 0)
        }
    }
    private func exec(_ sql: String) throws {
        let result = sqlite3_exec(db, sql, nil, nil, nil)
        guard result == SQLITE_OK else { throw JournalDatabaseError.storage(result) }
    }
    private func statement<T>(_ sql: String, values: [Data] = [], _ body: (OpaquePointer) throws -> T) throws -> T {
        var row: OpaquePointer?
        let result = sqlite3_prepare_v2(db, sql, -1, &row, nil)
        guard result == SQLITE_OK, let row else { throw JournalDatabaseError.storage(result) }
        defer { sqlite3_finalize(row) }
        for (index, value) in values.enumerated() {
            let result = value.withUnsafeBytes {
                sqlite3_bind_blob(row, Int32(index + 1), $0.baseAddress, Int32($0.count), unsafeBitCast(-1, to: sqlite3_destructor_type.self))
            }
            guard result == SQLITE_OK else { throw JournalDatabaseError.storage(result) }
        }
        return try body(row)
    }
}
