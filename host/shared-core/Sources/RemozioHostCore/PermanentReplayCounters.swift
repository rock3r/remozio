import Foundation
#if os(Linux)
import CSQLite
#else
import SQLite3
#endif

/// Counts held by the caller's existing journal transaction.
public struct PermanentReplayCounters {
    public enum Failure: Error, Equatable {
        case invalidState, writeTransactionRequired, storage(Int32)
    }

    public enum Counter {
        case consumedRequests, commandSubmissions, liveReceipts

        fileprivate var table: String {
            switch self {
            case .consumedRequests, .commandSubmissions: PermanentReplayCounters.authorityTable
            case .liveReceipts: PermanentReplayCounters.ledgerTable
            }
        }

        fileprivate var column: String {
            switch self {
            case .consumedRequests: "consumed_requests"
            case .commandSubmissions: "command_submissions"
            case .liveReceipts: "live_receipts"
            }
        }
    }

    public static let authorityTable = "permanent_replay_counts_v1"
    public static let ledgerTable = "replay_live_receipt_count_v1"

    public static let authorityDefinition = """
        CREATE TABLE \(authorityTable) (
            mac BLOB NOT NULL CHECK(length(mac)=16),
            account BLOB NOT NULL CHECK(length(account)=16),
            consumed_requests INTEGER NOT NULL CHECK(consumed_requests BETWEEN 0 AND 10000000),
            command_submissions INTEGER NOT NULL CHECK(command_submissions BETWEEN 0 AND 10000000),
            PRIMARY KEY(mac,account)
        ) STRICT, WITHOUT ROWID
        """

    public static let ledgerDefinition = """
        CREATE TABLE \(ledgerTable) (
            mac BLOB NOT NULL CHECK(length(mac)=16),
            account BLOB NOT NULL CHECK(length(account)=16),
            live_receipts INTEGER NOT NULL CHECK(live_receipts BETWEEN 0 AND 10000000),
            PRIMARY KEY(mac,account)
        ) STRICT, WITHOUT ROWID
        """

    private let db: OpaquePointer
    private let macID: Data
    private let accountID: Data

    public init(connection: OpaquePointer, macID: Data, accountID: Data) {
        db = connection
        self.macID = macID
        self.accountID = accountID
    }

    public func count(_ counter: Counter) throws -> Int64 {
        guard sqlite3_get_autocommit(db) == 0 else { throw Failure.invalidState }
        return try statement("SELECT \(counter.column) FROM main.\(counter.table) WHERE mac=? AND account=?") { row in
            let step = sqlite3_step(row)
            guard step != SQLITE_DONE else { throw Failure.invalidState }
            guard step == SQLITE_ROW else { throw Failure.storage(step) }
            let count = sqlite3_column_int64(row, 0)
            guard sqlite3_column_type(row, 0) == SQLITE_INTEGER, (0...10_000_000).contains(count) else {
                throw Failure.invalidState
            }
            return count
        }
    }

    /// The caller verifies capacity and inserts the corresponding key in the same write transaction.
    public func increment(_ counter: Counter) throws {
        try update(counter, expression: "\(counter.column)+1")
    }

    public func retireReceipt() throws {
        try update(.liveReceipts, expression: "live_receipts-1")
    }

    /// Ledger history recovery derives a new detail count. Permanent counts are not changed.
    public func recountLiveReceipts() throws {
        try update(.liveReceipts, expression: """
            (SELECT count(*) FROM main.consumptions_v1 c
             WHERE c.mac=\(Self.ledgerTable).mac AND c.account=\(Self.ledgerTable).account)
            """)
    }

    private func update(_ counter: Counter, expression: String) throws {
        guard sqlite3_txn_state(db, "main") == SQLITE_TXN_WRITE else { throw Failure.writeTransactionRequired }
        try statement("UPDATE main.\(counter.table) SET \(counter.column)=\(expression) WHERE mac=? AND account=?") {
            let step = sqlite3_step($0)
            guard step == SQLITE_DONE else { throw Failure.storage(step) }
            guard sqlite3_changes(db) == 1 else { throw Failure.invalidState }
        }
    }

    private func statement<Value>(_ sql: String, _ body: (OpaquePointer) throws -> Value) throws -> Value {
        var statement: OpaquePointer?
        let result = sqlite3_prepare_v2(db, sql, -1, &statement, nil)
        guard result == SQLITE_OK, let statement else { throw Failure.storage(result) }
        defer { sqlite3_finalize(statement) }
        for (slot, value) in [(Int32(1), macID), (Int32(2), accountID)] {
            let code = value.withUnsafeBytes {
                sqlite3_bind_blob(statement, slot, $0.baseAddress, Int32($0.count),
                    unsafeBitCast(-1, to: sqlite3_destructor_type.self))
            }
            guard code == SQLITE_OK else { throw Failure.storage(code) }
        }
        return try body(statement)
    }
}
