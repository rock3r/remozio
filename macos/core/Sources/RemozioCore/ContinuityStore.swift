import Foundation
import SQLite3

/// Root-owned independent checkpoint storage. Serialize calls and close before releasing authority ownership.
/// This store neither executes journal mutations nor grants dispatch permission.
public final class ContinuityStore {
    func directoryIdentities() throws -> [ProtectedStorageLease.DirectoryIdentity] {
        try lease.directoryIdentities()
    }
    private let lease: ProtectedContinuityLease
    private var db: OpaquePointer?
    private var unavailable = false
    private let macID: Data
    private let accountID: Data

    public static func open(directoryPath: String, macID: Data, accountID: Data,
                            initialize: ContinuityCheckpoint? = nil) throws -> ContinuityStore {
        try ContinuityStore(lease: ProtectedContinuityLease.acquire(directoryPath: directoryPath),
                            macID: macID, accountID: accountID, initialize: initialize)
    }

    init(lease: ProtectedContinuityLease, macID: Data, accountID: Data, initialize: ContinuityCheckpoint?) throws {
        self.lease = lease; self.macID = macID; self.accountID = accountID
        do {
            guard macID.count == 16, accountID.count == 16 else { throw ContinuityStoreError.wrongScope }
            try lease.validate()
            var connection: OpaquePointer?
            let result = sqlite3_open_v2(lease.databasePath, &connection,
                SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_NOFOLLOW, nil)
            db = connection
            guard result == SQLITE_OK, let connection else { throw ContinuityStoreError.storage(result) }
            guard sqlite3_compileoption_used("OMIT_LOAD_EXTENSION") == 1,
                  sqlite3_busy_timeout(connection, 5000) == SQLITE_OK else { throw ContinuityStoreError.incompatibleStore }
            _ = sqlite3_limit(connection, SQLITE_LIMIT_ATTACHED, 0)
            _ = sqlite3_limit(connection, SQLITE_LIMIT_LENGTH, 8192)
            try exec("PRAGMA trusted_schema=OFF")
            if initialize != nil {
                try requireEmptyStore()
            } else {
                guard try scalar("PRAGMA application_id") == 0x524D5A43,
                      try scalar("PRAGMA user_version") == 1 else { throw ContinuityStoreError.incompatibleStore }
            }
            try exec("PRAGMA journal_mode=DELETE")
            try exec("PRAGMA synchronous=EXTRA")
            try exec("PRAGMA fullfsync=ON")
            guard try scalar("PRAGMA synchronous") == 3, try scalar("PRAGMA fullfsync") == 1,
                  try scalar("PRAGMA trusted_schema") == 0 else { throw ContinuityStoreError.incompatibleStore }
            try statement("PRAGMA journal_mode") {
                try self.row($0)
                guard let mode = sqlite3_column_text($0, 0),
                      String(cString: mode) == "delete" else { throw ContinuityStoreError.incompatibleStore }
            }
            if let initialize {
                try transaction(write: true) {
                    try self.requireEmptyStore()
                    try self.exec("CREATE TABLE continuity_v1(id INTEGER PRIMARY KEY CHECK(id=1), mac BLOB NOT NULL CHECK(length(mac)=16), account BLOB NOT NULL CHECK(length(account)=16), committed BLOB NOT NULL, pending BLOB, repair INTEGER NOT NULL CHECK(repair IN (0,1))) STRICT")
                    try self.statement("INSERT INTO continuity_v1 VALUES(1,?,?,?,NULL,0)", [macID, accountID, try initialize.bytes]) { try self.done($0) }
                    try self.exec("PRAGMA application_id=1380801091")
                    try self.exec("PRAGMA user_version=1")
                }
            }
            _ = try read()
        } catch { close(); throw error }
    }
    deinit { close() }

    public func read() throws -> ContinuityState { try transaction(write: false) { try self.load() } }

    /// Persist both boundaries before changing the journal. A return is not permission to dispatch.
    public func prepare(expected: ContinuityCheckpoint, candidate: ContinuityCheckpoint) throws {
        try transaction(write: true) {
            let state = try self.load()
            guard !state.recoveryRequired else { throw ContinuityStoreError.recoveryRequired }
            guard state.committed == expected, state.pending == nil else { throw ContinuityStoreError.staleState }
            _ = try ContinuityState(committed: expected, pending: candidate, recoveryRequired: false)
            try self.statement("UPDATE continuity_v1 SET pending=? WHERE id=1", [try candidate.bytes]) { try self.done($0) }
        }
    }

    /// Call only after the journal's candidate boundary is durably committed and independently verified.
    public func finalize(expected: ContinuityState) throws {
        try transaction(write: true) {
            guard !expected.recoveryRequired else { throw ContinuityStoreError.recoveryRequired }
            guard let pending = expected.pending, try self.load() == expected else { throw ContinuityStoreError.staleState }
            try self.statement("UPDATE continuity_v1 SET committed=?,pending=NULL WHERE id=1", [try pending.bytes]) { try self.done($0) }
        }
    }

    /// Recovery may discard preparation only after proving the journal still matches the committed boundary.
    public func discardPreparation(expected: ContinuityState) throws {
        try transaction(write: true) {
            guard !expected.recoveryRequired else { throw ContinuityStoreError.recoveryRequired }
            guard expected.pending != nil, try self.load() == expected else { throw ContinuityStoreError.staleState }
            try self.exec("UPDATE continuity_v1 SET pending=NULL WHERE id=1")
        }
    }

    /// Sticky across reopen. This API intentionally has no repair-clearing operation.
    public func requireRecovery() throws {
        try transaction(write: true) { _ = try self.load(); try self.exec("UPDATE continuity_v1 SET repair=1 WHERE id=1") }
    }

    public func close() {
        if let db { _ = sqlite3_close_v2(db); self.db = nil }
        lease.close()
    }

    private func load() throws -> ContinuityState {
        guard try scalar("SELECT count(*) FROM continuity_v1") == 1 else { throw ContinuityStoreError.incompatibleStore }
        return try statement("SELECT mac,account,committed,pending,repair FROM continuity_v1 WHERE id=1") { stmt in
            try self.row(stmt)
            guard try self.blob(stmt, 0) == macID, try self.blob(stmt, 1) == accountID else { throw ContinuityStoreError.wrongScope }
            let committed = try ContinuityCheckpoint.decode(self.blob(stmt, 2))
            let pending = sqlite3_column_type(stmt, 3) == SQLITE_NULL ? nil : try ContinuityCheckpoint.decode(self.blob(stmt, 3))
            let repair = sqlite3_column_int64(stmt, 4)
            guard sqlite3_column_type(stmt, 4) == SQLITE_INTEGER, (0...1).contains(repair) else { throw ContinuityStoreError.incompatibleStore }
            return try ContinuityState(committed: committed, pending: pending, recoveryRequired: repair == 1)
        }
    }
    private func transaction<T>(write: Bool, _ body: () throws -> T) throws -> T {
        guard db != nil else { throw ContinuityStoreError.closed }
        guard !unavailable else { throw ContinuityStoreError.unavailable }
        do { try lease.validate() } catch { unavailable = true; throw error }
        try exec(write ? "BEGIN IMMEDIATE" : "BEGIN")
        do {
            let value = try body()
            try lease.validate()
            do { try exec("COMMIT") } catch { unavailable = true; throw error }
            do { try lease.validate() } catch { unavailable = true; throw error }
            return value
        } catch {
            if let db, sqlite3_get_autocommit(db) == 0 {
                if sqlite3_exec(db, "ROLLBACK", nil, nil, nil) != SQLITE_OK { unavailable = true }
            } else if write { unavailable = true }
            throw error
        }
    }
    private func requireEmptyStore() throws {
        guard try scalar("PRAGMA application_id") == 0, try scalar("PRAGMA user_version") == 0,
              try scalar("SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'") == 0 else {
            throw ContinuityStoreError.incompatibleStore
        }
    }
    private func row(_ stmt: OpaquePointer) throws {
        let result = sqlite3_step(stmt)
        guard result != SQLITE_DONE else { throw ContinuityStoreError.incompatibleStore }
        guard result == SQLITE_ROW else { throw ContinuityStoreError.storage(result) }
    }
    private func exec(_ sql: String) throws {
        let result = sqlite3_exec(db, sql, nil, nil, nil)
        guard result == SQLITE_OK else { throw ContinuityStoreError.storage(result) }
    }
    private func statement<T>(_ sql: String, _ values: [Data] = [], _ body: (OpaquePointer) throws -> T) throws -> T {
        var stmt: OpaquePointer?
        let result = sqlite3_prepare_v2(db, sql, -1, &stmt, nil)
        guard result == SQLITE_OK, let stmt else { throw ContinuityStoreError.storage(result) }
        defer { sqlite3_finalize(stmt) }
        for (index, value) in values.enumerated() {
            let bound = value.withUnsafeBytes { sqlite3_bind_blob(stmt, Int32(index + 1), $0.baseAddress,
                Int32($0.count), unsafeBitCast(-1, to: sqlite3_destructor_type.self)) }
            guard bound == SQLITE_OK else { throw ContinuityStoreError.storage(bound) }
        }
        return try body(stmt)
    }
    private func done(_ stmt: OpaquePointer) throws {
        let result = sqlite3_step(stmt)
        guard result == SQLITE_DONE else { throw ContinuityStoreError.storage(result) }
    }
    private func scalar(_ sql: String) throws -> Int64 {
        try statement(sql) {
            try self.row($0)
            return sqlite3_column_int64($0, 0)
        }
    }
    private func blob(_ stmt: OpaquePointer, _ column: Int32) throws -> Data {
        let count = sqlite3_column_bytes(stmt, column)
        guard sqlite3_column_type(stmt, column) == SQLITE_BLOB, count > 0, count <= 256,
              let bytes = sqlite3_column_blob(stmt, column) else { throw ContinuityStoreError.incompatibleStore }
        return Data(bytes: bytes, count: Int(count))
    }
}
