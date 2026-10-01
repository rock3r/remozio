import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import SQLite3

public enum GatewayDatabaseError: Error, Equatable {
    case invalidConfiguration, incompatibleStore, wrongScope, closed, unavailable, transactionActive
    case headMismatch, operationConflict, capacityExceeded, invalidClock, corruptData
    case storage(Int32)
}

/// Historical signed control, never a probe permit or proof of current enrollment.
public struct GatewayCandidateReceipt: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let candidate: GatewayTokenCandidate
    public let canonicalPayload: Data
    public let signature: Data
    public var description: String { "GatewayCandidateReceipt(redacted)" }
    public var debugDescription: String { description }
}

public struct GatewayCandidateAdmission: Sendable {
    public let receipt: GatewayCandidateReceipt
    public let inserted: Bool
}

/// Owns one registration's private connection. Serialize calls with current gateway trust and enrollment changes.
/// This store admits candidates only; it has no provider dispatch or recipient activation API.
public final class GatewayDatabase {
    private static let applicationID: Int64 = 0x524D5A47
    private let lease: ProtectedGatewayLease
    private let identity: GatewayRegistrationIdentity
    private let payloadLimits: CBORLimits
    private let signingLimits: CBORLimits
    private let maximumOperations: Int
    private let maximumPendingPerEnrollment: Int
    private let maximumLifetimeMillis: UInt64
    private let clockEpoch: UUID
    private let runID = UUID()
    private var lastMoment: UInt64?
    private var db: OpaquePointer?
    private var active = false
    private var unavailable = false

    /// Initialize only during protected setup on an empty, pre-provisioned file. Never initialize as recovery.
    public static func open(directoryPath: String, serviceUID: uid_t, identity: GatewayRegistrationIdentity,
                            payloadLimits: CBORLimits, signingLimits: CBORLimits, maximumOperations: Int,
                            maximumPendingPerEnrollment: Int, maximumLifetimeMillis: UInt64, clockEpoch: UUID,
                            busyMilliseconds: UInt32, initialize: Bool = false) throws -> GatewayDatabase {
        try GatewayDatabase(lease: ProtectedGatewayLease.acquire(directoryPath: directoryPath, serviceUID: serviceUID),
            identity: identity, payloadLimits: payloadLimits, signingLimits: signingLimits, maximumOperations: maximumOperations,
            maximumPendingPerEnrollment: maximumPendingPerEnrollment, maximumLifetimeMillis: maximumLifetimeMillis,
            clockEpoch: clockEpoch, busyMilliseconds: busyMilliseconds, initialize: initialize)
    }

    /// Internal fixture entry point. Ownership of the lease transfers even if opening fails.
    init(lease: ProtectedGatewayLease, identity: GatewayRegistrationIdentity, payloadLimits: CBORLimits,
         signingLimits: CBORLimits, maximumOperations: Int, maximumPendingPerEnrollment: Int,
         maximumLifetimeMillis: UInt64, clockEpoch: UUID, busyMilliseconds: UInt32, initialize: Bool) throws {
        self.lease = lease; self.identity = identity; self.payloadLimits = payloadLimits; self.signingLimits = signingLimits
        self.maximumOperations = maximumOperations; self.maximumPendingPerEnrollment = maximumPendingPerEnrollment
        self.maximumLifetimeMillis = maximumLifetimeMillis; self.clockEpoch = clockEpoch
        do {
            guard maximumOperations > 0, maximumOperations <= 1_000_000,
                  maximumPendingPerEnrollment > 0, maximumPendingPerEnrollment <= maximumOperations,
                  maximumLifetimeMillis > 0, busyMilliseconds <= 60_000,
                  payloadLimits.maxBytes <= Int(Int32.max) - 32768 else { throw GatewayDatabaseError.invalidConfiguration }
            try lease.validate()
            var connection: OpaquePointer?
            let rc = sqlite3_open_v2(lease.databasePath, &connection, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_NOFOLLOW, nil)
            db = connection
            guard rc == SQLITE_OK, let connection else { throw GatewayDatabaseError.storage(rc) }
            try lease.validate()
            guard sqlite3_busy_timeout(connection, Int32(busyMilliseconds)) == SQLITE_OK,
                  sqlite3_compileoption_used("OMIT_LOAD_EXTENSION") == 1 else { throw GatewayDatabaseError.invalidConfiguration }
            _ = sqlite3_limit(connection, SQLITE_LIMIT_ATTACHED, 0)
            _ = sqlite3_limit(connection, SQLITE_LIMIT_LENGTH, Int32(payloadLimits.maxBytes + 32768))
            try exec("PRAGMA trusted_schema=OFF"); try exec("PRAGMA foreign_keys=ON")
            if initialize { try requireEmpty() } else { try validateIdentity() }
            try exec("PRAGMA journal_mode=DELETE"); try exec("PRAGMA synchronous=EXTRA"); try exec("PRAGMA fullfsync=ON")
            guard try scalarText("PRAGMA journal_mode") == "delete", try scalar("PRAGMA synchronous") == 3,
                  try scalar("PRAGMA fullfsync") == 1, try scalar("PRAGMA foreign_keys") == 1,
                  try scalar("PRAGMA trusted_schema") == 0 else { throw GatewayDatabaseError.invalidConfiguration }
            if initialize { try transaction(write: true) { try create() } }
            try validateIdentity()
            // A restart cannot restore a process-local deadline or turn an old receipt into another probe.
            try transaction(write: true) { try exec("UPDATE gateway_candidates_v1 SET token=NULL WHERE token IS NOT NULL") }
        } catch { shutdown(); throw error }
    }
    deinit { shutdown() }

    public func head() throws -> UInt64 { try transaction(write: false) { try storedHead() } }
    public func receipt(operationID: Data) throws -> GatewayCandidateReceipt? {
        guard operationID.count == 16 else { throw GatewayDatabaseError.wrongScope }
        return try transaction(write: false) { try storedReceipt(operationID: operationID) }
    }

    /// The caller supplies a consistent current trust snapshot. A successful return means the transaction committed, not that a probe may run.
    public func admitCandidate(canonicalPayload: Data, signature: Data, wireVersion: UInt64, registrationToken: String,
                               trust: GatewayCandidateTrust, nowUnixMillis: UInt64, now: AuthorityMoment) throws -> GatewayCandidateAdmission {
        try transaction(write: true) {
            try checkClock(now)
            guard identity.matches(trust) else { throw GatewayDatabaseError.wrongScope }
            guard try storedHead() == trust.appliedControlRevision else { throw GatewayDatabaseError.headMismatch }
            let candidate = try GatewayCandidateVerifier.authenticate(canonicalCandidate: canonicalPayload, signature: signature,
                wireVersion: wireVersion, registrationToken: registrationToken, trust: trust, payloadLimits: payloadLimits, signingLimits: signingLimits)
            if let previous = try storedReceipt(operationID: candidate.operationID) {
                guard previous.canonicalPayload == canonicalPayload else { throw GatewayDatabaseError.operationConflict }
                return GatewayCandidateAdmission(receipt: previous, inserted: false)
            }
            let verified = try GatewayCandidateVerifier.verify(canonicalCandidate: canonicalPayload, signature: signature,
                wireVersion: wireVersion, registrationToken: registrationToken, trust: trust, nowUnixMillis: nowUnixMillis,
                now: now, maximumLifetimeMillis: maximumLifetimeMillis, payloadLimits: payloadLimits, signingLimits: signingLimits)
            try expire(now)
            guard try scalar("SELECT count(*) FROM gateway_candidates_v1") < maximumOperations else { throw GatewayDatabaseError.capacityExceeded }
            let pending = try statement("SELECT count(*) FROM gateway_candidates_v1 WHERE phone=? AND enrollment=? AND token IS NOT NULL",
                [candidate.binding.phoneID, candidate.binding.enrollmentEpoch]) { stmt in
                guard sqlite3_step(stmt) == SQLITE_ROW else { throw GatewayDatabaseError.storage(sqlite3_errcode(db)) }
                return sqlite3_column_int64(stmt, 0)
            }
            guard pending < maximumPendingPerEnrollment else { throw GatewayDatabaseError.capacityExceeded }
            let duplicate = try statement("SELECT count(*) FROM gateway_candidates_v1 WHERE candidate=? OR challenge=?",
                [candidate.binding.candidateID, candidate.binding.challenge]) { stmt in
                guard sqlite3_step(stmt) == SQLITE_ROW else { throw GatewayDatabaseError.storage(sqlite3_errcode(db)) }
                return sqlite3_column_int64(stmt, 0)
            }
            guard duplicate == 0 else { throw GatewayDatabaseError.operationConflict }
            try statement("INSERT INTO gateway_candidates_v1 VALUES(?,?,?,?,?,?,?,?,?,?,?)", [candidate.operationID,
                candidate.binding.candidateID, candidate.binding.challenge, candidate.binding.phoneID, candidate.binding.enrollmentEpoch,
                canonicalPayload, signature, uint(candidate.revision), uuid(runID), uint(verified.deadlineMilliseconds), Data(registrationToken.utf8)]) {
                try done($0)
            }
            try statement("UPDATE gateway_identity_v1 SET head=? WHERE id=1 AND head=?", [uint(candidate.revision), uint(trust.appliedControlRevision)]) {
                try done($0)
                guard sqlite3_changes(db) == 1 else { throw GatewayDatabaseError.headMismatch }
            }
            return GatewayCandidateAdmission(receipt: GatewayCandidateReceipt(candidate: candidate, canonicalPayload: canonicalPayload, signature: signature), inserted: true)
        }
    }

    /// Reclaim expired token material without deleting the signed operation receipts or rewinding the head.
    public func expireCandidates(now: AuthorityMoment) throws {
        try transaction(write: true) { try checkClock(now); try expire(now) }
    }
    public func close() throws {
        guard !active else { throw GatewayDatabaseError.transactionActive }
        shutdown()
    }

    private func checkClock(_ now: AuthorityMoment) throws {
        guard now.epoch == clockEpoch, lastMoment.map({ now.milliseconds >= $0 }) ?? true else {
            unavailable = true
            throw GatewayDatabaseError.invalidClock
        }
        lastMoment = now.milliseconds
    }
    private func expire(_ now: AuthorityMoment) throws {
        try statement("UPDATE gateway_candidates_v1 SET token=NULL WHERE token IS NOT NULL AND (run<>? OR deadline<=?)", [uuid(runID), uint(now.milliseconds)]) { try done($0) }
    }
    private func storedHead() throws -> UInt64 {
        try statement("SELECT head FROM gateway_identity_v1 WHERE id=1") {
            guard sqlite3_step($0) == SQLITE_ROW else { throw GatewayDatabaseError.corruptData }
            return try unsigned(blob($0, 0, maximum: 8))
        }
    }
    private func storedReceipt(operationID: Data) throws -> GatewayCandidateReceipt? {
        try statement("SELECT candidate,challenge,phone,enrollment,payload,signature,revision FROM gateway_candidates_v1 WHERE operation=?", [operationID]) { stmt in
            let rc = sqlite3_step(stmt)
            if rc == SQLITE_DONE { return nil }
            guard rc == SQLITE_ROW else { throw GatewayDatabaseError.storage(rc) }
            let payload = try blob(stmt, 4, maximum: payloadLimits.maxBytes), signature = try blob(stmt, 5, maximum: 64)
            let candidate: GatewayTokenCandidate
            do { candidate = try GatewayTokenCandidate.decode(payload, limits: payloadLimits) }
            catch { throw GatewayDatabaseError.corruptData }
            guard candidate.operationID == operationID, identity.matches(candidate.binding),
                  candidate.binding.candidateID == (try blob(stmt, 0, maximum: 16)), candidate.binding.challenge == (try blob(stmt, 1, maximum: 32)),
                  candidate.binding.phoneID == (try blob(stmt, 2, maximum: 16)), candidate.binding.enrollmentEpoch == (try blob(stmt, 3, maximum: 16)),
                  candidate.revision == (try unsigned(blob(stmt, 6, maximum: 8))), candidate.revision <= (try storedHead()),
                  try GatewayTokenCandidateSignature.verify(signature: signature, publicKey: identity.rootPublicKey, wireVersion: 1,
                    canonicalPayload: payload, payloadLimits: payloadLimits, inputLimits: signingLimits) else { throw GatewayDatabaseError.corruptData }
            return GatewayCandidateReceipt(candidate: candidate, canonicalPayload: payload, signature: signature)
        }
    }
    private func transaction<T>(write: Bool, _ body: () throws -> T) throws -> T {
        guard db != nil else { throw GatewayDatabaseError.closed }
        guard !unavailable else { throw GatewayDatabaseError.unavailable }
        guard !active else { throw GatewayDatabaseError.transactionActive }
        try validateLease()
        try exec(write ? "BEGIN IMMEDIATE" : "BEGIN")
        active = true; defer { active = false }
        do {
            let result = try body()
            try validateLease()
            do { try exec("COMMIT") } catch { unavailable = true; throw error }
            try validateLease()
            return result
        } catch {
            if error as? GatewayDatabaseError == .corruptData { unavailable = true }
            if let db, sqlite3_get_autocommit(db) == 0 {
                if sqlite3_exec(db, "ROLLBACK", nil, nil, nil) != SQLITE_OK { unavailable = true }
            } else if write { unavailable = true }
            throw error
        }
    }
    private func validateLease() throws {
        do { try lease.validate() } catch { unavailable = true; throw error }
    }
    private func requireEmpty() throws {
        guard try scalar("PRAGMA application_id") == 0, try scalar("PRAGMA user_version") == 0,
              try scalar("SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'") == 0 else { throw GatewayDatabaseError.incompatibleStore }
    }
    private func create() throws {
        try requireEmpty()
        try exec("CREATE TABLE gateway_identity_v1(id INTEGER PRIMARY KEY CHECK(id=1), identity BLOB NOT NULL, head BLOB NOT NULL CHECK(length(head)=8)) STRICT")
        try statement("INSERT INTO gateway_identity_v1 VALUES(1,?,?)", [identity.encode(), uint(0)]) { try done($0) }
        try exec("""
            CREATE TABLE gateway_candidates_v1 (
                operation BLOB PRIMARY KEY CHECK(length(operation)=16), candidate BLOB NOT NULL UNIQUE CHECK(length(candidate)=16),
                challenge BLOB NOT NULL UNIQUE CHECK(length(challenge)=32), phone BLOB NOT NULL CHECK(length(phone)=16),
                enrollment BLOB NOT NULL CHECK(length(enrollment)=16), payload BLOB NOT NULL, signature BLOB NOT NULL CHECK(length(signature)=64),
                revision BLOB NOT NULL UNIQUE CHECK(length(revision)=8), run BLOB NOT NULL CHECK(length(run)=16),
                deadline BLOB NOT NULL CHECK(length(deadline)=8), token BLOB CHECK(token IS NULL OR (length(token)>0 AND length(token)<=16384))
            ) STRICT, WITHOUT ROWID
            """)
        try exec("CREATE INDEX gateway_pending_v1 ON gateway_candidates_v1(phone,enrollment) WHERE token IS NOT NULL")
        try exec("PRAGMA application_id=\(Self.applicationID)"); try exec("PRAGMA user_version=1")
    }
    private func validateIdentity() throws {
        guard try scalar("PRAGMA application_id") == Self.applicationID, try scalar("PRAGMA user_version") == 1 else {
            throw GatewayDatabaseError.incompatibleStore
        }
        try statement("SELECT id,identity,head FROM gateway_identity_v1") {
            guard sqlite3_step($0) == SQLITE_ROW, sqlite3_column_int64($0, 0) == 1 else { throw GatewayDatabaseError.incompatibleStore }
            guard try blob($0, 1, maximum: 512) == identity.encode() else { throw GatewayDatabaseError.wrongScope }
            _ = try unsigned(blob($0, 2, maximum: 8))
            guard sqlite3_step($0) == SQLITE_DONE else { throw GatewayDatabaseError.incompatibleStore }
        }
        try statement("SELECT operation,candidate,challenge,phone,enrollment,payload,signature,revision,run,deadline,token FROM gateway_candidates_v1 LIMIT 0") {
            guard sqlite3_step($0) == SQLITE_DONE else { throw GatewayDatabaseError.incompatibleStore }
        }
        guard try scalar("SELECT count(*) FROM gateway_candidates_v1") <= maximumOperations else { throw GatewayDatabaseError.capacityExceeded }
    }
    private func shutdown() {
        if let db { precondition(sqlite3_close(db) == SQLITE_OK, "Gateway retained a private SQLite resource"); self.db = nil }
        lease.close()
    }
    private func exec(_ sql: String) throws {
        let rc = sqlite3_exec(db, sql, nil, nil, nil)
        guard rc == SQLITE_OK else { throw GatewayDatabaseError.storage(rc) }
    }
    private func statement<T>(_ sql: String, _ values: [Data] = [], _ body: (OpaquePointer) throws -> T) throws -> T {
        var stmt: OpaquePointer?
        let rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nil)
        guard rc == SQLITE_OK, let stmt else { throw GatewayDatabaseError.storage(rc) }
        defer { sqlite3_finalize(stmt) }
        for (index, value) in values.enumerated() {
            guard value.count <= Int(Int32.max) else { throw GatewayDatabaseError.invalidConfiguration }
            let rc = value.withUnsafeBytes { sqlite3_bind_blob(stmt, Int32(index + 1), $0.baseAddress, Int32($0.count), unsafeBitCast(-1, to: sqlite3_destructor_type.self)) }
            guard rc == SQLITE_OK else { throw GatewayDatabaseError.storage(rc) }
        }
        return try body(stmt)
    }
    private func done(_ stmt: OpaquePointer) throws {
        let rc = sqlite3_step(stmt)
        guard rc == SQLITE_DONE else { throw GatewayDatabaseError.storage(rc) }
    }
    private func scalar(_ sql: String) throws -> Int64 {
        try statement(sql) { guard sqlite3_step($0) == SQLITE_ROW else { throw GatewayDatabaseError.storage(sqlite3_errcode(db)) }; return sqlite3_column_int64($0, 0) }
    }
    private func scalarText(_ sql: String) throws -> String {
        try statement(sql) {
            guard sqlite3_step($0) == SQLITE_ROW, let value = sqlite3_column_text($0, 0) else { throw GatewayDatabaseError.storage(sqlite3_errcode(db)) }
            return String(cString: value)
        }
    }
    private func blob(_ stmt: OpaquePointer, _ column: Int32, maximum: Int) throws -> Data {
        let count = Int(sqlite3_column_bytes(stmt, column))
        guard sqlite3_column_type(stmt, column) == SQLITE_BLOB, count > 0, count <= maximum,
              let value = sqlite3_column_blob(stmt, column) else { throw GatewayDatabaseError.corruptData }
        return Data(bytes: value, count: count)
    }
    private func uint(_ value: UInt64) -> Data { withUnsafeBytes(of: value.bigEndian) { Data($0) } }
    private func unsigned(_ data: Data) throws -> UInt64 {
        guard data.count == 8 else { throw GatewayDatabaseError.corruptData }
        return data.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
    }
    private func uuid(_ value: UUID) -> Data { withUnsafeBytes(of: value.uuid) { Data($0) } }
}
