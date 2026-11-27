import CryptoKit
import Foundation
import SQLite3

/// Evidence from one journal transaction. These hashes do not grant admission or dispatch authority.
public struct JournalContinuityDigests: Equatable, Sendable {
    public let authority: Data
    public let ledger: Data
}

/// The catalog is part of the digest format. A schema change requires an explicit format review.
enum JournalContinuityDigest {
    private static let authorityTables = [
        "journal_identity_v1", "approval_authority_v1", "approval_enrollments_v1", "pairing_commits_v1",
        "routing_state_v1", "routing_operations_v1", "gateway_authority_v1", "gateway_outbox_v1",
        "gateway_root_candidates_v1", "gateway_desired_tokens_v1", "gateway_revocations_v1",
        "gateway_acknowledgment_v1", "gateway_reconciled_controls_v1", "gateway_recovered_revocations_v1",
        "gateway_trust_restrictions_v1",
    ]
    private static let ledgerTables = [
        "journal_identity_v1", "audit_epochs_v1", "audit_records_v1", "consumptions_v1", "consumption_outcomes_v1",
    ]

    static func read(_ db: OpaquePointer) throws -> JournalContinuityDigests {
        guard sqlite3_get_autocommit(db) == 0 else { throw JournalDatabaseError.expiredTransaction }
        let format = try AuthorityJournalSchema.formatVersion(on: db)
        let recoveryFormat = format >= AuthorityJournalSchema.recoveryFormat
        let permanentReplay = format == AuthorityJournalSchema.permanentReplayFormat
        let tier = try AuthorityJournalSchema.featureTier(on: db)
        let catalog = try requireCatalog(db, recoveryFormat: recoveryFormat, tier: tier, permanentReplay: permanentReplay)
        let authoritySchema = recoveryFormat ? format : (tier >= 15 ? tier : min(tier, 13))
        return try withUnsafeTemporaryAllocation(byteCount: DigestEncoder.capacity, alignment: 1) { buffer in
            try JournalContinuityDigests(
                authority: digest(db, tables: catalog.authority, domain: "authority", schema: authoritySchema, buffer: buffer),
                ledger: digest(db, tables: catalog.ledger, domain: "ledger", buffer: buffer))
        }
    }

    static func requireCatalog(_ db: OpaquePointer, recoveryFormat: Bool, tier: Int64,
                               permanentReplay: Bool = false) throws -> (authority: [String], ledger: [String]) {
        var tables = Set<String>()
        try rows(db, "SELECT name FROM main.sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name") { row in
            guard let name = sqlite3_column_text(row, 0) else { throw JournalDatabaseError.incompatibleStore }
            tables.insert(String(cString: name))
        }
        guard (12...18).contains(tier), !permanentReplay || (recoveryFormat && tier >= 15) else {
            throw JournalDatabaseError.incompatibleStore
        }
        if permanentReplay { try PermanentReplayJournal.validateSchema(on: db) }
        let authorityTables = Self.authorityTables + (tier >= 13 ? ["authority_code_policy_v1"] : [])
            + (tier >= 15 && !permanentReplay ? ["command_submissions_v1"] : [])
            + (permanentReplay ? PermanentReplayJournal.tables : [])
            + (tier >= 16 ? ["gateway_submission_outbox_v1"] : [])
            + (tier >= 17 ? ["update_scheduling_state_v1", "update_scheduling_operations_v1"] : [])
            + (tier >= 18 ? [GatewayAuthorityJournal.abandonmentTable] : [])
            + (recoveryFormat ? [AuthorityJournalSchema.tierTable, PairingRecoveryStageJournal.table] : [])
        let ledgerTables = Self.ledgerTables + (tier >= 14 ? ["history_recoveries_v1"] : [])
            + (permanentReplay ? ["command_submissions_v1"] : [])
        guard tables == Set(authorityTables + ledgerTables) else { throw JournalDatabaseError.incompatibleStore }
        return (authorityTables, ledgerTables)
    }

    private static func digest(_ db: OpaquePointer, tables: [String], domain: String, schema: Int64 = 12,
                               buffer: UnsafeMutableRawBufferPointer) throws -> Data {
        var encoder = DigestEncoder(buffer: buffer.baseAddress!)
        encoder.field(Data("remozio/journal-continuity/v1/schema\(schema)/\(domain)".utf8))
        for table in tables.sorted() {
            encoder.field(Data(table.utf8))
            var columns = [String]()
            try rows(db, "PRAGMA main.table_info('\(table)')") { row in
                guard let name = sqlite3_column_text(row, 1) else { throw JournalDatabaseError.incompatibleStore }
                columns.append(String(cString: name))
            }
            guard !columns.isEmpty else { throw JournalDatabaseError.incompatibleStore }
            encoder.number(UInt64(columns.count))
            for column in columns { encoder.field(Data(column.utf8)) }
            // Ordinals avoid interpreting column names as SQL. Sorting every value also handles composite keys.
            let order = (1...columns.count).map(String.init).joined(separator: ",")
            try rows(db, "SELECT * FROM main.\(table) ORDER BY \(order)") { row in
                encoder.byte(1)
                for index in columns.indices {
                    let column = Int32(index)
                    let type = sqlite3_column_type(row, column)
                    switch type {
                    case SQLITE_NULL: encoder.byte(0)
                    case SQLITE_INTEGER:
                        encoder.taggedNumber(1, UInt64(bitPattern: sqlite3_column_int64(row, column)))
                    case SQLITE_TEXT, SQLITE_BLOB:
                        let text = type == SQLITE_TEXT
                        let pointer = text ? sqlite3_column_text(row, column).map(UnsafeRawPointer.init) : sqlite3_column_blob(row, column)
                        let size = Int(sqlite3_column_bytes(row, column))
                        guard size == 0 || pointer != nil else { throw JournalDatabaseError.storage(SQLITE_NOMEM) }
                        encoder.taggedField(text ? 2 : 3, UnsafeRawBufferPointer(start: pointer, count: size))
                    default: throw JournalDatabaseError.incompatibleStore
                    }
                }
            }
            encoder.byte(0)
        }
        return encoder.finish()
    }

    private struct DigestEncoder {
        static let capacity = 16_384
        private static let numberBytes = MemoryLayout<UInt64>.size
        private static let taggedHeaderBytes = 1 + numberBytes
        // The caller owns this scratch allocation for the duration of both digests.
        private let buffer: UnsafeMutableRawPointer
        private var count = 0
        private var hash = SHA256()

        init(buffer: UnsafeMutableRawPointer) { self.buffer = buffer }

        mutating func byte(_ value: UInt8) {
            reserve(1)
            writeByte(value)
        }

        mutating func number(_ value: UInt64) {
            reserve(Self.numberBytes)
            writeNumber(value)
        }

        mutating func taggedNumber(_ tag: UInt8, _ value: UInt64) {
            reserve(Self.taggedHeaderBytes)
            writeByte(tag)
            writeNumber(value)
        }

        mutating func field(_ data: Data) {
            number(UInt64(data.count))
            data.withUnsafeBytes { bytes in
                if bytes.count >= Self.capacity {
                    flush()
                    hash.update(bufferPointer: bytes)
                } else {
                    reserve(bytes.count)
                    copy(bytes)
                }
            }
        }

        mutating func taggedField(_ tag: UInt8, _ bytes: UnsafeRawBufferPointer) {
            if bytes.count <= Self.capacity - Self.taggedHeaderBytes {
                reserve(Self.taggedHeaderBytes + bytes.count)
                writeByte(tag)
                writeNumber(UInt64(bytes.count))
                copy(bytes)
            } else {
                taggedNumber(tag, UInt64(bytes.count))
                flush()
                // SQLite owns these bytes until the next step.
                hash.update(bufferPointer: bytes)
            }
        }

        mutating func finish() -> Data {
            flush()
            return Data(hash.finalize())
        }

        private mutating func reserve(_ length: Int) {
            if length > Self.capacity - count { flush() }
        }

        private mutating func writeByte(_ value: UInt8) {
            buffer.storeBytes(of: value, toByteOffset: count, as: UInt8.self)
            count += 1
        }

        private mutating func writeNumber(_ value: UInt64) {
            var bigEndian = value.bigEndian
            withUnsafeBytes(of: &bigEndian) { bytes in
                // Fields need not start at an aligned offset.
                buffer.advanced(by: count).copyMemory(from: bytes.baseAddress!, byteCount: Self.numberBytes)
            }
            count += Self.numberBytes
        }

        private mutating func copy(_ bytes: UnsafeRawBufferPointer) {
            if let start = bytes.baseAddress, !bytes.isEmpty {
                buffer.advanced(by: count).copyMemory(from: start, byteCount: bytes.count)
                count += bytes.count
            }
        }

        private mutating func flush() {
            guard count != 0 else { return }
            hash.update(bufferPointer: UnsafeRawBufferPointer(start: buffer, count: count))
            count = 0
        }
    }

    private static func rows(_ db: OpaquePointer, _ sql: String, _ body: (OpaquePointer) throws -> Void) throws {
        var statement: OpaquePointer?
        let result = sqlite3_prepare_v2(db, sql, -1, &statement, nil)
        guard result == SQLITE_OK, let statement else { throw JournalDatabaseError.storage(result) }
        defer { sqlite3_finalize(statement) }
        while true {
            let result = sqlite3_step(statement)
            if result == SQLITE_DONE { return }
            guard result == SQLITE_ROW else { throw JournalDatabaseError.storage(result) }
            try body(statement)
        }
    }
}
