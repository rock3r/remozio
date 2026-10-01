import Foundation
import RemozioProtocol
import SQLite3

public enum ConsumptionJournalError: Error, Equatable {
    case invalidConfiguration, wrongScope, alreadyConsumed, capacityExceeded, corruptData
}

/// Historical evidence only. Neither this receipt nor its decision can authorize dispatch or recreate a pending request.
public struct ConsumptionReceipt: Equatable, Sendable {
    public let decision: DecisionPayload
    public let event: AuditEventMetadata
}

/// Private to the connection owner. Writes must share the audit transaction; no independent ledger API escapes.
final class ConsumptionJournal {
    private let db: OpaquePointer
    private let macID: Data
    private let accountID: Data
    private let decisionLimits: CBORLimits
    private let recordLimits: CBORLimits
    private let maximumRows: Int

    init(connection: OpaquePointer, macID: Data, accountID: Data, decisionLimits: CBORLimits,
         recordLimits: CBORLimits, maximumRows: Int) {
        db = connection; self.macID = macID; self.accountID = accountID
        self.decisionLimits = decisionLimits; self.recordLimits = recordLimits; self.maximumRows = maximumRows
    }

    func createSchema() throws {
        try execute("""
            CREATE TABLE main.consumptions_v1 (
                mac BLOB NOT NULL CHECK(length(mac)=16), account BLOB NOT NULL CHECK(length(account)=16),
                request BLOB NOT NULL CHECK(length(request)=16), decision BLOB NOT NULL, event BLOB NOT NULL,
                PRIMARY KEY(mac,account,request)
            ) STRICT, WITHOUT ROWID
            """)
    }

    func consume(canonicalDecision: Data, signature: Data, retained: RetainedApprovalRequest,
                 trust: ApprovalTrustSnapshot, now: AuthorityMoment, eventID: Data, receiptTimeMs: UInt64?,
                 writer: AuditEpochWriter, expectedHead: UInt64, audit: AuditJournalTables,
                 requestLimits: CBORLimits, signingLimits: CBORLimits) throws -> ConsumptionReceipt {
        guard retained.payload.macID == macID, retained.payload.accountID == accountID else { throw ConsumptionJournalError.wrongScope }
        let verified = try DecisionVerifier.verify(canonicalDecision: canonicalDecision, signature: signature, retained: retained,
            trust: trust, now: now, decisionLimits: decisionLimits, requestLimits: requestLimits, signingLimits: signingLimits)
        let decision = verified.decision
        guard try receipt(requestID: decision.requestID) == nil else { throw ConsumptionJournalError.alreadyConsumed }
        try statement("SELECT count(*) FROM main.consumptions_v1 WHERE mac=? AND account=?", [macID, accountID]) {
            guard sqlite3_step($0) == SQLITE_ROW else { throw JournalDatabaseError.storage(sqlite3_errcode(db)) }
            guard sqlite3_column_int64($0, 0) < Int64(maximumRows) else { throw ConsumptionJournalError.capacityExceeded }
        }
        guard expectedHead < UInt64.max else { throw AuditJournalError.headMismatch }
        let category: AuditCategory
        switch retained.payload.contract.requestKind {
        case .command: category = .command
        case .onePasswordAccess: category = .onePasswordAccess
        case .onePasswordUnlock: category = .onePasswordUnlock
        case .littleSnitch: category = .littleSnitch
        }
        let resolves = verified.requirement.effect == .resolveRequest
        let event = try AuditEventMetadata(eventID: eventID, macID: macID, accountID: accountID,
            journalEpoch: writer.epoch, sequence: expectedHead + 1, requestID: decision.requestID,
            eventTimeMs: nil, authorityReceiptTimeMs: receiptTimeMs, kind: .consumed, category: category,
            action: AuditActionMetadata(action: decision.action), decisionPhoneID: decision.phoneID,
            authentication: verified.requirement.keyClass == .biometric ? .biometricKey : .decisionKey,
            outcome: resolves ? .noDispatch : .accepted, reason: resolves ? .userDeclined : .none,
            droppedEventCount: nil, peerDeviceID: nil)
        let body = try event.encode(limits: recordLimits)
        try statement("INSERT INTO main.consumptions_v1 VALUES(?,?,?,?,?)", [macID, accountID, decision.requestID, canonicalDecision, body]) {
            let rc = sqlite3_step($0)
            guard rc == SQLITE_DONE else { throw JournalDatabaseError.storage(rc) }
        }
        try audit.append(body, writer: writer, expectedHead: expectedHead)
        return ConsumptionReceipt(decision: decision, event: event)
    }

    func receipt(requestID: Data) throws -> ConsumptionReceipt? {
        guard requestID.count == 16 else { throw ConsumptionJournalError.wrongScope }
        return try statement("SELECT decision,event FROM main.consumptions_v1 WHERE mac=? AND account=? AND request=?", [macID, accountID, requestID]) {
            let rc = sqlite3_step($0)
            if rc == SQLITE_DONE { return nil }
            guard rc == SQLITE_ROW else { throw JournalDatabaseError.storage(rc) }
            let decision = try DecisionPayload.decode(blob($0, 0, maximum: decisionLimits.maxBytes), limits: decisionLimits)
            let event = try AuditEventMetadata.decode(blob($0, 1, maximum: recordLimits.maxBytes), limits: recordLimits)
            guard decision.macID == macID, decision.accountID == accountID, decision.requestID == requestID,
                  event.macID == macID, event.accountID == accountID, event.requestID == requestID,
                  event.decisionPhoneID == decision.phoneID, event.action == AuditActionMetadata(action: decision.action),
                  event.kind == .consumed, event.peerDeviceID == nil else { throw ConsumptionJournalError.corruptData }
            let kind: RequestKind
            switch event.category {
            case .command: kind = .command
            case .onePasswordAccess: kind = .onePasswordAccess
            case .onePasswordUnlock: kind = .onePasswordUnlock
            case .littleSnitch: kind = .littleSnitch
            default: throw ConsumptionJournalError.corruptData
            }
            let requirement = try ActionPolicy.requirement(for: decision.action, requestKind: kind, retainedPermittedActions: [decision.action])
            let resolves = requirement.effect == .resolveRequest
            guard event.authentication == (requirement.keyClass == .biometric ? .biometricKey : .decisionKey),
                  event.outcome == (resolves ? .noDispatch : .accepted), event.reason == (resolves ? .userDeclined : .none) else {
                throw ConsumptionJournalError.corruptData
            }
            return ConsumptionReceipt(decision: decision, event: event)
        }
    }

    private func execute(_ sql: String) throws {
        let rc = sqlite3_exec(db, sql, nil, nil, nil)
        guard rc == SQLITE_OK else { throw JournalDatabaseError.storage(rc) }
    }
    private func statement<T>(_ sql: String, _ values: [Data], _ body: (OpaquePointer) throws -> T) throws -> T {
        var value: OpaquePointer?
        let rc = sqlite3_prepare_v2(db, sql, -1, &value, nil)
        guard rc == SQLITE_OK, let value else { throw JournalDatabaseError.storage(rc) }
        defer { sqlite3_finalize(value) }
        for (index, data) in values.enumerated() {
            guard data.count <= Int(Int32.max) else { throw ConsumptionJournalError.invalidConfiguration }
            let rc = data.withUnsafeBytes { sqlite3_bind_blob(value, Int32(index + 1), $0.baseAddress, Int32($0.count), unsafeBitCast(-1, to: sqlite3_destructor_type.self)) }
            guard rc == SQLITE_OK else { throw JournalDatabaseError.storage(rc) }
        }
        return try body(value)
    }
    private func blob(_ statement: OpaquePointer, _ column: Int32, maximum: Int) throws -> Data {
        let count = Int(sqlite3_column_bytes(statement, column))
        guard sqlite3_column_type(statement, column) == SQLITE_BLOB, count > 0, count <= maximum,
              let pointer = sqlite3_column_blob(statement, column) else { throw ConsumptionJournalError.corruptData }
        return Data(bytes: pointer, count: count)
    }
}
