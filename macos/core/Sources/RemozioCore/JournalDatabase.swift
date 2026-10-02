import Foundation
import RemozioProtocol
import SQLite3

public enum JournalDatabaseError: Error, Equatable {
    case invalidConfiguration, incompatibleStore, wrongScope, closed, unavailable, transactionActive, expiredTransaction, readOnly, transactionFailed
    case storage(Int32)
}

/// One Mac/account's journal connection. The root authority owns this object and serializes its calls.
/// This storage layer has no admission, checkpoint or dispatch authority.
public final class JournalDatabase {
    private static let applicationID: Int64 = 0x524D5A4F
    private let lease: ProtectedJournalLease
    private var db: OpaquePointer?
    private var tables: AuditJournalTables?
    private var consumption: ConsumptionJournal?
    private var gateway: GatewayAuthorityJournal?
    private var enrollment: EnrollmentJournal?
    private let recordLimits: CBORLimits
    private var active: UUID?
    private var unavailable = false

    /// `initialize` is an explicit setup operation on an empty, already provisioned file. Never use it as recovery.
    public static func open(directoryPath: String, macID: Data, accountID: Data,
                            recordLimits: CBORLimits, descriptorLimits: CBORLimits, decisionLimits: CBORLimits,
                            maximumConsumptions: Int, busyMilliseconds: UInt32, initialize: Bool = false, migrateFromVersion: Int64? = nil, gatewayPolicy: GatewayAuthorityPolicy? = nil) throws -> JournalDatabase {
        try JournalDatabase(lease: ProtectedJournalLease.acquire(directoryPath: directoryPath), macID: macID, accountID: accountID,
                            recordLimits: recordLimits, descriptorLimits: descriptorLimits, decisionLimits: decisionLimits,
                            maximumConsumptions: maximumConsumptions, busyMilliseconds: busyMilliseconds,
                            initialize: initialize, migrateFromVersion: migrateFromVersion, gatewayPolicy: gatewayPolicy)
    }

    /// Internal fixture entry point. Ownership of the lease transfers to this connection, including on failure.
    init(lease: ProtectedJournalLease, macID: Data, accountID: Data,
         recordLimits: CBORLimits, descriptorLimits: CBORLimits, decisionLimits: CBORLimits,
         maximumConsumptions: Int, busyMilliseconds: UInt32, initialize: Bool, migrateFromVersion: Int64? = nil, gatewayPolicy: GatewayAuthorityPolicy? = nil) throws {
        self.lease = lease
        self.recordLimits = recordLimits
        do {
            guard macID.count == 16, accountID.count == 16, busyMilliseconds <= 60_000,
                  maximumConsumptions > 0, maximumConsumptions <= Int(Int32.max), !(initialize && migrateFromVersion != nil),
                  migrateFromVersion == nil || migrateFromVersion == 1 || migrateFromVersion == 2 || migrateFromVersion == 3 || migrateFromVersion == 4 || migrateFromVersion == 5,
                  max(recordLimits.maxBytes, descriptorLimits.maxBytes) <= Int(Int32.max) - 4096,
                  decisionLimits.maxBytes <= Int(Int32.max) - 4096 - recordLimits.maxBytes else {
                throw JournalDatabaseError.invalidConfiguration
            }
            try lease.validate()
            var connection: OpaquePointer?
            let rc = sqlite3_open_v2(lease.databasePath, &connection, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_NOFOLLOW, nil)
            db = connection
            guard rc == SQLITE_OK, let connection else { throw JournalDatabaseError.storage(rc) }
            try lease.validate()
            guard sqlite3_busy_timeout(connection, Int32(busyMilliseconds)) == SQLITE_OK,
                  sqlite3_compileoption_used("OMIT_LOAD_EXTENSION") == 1 else { throw JournalDatabaseError.invalidConfiguration }
            _ = sqlite3_limit(connection, SQLITE_LIMIT_ATTACHED, 0)
            _ = sqlite3_limit(connection, SQLITE_LIMIT_LENGTH, Int32(max(max(recordLimits.maxBytes + decisionLimits.maxBytes, descriptorLimits.maxBytes) + 4096, max((gatewayPolicy?.payloadLimits.maxBytes ?? 0) + 32768, 65536))))
            try exec("PRAGMA trusted_schema=OFF")
            try exec("PRAGMA foreign_keys=ON")
            if initialize { try requireEmptyStore() }
            else { try validateIdentity(macID: macID, accountID: accountID, version: migrateFromVersion ?? 6) }
            try exec("PRAGMA journal_mode=DELETE")
            try exec("PRAGMA synchronous=EXTRA")
            try exec("PRAGMA fullfsync=ON")
            guard try text("PRAGMA journal_mode") == "delete", try integer("PRAGMA synchronous") == 3,
                  try integer("PRAGMA fullfsync") == 1, try integer("PRAGMA foreign_keys") == 1,
                  try integer("PRAGMA trusted_schema") == 0 else { throw JournalDatabaseError.invalidConfiguration }
            let tables = try AuditJournalTables(connection: connection, macID: macID, accountID: accountID,
                                                 recordLimits: recordLimits, descriptorLimits: descriptorLimits)
            self.tables = tables
            let consumption = ConsumptionJournal(connection: connection, macID: macID, accountID: accountID,
                decisionLimits: decisionLimits, recordLimits: recordLimits, maximumRows: maximumConsumptions)
            self.consumption = consumption
            enrollment = EnrollmentJournal(connection: connection, macID: macID, accountID: accountID)
            if let gatewayPolicy { gateway = GatewayAuthorityJournal(connection: connection, macID: macID, accountID: accountID, policy: gatewayPolicy) }
            if initialize { try create(macID: macID, accountID: accountID, tables: tables, consumption: consumption) }
            else if let migrateFromVersion { try migrate(macID: macID, accountID: accountID, consumption: consumption, from: migrateFromVersion) }
            try validateIdentity(macID: macID, accountID: accountID)
            try lease.validate()
        } catch {
            shutdown()
            throw error
        }
    }

    deinit { shutdown() }

    public func read<T>(_ body: (JournalTransaction) throws -> T) throws -> T { try transaction(write: false, body) }
    public func write<T>(_ body: (JournalTransaction) throws -> T) throws -> T { try transaction(write: true, body) }

    public func close() throws {
        guard active == nil else { throw JournalDatabaseError.transactionActive }
        shutdown()
    }

    private func transaction<T>(write: Bool, _ body: (JournalTransaction) throws -> T) throws -> T {
        guard db != nil else { throw JournalDatabaseError.closed }
        guard !unavailable else { throw JournalDatabaseError.unavailable }
        guard active == nil else { throw JournalDatabaseError.transactionActive }
        try validateLease()
        try exec(write ? "BEGIN IMMEDIATE" : "BEGIN")
        let token = UUID()
        active = token
        defer { active = nil }
        let scope = JournalTransaction(owner: self, token: token, writable: write)
        do {
            let value = try body(scope)
            guard !scope.failed else { throw JournalDatabaseError.transactionFailed }
            try validateLease()
            do { try exec("COMMIT") }
            catch { unavailable = true; throw error }
            try validateLease()
            return value
        } catch {
            if scope.createdEpoch || scope.headMismatch { unavailable = true }
            if let db, sqlite3_get_autocommit(db) == 0 {
                if sqlite3_exec(db, "ROLLBACK", nil, nil, nil) != SQLITE_OK { unavailable = true }
            } else if write { unavailable = true }
            throw error
        }
    }

    fileprivate func access(_ token: UUID) throws -> AuditJournalTables {
        guard db != nil, active == token, !unavailable, let tables else { throw JournalDatabaseError.expiredTransaction }
        try validateLease()
        return tables
    }

    fileprivate func ledger(_ token: UUID) throws -> ConsumptionJournal {
        _ = try access(token)
        guard let consumption else { throw JournalDatabaseError.expiredTransaction }
        return consumption
    }

    fileprivate func gatewayLedger(_ token: UUID) throws -> GatewayAuthorityJournal {
        _ = try access(token)
        guard let gateway else { throw GatewayAuthorityError.disabled }
        return gateway
    }

    fileprivate func appendEnrollmentEvent(_ event: AuditEventMetadata, token: UUID, writer: AuditEpochWriter, expectedHead: UInt64) throws {
        try access(token).append(event.encode(limits: recordLimits), writer: writer, expectedHead: expectedHead)
    }

    fileprivate func enrollmentLedger(_ token: UUID) throws -> EnrollmentJournal {
        _ = try access(token)
        guard let enrollment else { throw JournalDatabaseError.expiredTransaction }
        return enrollment
    }

    private func validateLease() throws {
        do { try lease.validate() }
        catch { unavailable = true; throw error }
    }

    private func create(macID: Data, accountID: Data, tables: AuditJournalTables, consumption: ConsumptionJournal) throws {
        try exec("BEGIN IMMEDIATE")
        do {
            try requireEmptyStore()
            try exec("CREATE TABLE main.journal_identity_v1(id INTEGER PRIMARY KEY CHECK(id=1), mac BLOB NOT NULL CHECK(length(mac)=16), account BLOB NOT NULL CHECK(length(account)=16)) STRICT")
            try statement("INSERT INTO main.journal_identity_v1 VALUES(1,?,?)") { stmt in
                for (index, value) in [macID, accountID].enumerated() {
                    let rc = value.withUnsafeBytes { sqlite3_bind_blob(stmt, Int32(index + 1), $0.baseAddress, Int32($0.count), unsafeBitCast(-1, to: sqlite3_destructor_type.self)) }
                    guard rc == SQLITE_OK else { throw JournalDatabaseError.storage(rc) }
                }
                guard sqlite3_step(stmt) == SQLITE_DONE else { throw JournalDatabaseError.storage(sqlite3_errcode(db)) }
            }
            try tables.createSchema()
            try consumption.createSchema()
            try consumption.createOutcomeSchema()
            try GatewayAuthorityJournal.createSchema(db!)
            try GatewayAuthorityJournal.createRevocationSchema(db!)
            try EnrollmentJournal.createSchema(db!)
            try exec("PRAGMA application_id=\(Self.applicationID)")
            try exec("PRAGMA user_version=6")
            try lease.validate()
            try exec("COMMIT")
        } catch { _ = sqlite3_exec(db, "ROLLBACK", nil, nil, nil); throw error }
    }

    private func migrate(macID: Data, accountID: Data, consumption: ConsumptionJournal, from version: Int64) throws {
        try exec("BEGIN IMMEDIATE")
        do {
            try validateIdentity(macID: macID, accountID: accountID, version: version)
            if version == 1 { try consumption.createSchema() }
            if version < 3 { try consumption.createOutcomeSchema() }
            if version < 4 { try GatewayAuthorityJournal.createSchema(db!) }
            if version < 5 { try GatewayAuthorityJournal.createRevocationSchema(db!) }
            try EnrollmentJournal.createSchema(db!)
            try exec("PRAGMA user_version=6")
            try lease.validate()
            try exec("COMMIT")
        } catch { _ = sqlite3_exec(db, "ROLLBACK", nil, nil, nil); throw error }
    }

    private func requireEmptyStore() throws {
        guard try integer("PRAGMA application_id") == 0, try integer("PRAGMA user_version") == 0,
              try integer("SELECT count(*) FROM main.sqlite_schema WHERE name NOT LIKE 'sqlite_%'") == 0 else {
            throw JournalDatabaseError.incompatibleStore
        }
    }

    private func validateIdentity(macID: Data, accountID: Data, version: Int64 = 6) throws {
        guard try integer("PRAGMA application_id") == Self.applicationID, try integer("PRAGMA user_version") == version else {
            throw JournalDatabaseError.incompatibleStore
        }
        try statement("SELECT id,mac,account FROM main.journal_identity_v1") { stmt in
            guard sqlite3_step(stmt) == SQLITE_ROW, sqlite3_column_int64(stmt, 0) == 1 else { throw JournalDatabaseError.incompatibleStore }
            for (column, value) in [(Int32(1), macID), (Int32(2), accountID)] {
                guard sqlite3_column_type(stmt, column) == SQLITE_BLOB, sqlite3_column_bytes(stmt, column) == 16,
                      let pointer = sqlite3_column_blob(stmt, column) else { throw JournalDatabaseError.incompatibleStore }
                guard Data(bytes: pointer, count: 16) == value else { throw JournalDatabaseError.wrongScope }
            }
            guard sqlite3_step(stmt) == SQLITE_DONE else { throw JournalDatabaseError.incompatibleStore }
        }
        var queries = ["SELECT mac,account,epoch,descriptor,head,retained FROM main.audit_epochs_v1 LIMIT 0",
                       "SELECT mac,account,epoch,sequence,event,body FROM main.audit_records_v1 LIMIT 0"]
        if version >= 2 { queries.append("SELECT mac,account,request,decision,event FROM main.consumptions_v1 LIMIT 0") }
        if version >= 3 { queries.append("SELECT mac,account,request,revision,event FROM main.consumption_outcomes_v1 LIMIT 0") }
        if version >= 4 {
            queries += ["SELECT id,identity,head FROM main.gateway_authority_v1 LIMIT 0",
                        "SELECT operation,revision,kind,candidate,payload,signature,token FROM main.gateway_outbox_v1 LIMIT 0",
                        "SELECT candidate,phone,enrollment,operation,run,started,deadline,consumed FROM main.gateway_root_candidates_v1 LIMIT 0",
                        "SELECT phone,candidate FROM main.gateway_desired_tokens_v1 LIMIT 0"]
        }
        if version >= 5 { queries.append("SELECT operation,revision,phone,enrollment,payload,signature,run,started,deadline FROM main.gateway_revocations_v1 LIMIT 0") }
        if version >= 6 {
            queries += ["SELECT id,policy,revision FROM main.approval_authority_v1 LIMIT 0",
                        "SELECT phone,epoch,active,body FROM main.approval_enrollments_v1 LIMIT 0"]
        }
        for query in queries {
            try statement(query) { guard sqlite3_step($0) == SQLITE_DONE else { throw JournalDatabaseError.incompatibleStore } }
        }
    }

    private func shutdown() {
        tables = nil
        consumption = nil
        gateway = nil
        enrollment = nil
        if let db {
            // No statement, blob handle or raw connection can escape this owner.
            precondition(sqlite3_close(db) == SQLITE_OK, "Journal connection retained a private SQLite resource")
            self.db = nil
        }
        lease.close()
    }
    private func exec(_ sql: String) throws {
        let rc = sqlite3_exec(db, sql, nil, nil, nil)
        guard rc == SQLITE_OK else { throw JournalDatabaseError.storage(rc) }
    }
    private func statement<T>(_ sql: String, _ body: (OpaquePointer) throws -> T) throws -> T {
        var value: OpaquePointer?
        let rc = sqlite3_prepare_v2(db, sql, -1, &value, nil)
        guard rc == SQLITE_OK, let value else { throw JournalDatabaseError.storage(rc) }
        defer { sqlite3_finalize(value) }
        return try body(value)
    }
    private func integer(_ sql: String) throws -> Int64 {
        try statement(sql) {
            guard sqlite3_step($0) == SQLITE_ROW else { throw JournalDatabaseError.storage(sqlite3_errcode(db)) }
            return sqlite3_column_int64($0, 0)
        }
    }
    private func text(_ sql: String) throws -> String {
        try statement(sql) {
            guard sqlite3_step($0) == SQLITE_ROW, let text = sqlite3_column_text($0, 0) else { throw JournalDatabaseError.storage(sqlite3_errcode(db)) }
            return String(cString: text)
        }
    }
}

/// Valid only inside its owner's synchronous callback. Escaping this object does not retain connection access.
public final class JournalTransaction {
    private weak var owner: JournalDatabase?
    private let token: UUID
    private let writable: Bool
    fileprivate var failed = false
    fileprivate var headMismatch = false
    fileprivate var createdEpoch = false
    fileprivate init(owner: JournalDatabase, token: UUID, writable: Bool) {
        self.owner = owner; self.token = token; self.writable = writable
    }
    private func tables(write: Bool = false) throws -> AuditJournalTables {
        guard let owner else { throw JournalDatabaseError.expiredTransaction }
        guard !write || writable else { throw JournalDatabaseError.readOnly }
        return try owner.access(token)
    }
    public func epoch(_ id: Data) throws -> AuditEpochRead? { try tables().epoch(id) }
    public func page(epoch: Data, after: UInt64, maximumRecords: Int, maximumBytes: Int) throws -> AuditJournalPage {
        try tables().page(epoch: epoch, after: after, maximumRecords: maximumRecords, maximumBytes: maximumBytes)
    }
    private func mutate<T>(_ body: (AuditJournalTables) throws -> T) throws -> T {
        do { return try body(tables(write: true)) }
        catch {
            failed = true
            if error as? AuditJournalError == .headMismatch { headMismatch = true }
            throw error
        }
    }
    /// Internal verification path. Public callers must use the overload that reads durable trust.
    func consume(canonicalDecision: Data, signature: Data, retained: RetainedApprovalRequest,
                        trust: ApprovalTrustSnapshot, now: AuthorityMoment, eventID: Data, receiptTimeMs: UInt64?,
                        writer: AuditEpochWriter, expectedHead: UInt64, requestLimits: CBORLimits,
                        signingLimits: CBORLimits) throws -> ConsumptionReceipt {
        try mutate { audit in
            guard let owner else { throw JournalDatabaseError.expiredTransaction }
            return try owner.ledger(token).consume(canonicalDecision: canonicalDecision, signature: signature,
                retained: retained, trust: trust, now: now, eventID: eventID, receiptTimeMs: receiptTimeMs,
                writer: writer, expectedHead: expectedHead, audit: audit, requestLimits: requestLimits, signingLimits: signingLimits)
        }
    }

    private func withEnrollment<T>(write: Bool, _ body: (EnrollmentJournal) throws -> T) throws -> T {
        do {
            _ = try tables(write: write)
            guard let owner else { throw JournalDatabaseError.expiredTransaction }
            return try body(owner.enrollmentLedger(token))
        } catch {
            failed = true
            if error as? EnrollmentJournalError == .corruptData || error as? AuditJournalError == .headMismatch { headMismatch = true }
            throw error
        }
    }

    /// Protected administrator setup. This stores policy only; it cannot infer trust from audit records or incoming decisions.
    public func configureApprovalAuthority(capabilities: ContractCapabilities, allowedContracts: Set<RequestContract>) throws -> UUID {
        try withEnrollment(write: true) { try $0.configure(capabilities: capabilities, allowed: allowedContracts) }
    }
    public func approvalTrustSnapshot() throws -> ApprovalTrustSnapshot {
        try withEnrollment(write: false) { try $0.snapshot() }
    }
    public func approvalEnrollments() throws -> [StoredApprovalEnrollment] {
        try withEnrollment(write: false) { ledger in _ = try ledger.snapshot(); return try ledger.all() }
    }

    /// The host verifies administrator authorization and the biometric enrollment proof before calling this method.
    public func addApprovalEnrollment(_ enrollment: StoredApprovalEnrollment, expectedTrustRevision: UUID,
                                      eventID: Data, receiptTimeMs: UInt64?, writer: AuditEpochWriter, expectedAuditHead: UInt64) throws -> UUID {
        try withEnrollment(write: true) { ledger in
            let next = try ledger.add(enrollment, expected: expectedTrustRevision)
            try enrollmentEvent(phone: enrollment.approval.phoneID, added: true, eventID: eventID, receiptTimeMs: receiptTimeMs,
                writer: writer, expectedHead: expectedAuditHead, snapshot: ledger.snapshot())
            return next
        }
    }

    /// Removal and its audit event share the transaction with the signed gateway control when a gateway is configured.
    public func revokeApprovalEnrollment(phoneID: Data, epoch: Data, expectedTrustRevision: UUID,
                                         eventID: Data, receiptTimeMs: UInt64?, writer: AuditEpochWriter, expectedAuditHead: UInt64,
                                         gateway: EnrollmentGatewayRemoval? = nil) throws -> (revision: UUID, gatewayControl: GatewayAuthorityEnvelope?) {
        try withEnrollment(write: true) { ledger in
            if try ledger.hasGateway(), gateway == nil { throw EnrollmentJournalError.gatewayRequired }
            let (old, next) = try ledger.revoke(phone: phoneID, epoch: epoch, expected: expectedTrustRevision)
            var control: GatewayAuthorityEnvelope?
            if let gateway {
                let enrollment = try GatewayPhoneEnrollment(phoneID: phoneID, epoch: epoch, tag: old.notificationTag, active: false)
                control = try revokeGatewayEnrollment(trust: GatewayAuthorityTrust(registration: gateway.registration, enrollment: enrollment, active: true),
                    expectedHead: gateway.expectedHead, nowUnixMillis: gateway.nowUnixMillis, now: gateway.now, sign: gateway.sign)
            }
            try enrollmentEvent(phone: phoneID, added: false, eventID: eventID, receiptTimeMs: receiptTimeMs,
                writer: writer, expectedHead: expectedAuditHead, snapshot: ledger.snapshot())
            return (next, control)
        }
    }

    private func enrollmentEvent(phone: Data, added: Bool, eventID: Data, receiptTimeMs: UInt64?, writer: AuditEpochWriter,
                                 expectedHead: UInt64, snapshot: ApprovalTrustSnapshot) throws {
        guard expectedHead < UInt64.max else { throw AuditJournalError.headMismatch }
        let event = try AuditEventMetadata(eventID: eventID, macID: snapshot.macID, accountID: snapshot.accountID,
            journalEpoch: writer.epoch, sequence: expectedHead + 1, requestID: nil, eventTimeMs: nil, authorityReceiptTimeMs: receiptTimeMs,
            kind: added ? .enrollmentAdded : .enrollmentRevoked, category: .enrollment, action: nil, decisionPhoneID: nil,
            authentication: .localAdministrator, outcome: .accepted, reason: added ? .none : .revoked, droppedEventCount: nil, peerDeviceID: phone)
        guard let owner else { throw JournalDatabaseError.expiredTransaction }
        try owner.appendEnrollmentEvent(event, token: token, writer: writer, expectedHead: expectedHead)
    }

    /// Reads current enrolled keys in this write transaction. No caller-supplied enrollment snapshot can authorize consumption.
    public func consume(canonicalDecision: Data, signature: Data, retained: RetainedApprovalRequest,
                        expectedTrustRevision: UUID, now: AuthorityMoment, eventID: Data, receiptTimeMs: UInt64?,
                        writer: AuditEpochWriter, expectedHead: UInt64, requestLimits: CBORLimits,
                        signingLimits: CBORLimits) throws -> ConsumptionReceipt {
        try withEnrollment(write: true) { ledger in
            let trust = try ledger.snapshot()
            guard trust.revision == expectedTrustRevision else { throw EnrollmentJournalError.staleRevision }
            return try consume(canonicalDecision: canonicalDecision, signature: signature, retained: retained, trust: trust,
                now: now, eventID: eventID, receiptTimeMs: receiptTimeMs, writer: writer, expectedHead: expectedHead,
                requestLimits: requestLimits, signingLimits: signingLimits)
        }
    }

    public func consumption(requestID: Data) throws -> ConsumptionReceipt? {
        guard let owner else { throw JournalDatabaseError.expiredTransaction }
        return try owner.ledger(token).receipt(requestID: requestID)
    }

    /// Record a controller-verified observation. No transition grants permission to execute or retry an action.
    public func transitionConsumption(requestID: Data, expectedRevision: UInt64, event: RequestEvent, eventID: Data,
                                      receiptTimeMs: UInt64?, writer: AuditEpochWriter, expectedHead: UInt64) throws -> ConsumptionOutcome {
        try mutate { audit in
            guard let owner else { throw JournalDatabaseError.expiredTransaction }
            return try owner.ledger(token).transition(requestID: requestID, expectedRevision: expectedRevision, event: event,
                eventID: eventID, receiptTimeMs: receiptTimeMs, writer: writer, expectedHead: expectedHead, audit: audit)
        }
    }

    public func consumptionOutcome(requestID: Data) throws -> ConsumptionOutcome? {
        guard let owner else { throw JournalDatabaseError.expiredTransaction }
        return try owner.ledger(token).outcome(requestID: requestID)
    }

    private func withGateway<T>(write: Bool, _ body: (GatewayAuthorityJournal) throws -> T) throws -> T {
        do {
            _ = try tables(write: write)
            guard let owner else { throw JournalDatabaseError.expiredTransaction }
            return try body(owner.gatewayLedger(token))
        } catch {
            failed = true
            if let error = error as? GatewayAuthorityError, [.headMismatch, .invalidClock, .corruptData].contains(error) { headMismatch = true }
            throw error
        }
    }

    /// Protected administrator setup only. This method cannot replace an existing gateway registration.
    public func configureGatewayAuthority(_ identity: GatewayRegistrationIdentity) throws {
        try withGateway(write: true) { try $0.configure(identity) }
    }
    public func gatewayAuthorityHead(_ identity: GatewayRegistrationIdentity) throws -> UInt64 {
        try withGateway(write: false) { try $0.head(identity) }
    }

    /// The host authenticates the phone channel separately and supplies retained enrollment state.
    /// Keep the signer local to the root authority. Publish only after this transaction commits and continuity is established.
    public func prepareGatewayCandidate(registrationToken: String, authenticatedPhoneID: Data, authenticatedEnrollmentEpoch: Data,
                                        trust: GatewayAuthorityTrust, expectedHead: UInt64, nowUnixMillis: UInt64, now: AuthorityMoment,
                                        sign: (GatewayTokenCandidate) throws -> Data) throws -> GatewayAuthorityEnvelope {
        try withGateway(write: true) {
            try $0.prepare(token: registrationToken, authenticatedPhoneID: authenticatedPhoneID, authenticatedEnrollmentEpoch: authenticatedEnrollmentEpoch,
                trust: trust, expectedHead: expectedHead, wall: nowUnixMillis, now: now, sign: sign)
        }
    }

    /// The root host establishes continuity and current enrollment before automatic recovery. No new phone prompt is needed.
    public func renewDesiredGatewayCandidate(trust: GatewayAuthorityTrust, expectedHead: UInt64,
                                             nowUnixMillis: UInt64, now: AuthorityMoment,
                                             sign: (GatewayTokenCandidate) throws -> Data) throws -> GatewayAuthorityEnvelope {
        try withGateway(write: true) { try $0.renewDesired(trust: trust, expectedHead: expectedHead, wall: nowUnixMillis, now: now, sign: sign) }
    }

    /// Proof consumption and the signed activation outbox share this transaction. No biometric is required for routine token rotation.
    public func consumeGatewayProof(canonicalProof: Data, authenticatedPhoneID: Data, authenticatedEnrollmentEpoch: Data,
                                    trust: GatewayAuthorityTrust, expectedHead: UInt64, nowUnixMillis: UInt64, now: AuthorityMoment,
                                    sign: (GatewayMappingActivation) throws -> Data) throws -> GatewayAuthorityEnvelope {
        try withGateway(write: true) {
            try $0.consume(proofBytes: canonicalProof, authenticatedPhoneID: authenticatedPhoneID, authenticatedEnrollmentEpoch: authenticatedEnrollmentEpoch,
                trust: trust, expectedHead: expectedHead, wall: nowUnixMillis, now: now, sign: sign)
        }
    }

    public func pendingGatewayControl(operationID: Data, trust: GatewayAuthorityTrust,
                                      nowUnixMillis: UInt64, now: AuthorityMoment) throws -> GatewayAuthorityEnvelope? {
        try withGateway(write: false) { try $0.pending(operationID: operationID, trust: trust, wall: nowUnixMillis, now: now) }
    }

    /// Protected enrollment removal only. Append the enrollment audit event in this same transaction.
    /// Repeating this operation refreshes the delivery control; it never removes the retained revocation.
    public func revokeGatewayEnrollment(trust: GatewayAuthorityTrust, expectedHead: UInt64,
                                        nowUnixMillis: UInt64, now: AuthorityMoment,
                                        sign: (GatewayPhoneRevocation) throws -> Data) throws -> GatewayAuthorityEnvelope {
        try withGateway(write: true) { try $0.revoke(trust: trust, expectedHead: expectedHead, wall: nowUnixMillis, now: now, sign: sign) }
    }

    /// Historical revocation survives control expiry and process restart. It does not prove a gateway acknowledgment.
    public func gatewayEnrollmentRevoked(trust: GatewayAuthorityTrust) throws -> Bool {
        try withGateway(write: false) { try $0.revoked(trust: trust) }
    }

    /// This path accepts inactive enrollment state so a removal can still reach the gateway.
    public func pendingGatewayRevocation(operationID: Data, trust: GatewayAuthorityTrust,
                                         nowUnixMillis: UInt64, now: AuthorityMoment) throws -> GatewayAuthorityEnvelope? {
        try withGateway(write: false) { try $0.pendingRevocation(operationID: operationID, trust: trust, wall: nowUnixMillis, now: now) }
    }

    public func createEpoch(_ descriptor: AuditEpochDescriptor) throws -> AuditEpochWriter {
        try mutate {
            let writer = try $0.createEpoch(descriptor)
            createdEpoch = true
            return writer
        }
    }
    public func append(_ canonicalRecord: Data, writer: AuditEpochWriter, expectedHead: UInt64) throws {
        try mutate { try $0.append(canonicalRecord, writer: writer, expectedHead: expectedHead) }
    }
    public func prune(epoch: Data, through: UInt64, expectedHead: UInt64) throws {
        try mutate { try $0.prune(epoch: epoch, through: through, expectedHead: expectedHead) }
    }
}
