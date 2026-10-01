import CryptoKit
import Darwin
import Foundation
@testable import RemozioCore
import RemozioProtocol
import SQLite3
import XCTest

final class ConsumptionJournalTests: XCTestCase {
    private enum Failure: Error { case injected }
    private let clock = UUID()
    private let key = P256.Signing.PrivateKey()
    private func id(_ n: UInt8, count: Int = 16) -> Data { Data(repeating: n, count: count) }
    private var bounds: CBORLimits { get throws { try CBORLimits(maxBytes: 16384, maxDepth: 12, maxItems: 512) } }
    private func open(_ fixture: Fixture, initialize: Bool = false, migrate: Bool = false, maximum: Int = 10,
                      account: UInt8 = 2) throws -> JournalDatabase {
        try JournalDatabase(lease: fixture.lease(), macID: id(1), accountID: id(account), recordLimits: bounds,
            descriptorLimits: bounds, decisionLimits: bounds, maximumConsumptions: maximum, busyMilliseconds: 100,
            initialize: initialize, migrateFromVersion1: migrate)
    }
    private func descriptor(_ epoch: UInt8 = 3) throws -> AuditEpochDescriptor {
        try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(id(1)), 2: .bytes(id(2)), 3: .bytes(id(epoch)),
            4: .unsigned(7), 5: .unsigned(1), 6: .null, 7: .null, 8: .null,
        ]), limits: bounds), limits: bounds)
    }
    private func request(_ number: UInt8 = 4, kind: RequestKind = .command, action: CapturedAction? = nil,
                         phase: RequestPhase = .presented, challenge: UInt8 = 9) throws -> RetainedApprovalRequest {
        let selected = action ?? CapturedAction(choice: .execute, scope: .currentRequest)
        let payload = try IssuedRequestPayload(contract: RequestContract(requestKind: kind, wireVersion: 1, schemaVersion: 1),
            macID: id(1), accountID: id(2), requestID: id(number), challenge: id(challenge, count: 32), requiredFeatures: [],
            createdUnixMilliseconds: 100, expiresUnixMilliseconds: 200,
            canonicalCapture: DeterministicCBOR.encode(.map([0: .text("private synthetic capture never persisted")]), limits: bounds),
            permittedActions: [selected, CapturedAction(choice: .decline, scope: .currentRequest)], bodyLimits: bounds, captureLimits: bounds)
        return try RetainedApprovalRequest(payload: payload, phase: phase,
            admittedAt: AuthorityMoment(epoch: clock, milliseconds: 100), deadlineMilliseconds: 200)
    }
    private func trust(_ request: RetainedApprovalRequest, active: Bool = true) throws -> ApprovalTrustSnapshot {
        let capabilities = ContractCapabilities(contracts: [request.payload.contract: []])
        let keys = try [EnrolledApprovalKey(id: id(6), keyClass: .biometric, publicKey: key.publicKey.x963Representation),
                        EnrolledApprovalKey(id: id(7), keyClass: .decision, publicKey: key.publicKey.x963Representation)]
        return try ApprovalTrustSnapshot(macID: id(1), accountID: id(2), revision: UUID(), authorityCapabilities: capabilities,
            allowedContracts: [request.payload.contract], enrollments: [5, 8].map {
                try ApprovalEnrollment(phoneID: id($0), active: active, capabilities: capabilities, keys: keys)
            })
    }
    private func consume(_ transaction: JournalTransaction, _ writer: AuditEpochWriter, request: RetainedApprovalRequest,
                         head: UInt64 = 0, phone: UInt8 = 5, action: CapturedAction? = nil, event: UInt8 = 10,
                         now: UInt64 = 150, active: Bool = true, damageSignature: Bool = false) throws -> ConsumptionReceipt {
        let selected = action ?? request.payload.permittedActions[0]
        let requirement = try ActionPolicy.requirement(for: selected, requestKind: request.payload.contract.requestKind,
                                                       retainedPermittedActions: Set(request.payload.permittedActions))
        let decision = try DecisionPayload(macID: id(1), accountID: id(2), requestID: request.payload.requestID,
            requestDigest: request.payload.requestDigest(bodyLimits: bounds, signingLimits: bounds), challenge: request.payload.challenge,
            phoneID: id(phone), keyID: id(requirement.keyClass == .biometric ? 6 : 7), action: selected).encode(limits: bounds)
        let purpose: SigningPurpose
        switch requirement.purpose {
        case .cancellation: purpose = .cancellation
        case .oneTimeUI: purpose = .oneTimeUI
        case .biometricAuthorization: purpose = .biometricAuthorization
        }
        var signature = try key.signature(for: SigningInput.make(wireVersion: 1, messageType: .decision, purpose: purpose,
            canonicalPayload: decision, payloadLimits: bounds, inputLimits: bounds)).rawRepresentation
        if damageSignature { signature[0] ^= 1 }
        return try transaction.consume(canonicalDecision: decision, signature: signature, retained: request, trust: trust(request, active: active),
            now: AuthorityMoment(epoch: clock, milliseconds: now), eventID: id(event), receiptTimeMs: 12345,
            writer: writer, expectedHead: head, requestLimits: bounds, signingLimits: bounds)
    }

    func testFirstVerifiedPhoneWinsAndReopenCannotChangeItsDecision() throws {
        for firstDeclines in [false, true] {
            let fixture = try Fixture(), database = try open(fixture, initialize: true), request = try request()
            let writer = try database.write { try $0.createEpoch(descriptor()) }
            let decline = CapturedAction(choice: .decline, scope: .currentRequest)
            let winner = try database.write { try consume($0, writer, request: request, action: firstDeclines ? decline : nil) }
            XCTAssertEqual(winner.event.authentication, firstDeclines ? .decisionKey : .biometricKey)
            XCTAssertEqual(winner.event.outcome, firstDeclines ? .noDispatch : .accepted)
            XCTAssertThrowsError(try database.write { try consume($0, writer, request: request, head: 1, phone: 8,
                                                                 action: firstDeclines ? nil : decline, event: 11) }) {
                XCTAssertEqual($0 as? ConsumptionJournalError, .alreadyConsumed)
            }
            XCTAssertEqual(try database.read { try $0.consumption(requestID: id(4)) }, winner)
            XCTAssertEqual(try database.read { try $0.page(epoch: id(3), after: 0, maximumRecords: 10, maximumBytes: 16384).canonicalRecords },
                           try [winner.event.encode(limits: bounds)])
            try database.close()
            let reopened = try open(fixture), newer = try reopened.write { try $0.createEpoch(descriptor(12)) }
            XCTAssertEqual(try reopened.read { try $0.consumption(requestID: id(4)) }, winner)
            XCTAssertThrowsError(try reopened.write { try consume($0, newer, request: request) }) {
                XCTAssertEqual($0 as? ConsumptionJournalError, .alreadyConsumed)
            }
            XCTAssertEqual(try reopened.read { try $0.epoch(id(12))?.head }, 0)
            try reopened.close()
            XCTAssertNil(try Data(contentsOf: URL(fileURLWithPath: fixture.path)).range(of: Data("private synthetic capture never persisted".utf8)))
        }
    }

    func testAnotherAccountCannotConsumeTheRetainedRequest() throws {
        let firstFixture = try Fixture(), first = try open(firstFixture, initialize: true)
        let writer = try first.write { try $0.createEpoch(descriptor()) }
        let secondFixture = try Fixture(), second = try open(secondFixture, initialize: true, account: 9)
        XCTAssertThrowsError(try second.write { try consume($0, writer, request: request()) }) {
            XCTAssertEqual($0 as? ConsumptionJournalError, .wrongScope)
        }
        XCTAssertNil(try second.read { try $0.consumption(requestID: id(4)) })
        XCTAssertNil(try first.read { try $0.consumption(requestID: id(4)) })
    }

    func testDuplicateAuditEventCannotLeaveASecondConsumption() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        let writer = try database.write { try $0.createEpoch(descriptor()) }
        let winner = try database.write { try consume($0, writer, request: request()) }
        XCTAssertThrowsError(try database.write { try consume($0, writer, request: request(20), head: 1) })
        XCTAssertEqual(try database.read { try $0.consumption(requestID: id(4)) }, winner)
        XCTAssertNil(try database.read { try $0.consumption(requestID: id(20)) })
        XCTAssertEqual(try database.read { try $0.epoch(id(3))?.head }, 1)
    }

    func testChangedChallengeCannotReuseConsumedRequestIdentity() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        let writer = try database.write { try $0.createEpoch(descriptor()) }
        let winner = try database.write { try consume($0, writer, request: request()) }
        XCTAssertThrowsError(try database.write { try consume($0, writer, request: request(challenge: 20), head: 1) }) {
            XCTAssertEqual($0 as? ConsumptionJournalError, .alreadyConsumed)
        }
        XCTAssertEqual(try database.read { try $0.consumption(requestID: id(4)) }, winner)
    }

    func testCurrentSignatureEnrollmentExpiryAndLifecycleAreCheckedBeforeWrites() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        let writer = try database.write { try $0.createEpoch(descriptor()) }
        for (phase, now, active, damaged, error) in [
            (RequestPhase.cancelled, UInt64(150), true, false, DecisionVerificationError.unavailableRequest),
            (.presented, 200, true, false, .expired), (.presented, 99, true, false, .invalidClock),
            (.presented, 150, false, false, .unavailableEnrollment), (.presented, 150, true, true, .invalidSignature),
        ] {
            XCTAssertThrowsError(try database.write { try consume($0, writer, request: request(phase: phase), now: now,
                                                                 active: active, damageSignature: damaged) }) {
                XCTAssertEqual($0 as? DecisionVerificationError, error)
            }
            XCTAssertNil(try database.read { try $0.consumption(requestID: id(4)) })
            XCTAssertEqual(try database.read { try $0.epoch(id(3))?.head }, 0)
        }
    }

    func testUIActionsKeepTheirRequiredAuthenticationAndAuditCategory() throws {
        let cases: [(RequestKind, CapturedAction, AuditCategory, AuditAuthentication)] = [
            (.littleSnitch, .init(choice: .allowOnce, scope: .currentRequest), .littleSnitch, .decisionKey),
            (.littleSnitch, .init(choice: .denyOnce, scope: .currentRequest), .littleSnitch, .decisionKey),
            (.littleSnitch, .init(choice: .allowRule, scope: .forever), .littleSnitch, .biometricKey),
            (.onePasswordAccess, .init(choice: .approveAccess, scope: .currentRequest), .onePasswordAccess, .biometricKey),
            (.onePasswordUnlock, .init(choice: .unlockVault, scope: .currentRequest), .onePasswordUnlock, .biometricKey),
        ]
        for (kind, action, category, authentication) in cases {
            let fixture = try Fixture(), database = try open(fixture, initialize: true)
            let writer = try database.write { try $0.createEpoch(descriptor()) }
            let result = try database.write { try consume($0, writer, request: request(kind: kind, action: action)) }
            XCTAssertEqual(result.event.category, category)
            XCTAssertEqual(result.event.authentication, authentication)
            XCTAssertEqual(result.event.action, AuditActionMetadata(action: action))
            XCTAssertEqual(try database.read { try $0.consumption(requestID: id(4)) }, result)
        }
    }

    func testFailureInEitherTableRollsBackBothEvenWhenCaught() throws {
        for table in ["consumptions_v1", "audit_records_v1"] {
            let fixture = try Fixture(), database = try open(fixture, initialize: true)
            let writer = try database.write { try $0.createEpoch(descriptor()) }
            try fixture.sql("CREATE TRIGGER fail_write BEFORE INSERT ON \(table) BEGIN SELECT RAISE(ABORT,'injected'); END")
            XCTAssertThrowsError(try database.write { transaction in
                XCTAssertThrowsError(try consume(transaction, writer, request: request()))
            }) { XCTAssertEqual($0 as? JournalDatabaseError, .transactionFailed) }
            XCTAssertNil(try database.read { try $0.consumption(requestID: id(4)) })
            XCTAssertEqual(try database.read { try $0.epoch(id(3))?.head }, 0)
            try fixture.sql("DROP TRIGGER fail_write")
            _ = try database.write { try consume($0, writer, request: request()) }
        }
    }

    func testCallbackAndAutomaticRollbackLeaveNoPartialConsumption() throws {
        for automatic in [false, true] {
            let fixture = try Fixture(), database = try open(fixture, initialize: true)
            let writer = try database.write { try $0.createEpoch(descriptor()) }
            if automatic { try fixture.sql("CREATE TRIGGER fail_write BEFORE INSERT ON audit_records_v1 BEGIN SELECT RAISE(ROLLBACK,'injected'); END") }
            XCTAssertThrowsError(try database.write {
                _ = try consume($0, writer, request: request())
                throw Failure.injected
            })
            if automatic { XCTAssertThrowsError(try database.read { _ in }) { XCTAssertEqual($0 as? JournalDatabaseError, .unavailable) } }
            try database.close()
            let reopened = try open(fixture)
            XCTAssertNil(try reopened.read { try $0.consumption(requestID: id(4)) })
            XCTAssertEqual(try reopened.read { try $0.epoch(id(3))?.head }, 0)
        }
    }

    func testHeadMismatchRollsBackInsertedConsumptionAndRetiresOwner() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        let writer = try database.write { try $0.createEpoch(descriptor()) }
        _ = try database.write { try consume($0, writer, request: request()) }
        XCTAssertThrowsError(try database.write { try consume($0, writer, request: request(20), event: 11) }) {
            XCTAssertEqual($0 as? AuditJournalError, .headMismatch)
        }
        XCTAssertThrowsError(try database.read { _ in }) { XCTAssertEqual($0 as? JournalDatabaseError, .unavailable) }
        try database.close()
        let reopened = try open(fixture)
        XCTAssertNil(try reopened.read { try $0.consumption(requestID: id(20)) })
        XCTAssertNotNil(try reopened.read { try $0.consumption(requestID: id(4)) })
        XCTAssertEqual(try reopened.read { try $0.epoch(id(3))?.head }, 1)
    }

    func testCapacityAndAuditRetentionNeverEvictOrResetTheWinner() throws {
        let fixture = try Fixture()
        XCTAssertThrowsError(try open(fixture, initialize: true, maximum: 0))
        let database = try open(fixture, initialize: true, maximum: 1)
        let writer = try database.write { try $0.createEpoch(descriptor()) }
        let winner = try database.write { try consume($0, writer, request: request()) }
        try database.write { try $0.prune(epoch: id(3), through: 1, expectedHead: 1) }
        XCTAssertEqual(try database.read { try $0.consumption(requestID: id(4)) }, winner)
        XCTAssertThrowsError(try database.write { try consume($0, writer, request: request(20), head: 1, event: 11) }) {
            XCTAssertEqual($0 as? ConsumptionJournalError, .capacityExceeded)
        }
        XCTAssertNil(try database.read { try $0.consumption(requestID: id(20)) })
        XCTAssertEqual(try database.read { try $0.epoch(id(3))?.head }, 1)
    }

    func testReadOnlyAndExpiredHandlesCannotConsume() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        let writer = try database.write { try $0.createEpoch(descriptor()) }
        XCTAssertThrowsError(try database.read { try consume($0, writer, request: request()) }) {
            XCTAssertEqual($0 as? JournalDatabaseError, .readOnly)
        }
        let escaped = try database.write { $0 }
        XCTAssertThrowsError(try consume(escaped, writer, request: request()))
        XCTAssertThrowsError(try escaped.consumption(requestID: id(4)))
        XCTAssertNil(try database.read { try $0.consumption(requestID: id(4)) })
    }

    func testExplicitVersionOneMigrationPreservesHistoryAndRejectsWrongScope() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        let writer = try database.write { try $0.createEpoch(descriptor()) }
        let prior = try database.write { try consume($0, writer, request: request()) }
        try database.close()
        // Recreate the pre-consumption v1 layout. This is a fixture, never a recovery operation.
        try fixture.sql("DROP TABLE consumptions_v1; PRAGMA user_version=1")
        XCTAssertThrowsError(try open(fixture))
        XCTAssertThrowsError(try open(fixture, migrate: true, account: 9))
        XCTAssertEqual(try fixture.version(), 1)
        let migrated = try open(fixture, migrate: true)
        XCTAssertEqual(try migrated.read { try $0.page(epoch: id(3), after: 0, maximumRecords: 1, maximumBytes: 16384).canonicalRecords },
                       try [prior.event.encode(limits: bounds)])
        XCTAssertNil(try migrated.read { try $0.consumption(requestID: id(4)) }) // Audit history never recreates authority state.
        try migrated.close()
        XCTAssertEqual(try fixture.version(), 2)
        XCTAssertThrowsError(try open(fixture, migrate: true))
        let reopened = try open(fixture)
        try reopened.close()
    }

    func testFailedMigrationAndMissingLedgerDoNotResetStorage() throws {
        let fixture = try Fixture(), database = try open(fixture, initialize: true)
        try database.close()
        try fixture.sql("PRAGMA user_version=1") // Deliberate conflicting table.
        XCTAssertThrowsError(try open(fixture, migrate: true))
        XCTAssertEqual(try fixture.version(), 1)
        try fixture.sql("PRAGMA user_version=2; DROP TABLE consumptions_v1")
        XCTAssertThrowsError(try open(fixture))
        XCTAssertThrowsError(try open(fixture, initialize: true))
        XCTAssertEqual(try fixture.version(), 2)
    }

    func testMalformedAndInconsistentReceiptsFailBoundedReads() throws {
        for mutation in ["UPDATE consumptions_v1 SET decision=x'01'", "UPDATE consumptions_v1 SET event=zeroblob(17000)",
                         "UPDATE consumptions_v1 SET request=zeroblob(16)"] {
            let fixture = try Fixture(), database = try open(fixture, initialize: true)
            let writer = try database.write { try $0.createEpoch(descriptor()) }
            _ = try database.write { try consume($0, writer, request: request()) }
            try fixture.sql(mutation)
            let queryID = mutation.contains("request=") ? id(0) : id(4)
            XCTAssertThrowsError(try database.read { try $0.consumption(requestID: queryID) })
        }
    }

    private final class Fixture {
        let root: URL
        var path: String { root.appendingPathComponent("store/journal.sqlite").path }
        init() throws {
            guard let canonical = realpath(FileManager.default.temporaryDirectory.path, nil) else { throw Failure.injected }
            defer { free(canonical) }
            root = URL(fileURLWithPath: String(cString: canonical)).appendingPathComponent(UUID().uuidString)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            try FileManager.default.createDirectory(at: root.appendingPathComponent("store"), withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            for name in ["writer.lock", "journal.sqlite"] {
                let fd = Darwin.open(root.appendingPathComponent("store/" + name).path, O_CREAT | O_EXCL | O_WRONLY, 0o600)
                guard fd >= 0 else { throw Failure.injected }
                Darwin.close(fd)
            }
        }
        deinit { try? FileManager.default.removeItem(at: root) }
        func lease() throws -> ProtectedJournalLease { try ProtectedJournalLease(anchor: root.path, relativeDirectory: "store", owner: getuid()) }
        private func connection<T>(_ body: (OpaquePointer) throws -> T) throws -> T {
            var db: OpaquePointer?
            let rc = sqlite3_open(path, &db)
            defer { if let db { sqlite3_close(db) } }
            guard rc == SQLITE_OK, let db else { throw Failure.injected }
            return try body(db)
        }
        func sql(_ query: String) throws {
            try connection { guard sqlite3_exec($0, query, nil, nil, nil) == SQLITE_OK else { throw Failure.injected } }
        }
        func version() throws -> Int64 {
            try connection { db in
                var stmt: OpaquePointer?
                guard sqlite3_prepare_v2(db, "PRAGMA user_version", -1, &stmt, nil) == SQLITE_OK, let stmt else { throw Failure.injected }
                defer { sqlite3_finalize(stmt) }
                guard sqlite3_step(stmt) == SQLITE_ROW else { throw Failure.injected }
                return sqlite3_column_int64(stmt, 0)
            }
        }
    }
}
