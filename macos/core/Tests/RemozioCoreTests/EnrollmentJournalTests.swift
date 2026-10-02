import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import SQLite3
import XCTest
@testable import RemozioCore

final class EnrollmentJournalTests: XCTestCase {
    private enum Failure: Error { case injected }
    private let key = P256.Signing.PrivateKey()
    private let rootKey = P256.Signing.PrivateKey()
    private let clock = UUID()
    private func id(_ n: UInt8, count: Int = 16) -> Data { Data(repeating: n, count: count) }
    private var limits: CBORLimits { get throws { try .init(maxBytes: 16384, maxDepth: 12, maxItems: 1024) } }
    private var contract: RequestContract { get throws { try .init(requestKind: .command, wireVersion: 1, schemaVersion: 1) } }
    private var capabilities: ContractCapabilities { get throws { try .init(contracts: [contract: []]) } }
    private func moment() -> AuthorityMoment { .init(epoch: clock, milliseconds: 110) }
    private func enrollment(phone: UInt8 = 5, epoch: UInt8 = 9, signingKey: P256.Signing.PrivateKey? = nil) throws -> StoredApprovalEnrollment {
        let biometric = signingKey ?? key
        return try StoredApprovalEnrollment(epoch: id(epoch), notificationTag: id(phone, count: 32), identityPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
            approval: ApprovalEnrollment(phoneID: id(phone), active: true, capabilities: capabilities, keys: [
                EnrolledApprovalKey(id: id(phone * 2), keyClass: .biometric, publicKey: biometric.publicKey.x963Representation),
                EnrolledApprovalKey(id: id(phone * 2 + 1), keyClass: .decision, publicKey: P256.Signing.PrivateKey().publicKey.x963Representation),
            ]))
    }
    private func descriptor() throws -> AuditEpochDescriptor {
        try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(id(1)), 2: .bytes(id(2)), 3: .bytes(id(3)),
            4: .unsigned(7), 5: .unsigned(1), 6: .null, 7: .null, 8: .null,
        ]), limits: limits), limits: limits)
    }
    private func open(_ fixture: Fixture, initialize: Bool = false, migrate: Int64? = nil) throws -> JournalDatabase {
        try JournalDatabase(lease: fixture.lease(), macID: id(1), accountID: id(2), recordLimits: limits, descriptorLimits: limits,
            decisionLimits: limits, maximumConsumptions: 20, busyMilliseconds: 100, initialize: initialize, migrateFromVersion: migrate,
            gatewayPolicy: GatewayAuthorityPolicy(payloadLimits: limits, signingLimits: limits, maximumControls: 50,
                candidateLifetimeMillis: 1000, clockEpoch: clock))
    }
    private func setup(_ fixture: Fixture) throws -> (JournalDatabase, AuditEpochWriter, UUID) {
        let db = try open(fixture, initialize: true)
        let revision = try db.write { try $0.configureApprovalAuthority(capabilities: capabilities, allowedContracts: [contract]) }
        let writer = try db.write { try $0.createEpoch(descriptor()) }
        return (db, writer, revision)
    }
    private func add(_ db: JournalDatabase, writer: AuditEpochWriter, revision: UUID, head: UInt64 = 0,
                     phone: UInt8 = 5, epoch: UInt8 = 9, signingKey: P256.Signing.PrivateKey? = nil) throws -> UUID {
        try db.write { try $0.addApprovalEnrollment(enrollment(phone: phone, epoch: epoch, signingKey: signingKey), expectedTrustRevision: revision,
            eventID: id(UInt8(head + 40)), receiptTimeMs: 1000, writer: writer, expectedAuditHead: head) }
    }
    private func remove(_ db: JournalDatabase, writer: AuditEpochWriter, revision: UUID, head: UInt64 = 1,
                        gateway: EnrollmentGatewayRemoval? = nil) throws -> (revision: UUID, gatewayControl: GatewayAuthorityEnvelope?) {
        try db.write { try $0.revokeApprovalEnrollment(phoneID: id(5), epoch: id(9), expectedTrustRevision: revision,
            eventID: id(UInt8(head + 40)), receiptTimeMs: 1000, writer: writer, expectedAuditHead: head, gateway: gateway) }
    }
    private func request() throws -> RetainedApprovalRequest {
        let action = CapturedAction(choice: .execute, scope: .currentRequest)
        return try RetainedApprovalRequest(payload: IssuedRequestPayload(contract: contract, macID: id(1), accountID: id(2), requestID: id(4),
            challenge: id(30, count: 32), requiredFeatures: [], createdUnixMilliseconds: 1000, expiresUnixMilliseconds: 2000,
            canonicalCapture: DeterministicCBOR.encode(.map([0: .text("synthetic request")]), limits: limits), permittedActions: [action],
            bodyLimits: limits, captureLimits: limits), phase: .presented, admittedAt: .init(epoch: clock, milliseconds: 100), deadlineMilliseconds: 1100)
    }
    private func consume(_ transaction: JournalTransaction, writer: AuditEpochWriter, revision: UUID, head: UInt64,
                         phone: UInt8 = 5, signingKey: P256.Signing.PrivateKey? = nil) throws -> ConsumptionReceipt {
        let retained = try request()
        let decision = try DecisionPayload(macID: id(1), accountID: id(2), requestID: id(4),
            requestDigest: retained.payload.requestDigest(bodyLimits: limits, signingLimits: limits), challenge: retained.payload.challenge,
            phoneID: id(phone), keyID: id(phone * 2), action: retained.payload.permittedActions[0]).encode(limits: limits)
        let signature = try (signingKey ?? key).signature(for: SigningInput.make(wireVersion: 1, messageType: .decision,
            purpose: .biometricAuthorization, canonicalPayload: decision, payloadLimits: limits, inputLimits: limits)).rawRepresentation
        return try transaction.consume(canonicalDecision: decision, signature: signature, retained: retained,
            expectedTrustRevision: revision, now: moment(), eventID: id(80), receiptTimeMs: 1000,
            writer: writer, expectedHead: head, requestLimits: limits, signingLimits: limits)
    }
    private func identity() throws -> GatewayRegistrationIdentity {
        try .init(ownerID: id(11), macID: id(1), accountID: id(2), gatewayID: id(12), lifecycleEpoch: id(13), rootPublicKey: rootKey.publicKey.x963Representation)
    }
    private func gatewayRemoval(head: UInt64 = 0, validSignature: Bool = true) throws -> EnrollmentGatewayRemoval {
        try .init(registration: identity(), expectedHead: head, nowUnixMillis: 1000, now: moment()) { value in
            if !validSignature { return self.id(0, count: 64) }
            return try self.rootKey.signature(for: GatewayRecipientSigningInput.make(wireVersion: 1, kind: .phoneRevocation,
                canonicalPayload: value.encode(limits: self.limits), payloadLimits: self.limits, inputLimits: self.limits)).rawRepresentation
        }
    }

    func testPublicConsumptionRequiresStoredEnrollmentAndUsesItsKeys() throws {
        let fixture = try Fixture(), db = try open(fixture, initialize: true), writer = try db.write { try $0.createEpoch(descriptor()) }
        XCTAssertThrowsError(try db.write { try consume($0, writer: writer, revision: UUID(), head: 0) }) {
            XCTAssertEqual($0 as? EnrollmentJournalError, .unconfigured)
        }
        let empty = try db.write { try $0.configureApprovalAuthority(capabilities: capabilities, allowedContracts: [contract]) }
        XCTAssertThrowsError(try db.write { try consume($0, writer: writer, revision: empty, head: 0) }) {
            XCTAssertEqual($0 as? DecisionVerificationError, .unavailableEnrollment)
        }
        let revision = try add(db, writer: writer, revision: empty)
        XCTAssertThrowsError(try db.write { try consume($0, writer: writer, revision: revision, head: 1, signingKey: P256.Signing.PrivateKey()) }) {
            XCTAssertEqual($0 as? DecisionVerificationError, .invalidSignature)
        }
        let receipt = try db.write { try consume($0, writer: writer, revision: revision, head: 1) }
        XCTAssertEqual(receipt.event.sequence, 2)
        XCTAssertEqual(receipt.decision.phoneID, id(5))
    }

    func testRemovalSerializesWithConsumptionAndPreservesOtherPhones() throws {
        let fixture = try Fixture(), (db, writer, empty) = try setup(fixture), other = P256.Signing.PrivateKey()
        let first = try add(db, writer: writer, revision: empty)
        let second = try add(db, writer: writer, revision: first, head: 1, phone: 8, epoch: 10, signingKey: other)
        let removed = try remove(db, writer: writer, revision: second, head: 2)
        XCTAssertThrowsError(try db.write { try consume($0, writer: writer, revision: second, head: 3) }) {
            XCTAssertEqual($0 as? EnrollmentJournalError, .staleRevision)
        }
        XCTAssertThrowsError(try db.write { try consume($0, writer: writer, revision: removed.revision, head: 3) }) {
            XCTAssertEqual($0 as? DecisionVerificationError, .unavailableEnrollment)
        }
        XCTAssertNil(try db.read { try $0.consumption(requestID: id(4)) })
        let winner = try db.write { try consume($0, writer: writer, revision: removed.revision, head: 3, phone: 8, signingKey: other) }
        XCTAssertEqual(winner.decision.phoneID, id(8))
        XCTAssertEqual(try db.read { try $0.approvalEnrollments().filter { !$0.approval.active }.count }, 1)
    }

    func testConsumedDecisionRemainsHistoricalAfterRemoval() throws {
        let fixture = try Fixture(), (db, writer, empty) = try setup(fixture)
        let revision = try add(db, writer: writer, revision: empty)
        let winner = try db.write { try consume($0, writer: writer, revision: revision, head: 1) }
        _ = try remove(db, writer: writer, revision: revision, head: 2)
        XCTAssertEqual(try db.read { try $0.consumption(requestID: id(4)) }, winner)
        XCTAssertEqual(try db.read { try $0.epoch(id(3))?.head }, 3)
    }

    func testEnrollmentAndRevocationSurviveRestartWithoutDerivingTrustFromAudit() throws {
        let fixture = try Fixture(), (db, writer, empty) = try setup(fixture)
        let revision = try add(db, writer: writer, revision: empty)
        let removed = try remove(db, writer: writer, revision: revision)
        try db.close()
        let reopened = try open(fixture)
        let snapshot = try reopened.read { try $0.approvalTrustSnapshot() }
        XCTAssertEqual(snapshot.revision, removed.revision); XCTAssertTrue(snapshot.enrollments.isEmpty)
        let retained = try reopened.read { try $0.approvalEnrollments() }
        XCTAssertEqual(retained.count, 1); XCTAssertFalse(retained[0].approval.active)
        XCTAssertEqual(retained[0].epoch, id(9))
        XCTAssertThrowsError(try reopened.write { try $0.configureApprovalAuthority(capabilities: capabilities, allowedContracts: [contract]) }) {
            XCTAssertEqual($0 as? EnrollmentJournalError, .alreadyConfigured)
        }
    }

    func testReplacementAndItsAuditAreAtomicAndRetiredKeysCannotReturn() throws {
        let fixture = try Fixture(), (db, writer, empty) = try setup(fixture)
        let revision = try add(db, writer: writer, revision: empty)
        XCTAssertThrowsError(try db.write { tx in
            let removed = try tx.revokeApprovalEnrollment(phoneID: id(5), epoch: id(9), expectedTrustRevision: revision,
                eventID: id(41), receiptTimeMs: nil, writer: writer, expectedAuditHead: 1)
            _ = try tx.addApprovalEnrollment(enrollment(epoch: 10), expectedTrustRevision: removed.revision,
                eventID: id(42), receiptTimeMs: nil, writer: writer, expectedAuditHead: 2)
        }) { XCTAssertEqual($0 as? EnrollmentJournalError, .reusedIdentity) }
        XCTAssertEqual(try db.read { try $0.approvalTrustSnapshot().revision }, revision)
        XCTAssertEqual(try db.read { try $0.epoch(id(3))?.head }, 1)
        try db.write { tx in
            let removed = try tx.revokeApprovalEnrollment(phoneID: id(5), epoch: id(9), expectedTrustRevision: revision,
                eventID: id(41), receiptTimeMs: nil, writer: writer, expectedAuditHead: 1)
            _ = try tx.addApprovalEnrollment(enrollment(phone: 8, epoch: 10, signingKey: P256.Signing.PrivateKey()), expectedTrustRevision: removed.revision,
                eventID: id(42), receiptTimeMs: nil, writer: writer, expectedAuditHead: 2)
        }
        XCTAssertEqual(try db.read { try $0.approvalTrustSnapshot().enrollments.map(\.phoneID) }, [id(8)])
        let events = try db.read { try $0.page(epoch: id(3), after: 0, maximumRecords: 10, maximumBytes: 16384).canonicalRecords }
        XCTAssertEqual(try events.map { try AuditEventMetadata.decode($0, limits: limits).kind }, [.enrollmentAdded, .enrollmentRevoked, .enrollmentAdded])
    }

    func testGatewayRemovalAndAuditCommitTogetherAndBadSignerRollsEverythingBack() throws {
        let fixture = try Fixture(), (db, writer, empty) = try setup(fixture)
        let revision = try add(db, writer: writer, revision: empty)
        try db.write { try $0.configureGatewayAuthority(identity()) }
        XCTAssertThrowsError(try remove(db, writer: writer, revision: revision)) { XCTAssertEqual($0 as? EnrollmentJournalError, .gatewayRequired) }
        XCTAssertThrowsError(try remove(db, writer: writer, revision: revision, gateway: gatewayRemoval(validSignature: false))) {
            XCTAssertEqual($0 as? GatewayAuthorityError, .invalidSignature)
        }
        XCTAssertEqual(try db.read { try $0.approvalTrustSnapshot().revision }, revision)
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(identity()) }, 0)
        let removed = try remove(db, writer: writer, revision: revision, gateway: gatewayRemoval())
        XCTAssertEqual(removed.gatewayControl?.kind, 3)
        XCTAssertTrue(try db.read { try $0.approvalTrustSnapshot().enrollments.isEmpty })
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(identity()) }, 1)
        XCTAssertEqual(try db.read { try $0.epoch(id(3))?.head }, 2)
    }

    func testStorageFaultsAndSwallowedErrorsCannotPartiallyCommitRemoval() throws {
        for trigger in ["BEFORE UPDATE ON approval_enrollments_v1", "BEFORE UPDATE ON approval_authority_v1", "BEFORE INSERT ON audit_records_v1"] {
            let fixture = try Fixture(), (db, writer, empty) = try setup(fixture)
            let revision = try add(db, writer: writer, revision: empty)
            try fixture.sql("CREATE TRIGGER reject_write \(trigger) BEGIN SELECT RAISE(ABORT,'fixture'); END")
            XCTAssertThrowsError(try db.write { tx in
                _ = try? tx.revokeApprovalEnrollment(phoneID: id(5), epoch: id(9), expectedTrustRevision: revision,
                    eventID: id(41), receiptTimeMs: nil, writer: writer, expectedAuditHead: 1)
            }) { XCTAssertEqual($0 as? JournalDatabaseError, .transactionFailed) }
            XCTAssertEqual(try db.read { try $0.approvalTrustSnapshot().revision }, revision)
            XCTAssertEqual(try db.read { try $0.epoch(id(3))?.head }, 1)
            try fixture.sql("DROP TRIGGER reject_write")
            _ = try remove(db, writer: writer, revision: revision)
        }
    }

    func testReadOnlyExpiredAndCorruptStorageCannotSupplyTrust() throws {
        let fixture = try Fixture(), (db, writer, empty) = try setup(fixture)
        XCTAssertThrowsError(try db.read { try $0.addApprovalEnrollment(enrollment(), expectedTrustRevision: empty,
            eventID: id(40), receiptTimeMs: nil, writer: writer, expectedAuditHead: 0) }) { XCTAssertEqual($0 as? JournalDatabaseError, .readOnly) }
        let escaped = try db.read { $0 }
        XCTAssertThrowsError(try escaped.approvalTrustSnapshot()) { XCTAssertEqual($0 as? JournalDatabaseError, .expiredTransaction) }
        _ = try add(db, writer: writer, revision: empty)
        try fixture.sql("UPDATE approval_enrollments_v1 SET body=x'01'")
        XCTAssertThrowsError(try db.read { try $0.approvalTrustSnapshot() }) { XCTAssertEqual($0 as? EnrollmentJournalError, .corruptData) }
        XCTAssertThrowsError(try db.read { _ in }) { XCTAssertEqual($0 as? JournalDatabaseError, .unavailable) }
    }

    func testExplicitSchemaFiveMigrationKeepsAuditAndStartsUnconfigured() throws {
        let fixture = try Fixture(), db = try open(fixture, initialize: true)
        _ = try db.write { try $0.createEpoch(descriptor()) }; try db.close()
        try fixture.sql("DROP TABLE routing_operations_v1; DROP TABLE routing_state_v1; DROP TABLE approval_enrollments_v1; DROP TABLE approval_authority_v1; PRAGMA user_version=5")
        XCTAssertThrowsError(try open(fixture))
        let migrated = try open(fixture, migrate: 5)
        XCTAssertNotNil(try migrated.read { try $0.epoch(id(3)) })
        XCTAssertThrowsError(try migrated.read { try $0.approvalTrustSnapshot() }) { XCTAssertEqual($0 as? EnrollmentJournalError, .unconfigured) }
        try migrated.close()
        let reopened = try open(fixture)
        XCTAssertNotNil(try reopened.read { try $0.epoch(id(3)) })
    }

    func testSamePhoneCanReenrollWithFreshEpochAndKeys() throws {
        let fixture = try Fixture(), (db, writer, empty) = try setup(fixture)
        let revision = try add(db, writer: writer, revision: empty)
        let removed = try remove(db, writer: writer, revision: revision)
        let material = try enrollment(phone: 8, epoch: 10, signingKey: P256.Signing.PrivateKey())
        let replacement = try StoredApprovalEnrollment(epoch: material.epoch, notificationTag: material.notificationTag,
            identityPublicKey: material.identityPublicKey, approval: ApprovalEnrollment(phoneID: id(5), active: true,
                capabilities: material.approval.capabilities, keys: material.approval.keys))
        let fresh = try db.write { try $0.addApprovalEnrollment(replacement, expectedTrustRevision: removed.revision,
            eventID: id(42), receiptTimeMs: nil, writer: writer, expectedAuditHead: 2) }
        XCTAssertEqual(try db.read { try $0.approvalTrustSnapshot().enrollments.map(\.phoneID) }, [id(5)])
        XCTAssertEqual(try db.read { try $0.approvalEnrollments().count }, 2)
        XCTAssertThrowsError(try db.write { try consume($0, writer: writer, revision: fresh, head: 3) }) {
            XCTAssertEqual($0 as? DecisionVerificationError, .wrongKey)
        }
    }

    func testMalformedPolicyAndPhoneMetadataRetireOwner() throws {
        for mutation in ["UPDATE approval_authority_v1 SET policy=x'7b7d'",
                         "UPDATE approval_enrollments_v1 SET phone=zeroblob(16)",
                         "UPDATE approval_enrollments_v1 SET epoch=zeroblob(16)"] {
            let fixture = try Fixture(), (db, writer, empty) = try setup(fixture)
            _ = try add(db, writer: writer, revision: empty)
            try fixture.sql(mutation)
            XCTAssertThrowsError(try db.read { try $0.approvalTrustSnapshot() }) { XCTAssertEqual($0 as? EnrollmentJournalError, .corruptData) }
            XCTAssertThrowsError(try db.read { _ in }) { XCTAssertEqual($0 as? JournalDatabaseError, .unavailable) }
        }
    }

    func testFailedSchemaFiveMigrationDoesNotResetExistingState() throws {
        let fixture = try Fixture(), (db, writer, empty) = try setup(fixture)
        _ = try add(db, writer: writer, revision: empty); try db.close()
        try fixture.sql("PRAGMA user_version=5")
        XCTAssertThrowsError(try open(fixture, migrate: 5))
        try fixture.sql("PRAGMA user_version=7")
        let reopened = try open(fixture)
        XCTAssertEqual(try reopened.read { try $0.approvalEnrollments().count }, 1)
        XCTAssertEqual(try reopened.read { try $0.epoch(id(3))?.head }, 1)
    }

    func testInvalidEnrollmentKeysAndPolicyCannotConfigureAuthority() throws {
        let fixture = try Fixture(), db = try open(fixture, initialize: true)
        XCTAssertThrowsError(try db.write { try $0.configureApprovalAuthority(capabilities: .init(contracts: [:]), allowedContracts: []) }) {
            XCTAssertEqual($0 as? EnrollmentJournalError, .invalidState)
        }
        let sameKey = try ApprovalEnrollment(phoneID: id(5), active: true, capabilities: capabilities, keys: [
            EnrolledApprovalKey(id: id(10), keyClass: .biometric, publicKey: key.publicKey.x963Representation),
            EnrolledApprovalKey(id: id(11), keyClass: .decision, publicKey: key.publicKey.x963Representation),
        ])
        XCTAssertThrowsError(try StoredApprovalEnrollment(epoch: id(9), notificationTag: id(5, count: 32),
            identityPublicKey: rootKey.publicKey.x963Representation, approval: sameKey)) { XCTAssertEqual($0 as? EnrollmentJournalError, .invalidState) }
        let valid = try enrollment()
        XCTAssertThrowsError(try StoredApprovalEnrollment(epoch: id(9), notificationTag: id(5, count: 32),
            identityPublicKey: id(4, count: 65), approval: valid.approval)) { XCTAssertEqual($0 as? EnrollmentJournalError, .invalidState) }
        _ = try db.write { try $0.configureApprovalAuthority(capabilities: capabilities, allowedContracts: [contract]) }
    }

    private func tokenCandidate(_ db: JournalDatabase, revision: UUID, head: UInt64 = 0, epoch: UInt8 = 9) throws -> GatewayAuthorityEnvelope {
        try db.write { try $0.prepareGatewayCandidate(registrationToken: "synthetic-token", authenticatedPhoneID: id(5), authenticatedEnrollmentEpoch: id(epoch),
            registration: identity(), registrationActive: true, expectedTrustRevision: revision, expectedHead: head,
            nowUnixMillis: 1000, now: moment(), sign: signCandidate) }
    }
    private func signCandidate(_ value: GatewayTokenCandidate) throws -> Data {
        try rootKey.signature(for: GatewayTokenCandidateSigningInput.make(wireVersion: 1, canonicalPayload: value.encode(limits: limits),
            payloadLimits: limits, inputLimits: limits)).rawRepresentation
    }
    private func tokenProof(_ envelope: GatewayAuthorityEnvelope) throws -> Data {
        try GatewayTokenProof(binding: GatewayTokenCandidate.decode(envelope.canonicalPayload, limits: limits).binding).encode(limits: limits)
    }
    private func activate(_ db: JournalDatabase, envelope: GatewayAuthorityEnvelope, revision: UUID, head: UInt64 = 1,
                          epoch: UInt8 = 9) throws -> GatewayAuthorityEnvelope {
        try db.write { try $0.consumeGatewayProof(canonicalProof: tokenProof(envelope), authenticatedPhoneID: id(5), authenticatedEnrollmentEpoch: id(epoch),
            registration: identity(), registrationActive: true, expectedTrustRevision: revision, expectedHead: head, nowUnixMillis: 1000, now: moment()) { value in
                try rootKey.signature(for: GatewayRecipientSigningInput.make(wireVersion: 1, kind: .activation,
                    canonicalPayload: value.encode(limits: limits), payloadLimits: limits, inputLimits: limits)).rawRepresentation
            } }
    }

    func testPublicGatewayCandidateAndProofUseStoredPhoneTagAndEpoch() throws {
        let fixture = try Fixture(), (db, writer, empty) = try setup(fixture)
        try db.write { try $0.configureGatewayAuthority(identity()) }
        XCTAssertThrowsError(try tokenCandidate(db, revision: empty)) { XCTAssertEqual($0 as? EnrollmentJournalError, .unavailableEnrollment) }
        let revision = try add(db, writer: writer, revision: empty)
        let envelope = try tokenCandidate(db, revision: revision)
        let value = try GatewayTokenCandidate.decode(envelope.canonicalPayload, limits: limits)
        XCTAssertEqual(value.binding.enrollmentTag, id(5, count: 32)); XCTAssertEqual(value.binding.enrollmentEpoch, id(9))
        XCTAssertEqual(try db.read { try $0.pendingGatewayControl(operationID: envelope.operationID, phoneID: id(5), enrollmentEpoch: id(9),
            registration: identity(), registrationActive: true, expectedTrustRevision: revision, nowUnixMillis: 1000, now: moment()) }?.signature, envelope.signature)
        let activation = try activate(db, envelope: envelope, revision: revision)
        XCTAssertEqual(try GatewayMappingActivation.decode(activation.canonicalPayload, limits: limits).binding, value.binding)
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(identity()) }, 2)
    }

    func testPublicGatewayRemovalBlocksLateProofRenewalAndPendingControls() throws {
        let fixture = try Fixture(), (db, writer, empty) = try setup(fixture)
        let revision = try add(db, writer: writer, revision: empty)
        try db.write { try $0.configureGatewayAuthority(identity()) }
        let envelope = try tokenCandidate(db, revision: revision)
        let removed = try remove(db, writer: writer, revision: revision, gateway: gatewayRemoval(head: 1))
        XCTAssertThrowsError(try activate(db, envelope: envelope, revision: revision, head: 2)) { XCTAssertEqual($0 as? EnrollmentJournalError, .staleRevision) }
        XCTAssertThrowsError(try activate(db, envelope: envelope, revision: removed.revision, head: 2)) { XCTAssertEqual($0 as? EnrollmentJournalError, .unavailableEnrollment) }
        XCTAssertThrowsError(try db.write { try $0.renewDesiredGatewayCandidate(phoneID: id(5), enrollmentEpoch: id(9),
            registration: identity(), registrationActive: true, expectedTrustRevision: removed.revision, expectedHead: 2,
            nowUnixMillis: 1000, now: moment(), sign: signCandidate) }) { XCTAssertEqual($0 as? EnrollmentJournalError, .unavailableEnrollment) }
        XCTAssertThrowsError(try db.read { try $0.pendingGatewayControl(operationID: envelope.operationID, phoneID: id(5), enrollmentEpoch: id(9),
            registration: identity(), registrationActive: true, expectedTrustRevision: removed.revision, nowUnixMillis: 1000, now: moment()) }) {
            XCTAssertEqual($0 as? EnrollmentJournalError, .unavailableEnrollment)
        }
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(identity()) }, 2)
    }

    func testPublicGatewayRejectsWrongPeerScopeAndInactiveRegistrationBeforeSigning() throws {
        let fixture = try Fixture(), (db, writer, empty) = try setup(fixture)
        let revision = try add(db, writer: writer, revision: empty)
        try db.write { try $0.configureGatewayAuthority(identity()) }
        let r = try identity()
        let wrongAccount = try GatewayRegistrationIdentity(ownerID: r.ownerID, macID: r.macID, accountID: id(99), gatewayID: r.gatewayID,
            lifecycleEpoch: r.lifecycleEpoch, rootPublicKey: r.rootPublicKey)
        let wrongKey = try GatewayRegistrationIdentity(ownerID: r.ownerID, macID: r.macID, accountID: r.accountID, gatewayID: r.gatewayID,
            lifecycleEpoch: r.lifecycleEpoch, rootPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation)
        var signed = false
        for (phone, epoch, registration, active) in [(id(8), id(9), r, true), (id(5), id(10), r, true),
            (id(5), id(9), wrongAccount, true), (id(5), id(9), wrongKey, true), (id(5), id(9), r, false)] {
            XCTAssertThrowsError(try db.write { try $0.prepareGatewayCandidate(registrationToken: "synthetic-token",
                authenticatedPhoneID: phone, authenticatedEnrollmentEpoch: epoch, registration: registration,
                registrationActive: active, expectedTrustRevision: revision, expectedHead: 0, nowUnixMillis: 1000, now: moment()) {
                    signed = true; return try signCandidate($0)
                } })
        }
        XCTAssertFalse(signed)
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(identity()) }, 0)
        _ = try tokenCandidate(db, revision: revision)
    }

    func testPublicGatewayRestartRenewalKeepsPairingAndUsesFreshChallenge() throws {
        let fixture = try Fixture(), (db, writer, empty) = try setup(fixture)
        let revision = try add(db, writer: writer, revision: empty)
        try db.write { try $0.configureGatewayAuthority(identity()) }
        let old = try tokenCandidate(db, revision: revision)
        try db.close()
        let reopened = try open(fixture)
        XCTAssertThrowsError(try activate(reopened, envelope: old, revision: revision)) { XCTAssertEqual($0 as? GatewayAuthorityError, .expired) }
        let fresh = try reopened.write { try $0.renewDesiredGatewayCandidate(phoneID: id(5), enrollmentEpoch: id(9),
            registration: identity(), registrationActive: true, expectedTrustRevision: revision, expectedHead: 1,
            nowUnixMillis: 1000, now: moment(), sign: signCandidate) }
        let first = try GatewayTokenCandidate.decode(old.canonicalPayload, limits: limits), next = try GatewayTokenCandidate.decode(fresh.canonicalPayload, limits: limits)
        XCTAssertNotEqual(first.binding.challenge, next.binding.challenge)
        XCTAssertEqual(next.binding.enrollmentEpoch, first.binding.enrollmentEpoch)
        XCTAssertEqual(next.binding.enrollmentTag, first.binding.enrollmentTag)
        _ = try activate(reopened, envelope: fresh, revision: revision, head: 2)
    }

    func testPublicGatewayNewEnrollmentCannotUseOldEpochProof() throws {
        let fixture = try Fixture(), (db, writer, empty) = try setup(fixture)
        let revision = try add(db, writer: writer, revision: empty)
        try db.write { try $0.configureGatewayAuthority(identity()) }
        let old = try tokenCandidate(db, revision: revision)
        let removed = try remove(db, writer: writer, revision: revision, gateway: gatewayRemoval(head: 1))
        let material = try enrollment(phone: 8, epoch: 10, signingKey: P256.Signing.PrivateKey())
        let replacement = try StoredApprovalEnrollment(epoch: material.epoch, notificationTag: material.notificationTag,
            identityPublicKey: material.identityPublicKey, approval: ApprovalEnrollment(phoneID: id(5), active: true,
                capabilities: material.approval.capabilities, keys: material.approval.keys))
        let nextRevision = try db.write { try $0.addApprovalEnrollment(replacement, expectedTrustRevision: removed.revision,
            eventID: id(42), receiptTimeMs: nil, writer: writer, expectedAuditHead: 2) }
        XCTAssertThrowsError(try activate(db, envelope: old, revision: nextRevision, head: 2)) { XCTAssertEqual($0 as? EnrollmentJournalError, .unavailableEnrollment) }
        let fresh = try tokenCandidate(db, revision: nextRevision, head: 2, epoch: 10)
        XCTAssertThrowsError(try activate(db, envelope: old, revision: nextRevision, head: 3, epoch: 10)) { XCTAssertEqual($0 as? GatewayAuthorityError, .superseded) }
        _ = try activate(db, envelope: fresh, revision: nextRevision, head: 3, epoch: 10)
        XCTAssertEqual(try GatewayTokenCandidate.decode(fresh.canonicalPayload, limits: limits).binding.enrollmentTag, material.notificationTag)
    }

    func testPublicGatewayReadOnlyAndSwallowedEnrollmentFailureCannotWrite() throws {
        let fixture = try Fixture(), (db, writer, empty) = try setup(fixture)
        let revision = try add(db, writer: writer, revision: empty)
        try db.write { try $0.configureGatewayAuthority(identity()) }
        XCTAssertThrowsError(try db.read { try $0.prepareGatewayCandidate(registrationToken: "synthetic-token", authenticatedPhoneID: id(5),
            authenticatedEnrollmentEpoch: id(9), registration: identity(), registrationActive: true, expectedTrustRevision: revision,
            expectedHead: 0, nowUnixMillis: 1000, now: moment(), sign: signCandidate) }) { XCTAssertEqual($0 as? JournalDatabaseError, .readOnly) }
        XCTAssertThrowsError(try db.write { tx in
            _ = try? tx.prepareGatewayCandidate(registrationToken: "synthetic-token", authenticatedPhoneID: id(5),
                authenticatedEnrollmentEpoch: id(9), registration: identity(), registrationActive: true, expectedTrustRevision: empty,
                expectedHead: 0, nowUnixMillis: 1000, now: moment(), sign: signCandidate)
            _ = try tx.prepareGatewayCandidate(registrationToken: "synthetic-token", authenticatedPhoneID: id(5),
                authenticatedEnrollmentEpoch: id(9), registration: identity(), registrationActive: true, expectedTrustRevision: revision,
                expectedHead: 0, nowUnixMillis: 1000, now: moment(), sign: signCandidate)
        }) { XCTAssertEqual($0 as? JournalDatabaseError, .transactionFailed) }
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(identity()) }, 0)
        _ = try tokenCandidate(db, revision: revision)
    }

    private final class Fixture {
        let root: URL
        var directory: String { root.appendingPathComponent("store").path }
        var path: String { directory + "/journal.sqlite" }
        init() throws {
            guard let canonical = realpath(FileManager.default.temporaryDirectory.path, nil) else { throw Failure.injected }
            defer { free(canonical) }
            root = URL(fileURLWithPath: String(cString: canonical)).appendingPathComponent(UUID().uuidString)
            try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            for name in ["writer.lock", "journal.sqlite"] {
                let fd = Darwin.open(directory + "/" + name, O_CREAT | O_EXCL | O_WRONLY, 0o600)
                guard fd >= 0 else { throw Failure.injected }; Darwin.close(fd)
            }
        }
        deinit { try? FileManager.default.removeItem(at: root) }
        func lease() throws -> ProtectedJournalLease { try .init(anchor: root.path, relativeDirectory: "store", owner: getuid()) }
        func sql(_ sql: String) throws {
            var db: OpaquePointer?
            guard sqlite3_open(path, &db) == SQLITE_OK, let db else { throw Failure.injected }
            defer { sqlite3_close(db) }
            guard sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else { throw Failure.injected }
        }
    }
}
