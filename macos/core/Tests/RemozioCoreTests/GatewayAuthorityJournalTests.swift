import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import SQLite3
import XCTest
@testable import RemozioCore

final class GatewayAuthorityJournalTests: XCTestCase {
    private let key = P256.Signing.PrivateKey()
    private let clockEpoch = UUID()
    private enum Failure: Error { case injected }
    private func id(_ n: UInt8, count: Int = 16) -> Data { Data(repeating: n, count: count) }
    private var limits: CBORLimits { get throws { try .init(maxBytes: 16384, maxDepth: 8, maxItems: 512) } }
    private func trust(active: Bool = true, phone: UInt8 = 6, epoch: UInt8 = 7, tag: UInt8 = 6) throws -> GatewayAuthorityTrust {
        try .init(registration: GatewayRegistrationIdentity(ownerID: id(1), macID: id(2), accountID: id(3), gatewayID: id(4),
            lifecycleEpoch: id(5), rootPublicKey: key.publicKey.x963Representation),
            enrollment: GatewayPhoneEnrollment(phoneID: id(phone), epoch: id(epoch), tag: id(tag, count: 32), active: active), active: true)
    }
    private func moment(_ value: UInt64 = 100, epoch: UUID? = nil) -> AuthorityMoment { .init(epoch: epoch ?? clockEpoch, milliseconds: value) }
    private func sign(_ candidate: GatewayTokenCandidate) throws -> Data {
        try key.signature(for: GatewayTokenCandidateSigningInput.make(wireVersion: 1, canonicalPayload: candidate.encode(limits: limits),
            payloadLimits: limits, inputLimits: limits)).rawRepresentation
    }
    private func sign(_ activation: GatewayMappingActivation) throws -> Data {
        try key.signature(for: GatewayRecipientSigningInput.make(wireVersion: 1, kind: .activation,
            canonicalPayload: activation.encode(limits: limits), payloadLimits: limits, inputLimits: limits)).rawRepresentation
    }
    private func sign(_ revocation: GatewayPhoneRevocation) throws -> Data {
        try key.signature(for: GatewayRecipientSigningInput.make(wireVersion: 1, kind: .phoneRevocation,
            canonicalPayload: revocation.encode(limits: limits), payloadLimits: limits, inputLimits: limits)).rawRepresentation
    }
    private func revoke(_ db: JournalDatabase, head: UInt64, trusted: GatewayAuthorityTrust? = nil,
                        wall: UInt64 = 1010, now: UInt64 = 110) throws -> GatewayAuthorityEnvelope {
        try db.write { try $0.revokeGatewayEnrollment(trust: trusted ?? trust(), expectedHead: head,
            nowUnixMillis: wall, now: moment(now), sign: sign) }
    }
    private func open(_ fixture: Fixture, initialize: Bool = false, maximum: Int = 20, enabled: Bool = true,
                      migrate: Int64? = nil, epoch: UUID? = nil) throws -> JournalDatabase {
        try JournalDatabase(lease: fixture.lease(), macID: id(2), accountID: id(3), recordLimits: limits,
            descriptorLimits: limits, decisionLimits: limits, maximumConsumptions: 20, busyMilliseconds: 100,
            initialize: initialize, migrateFromVersion: migrate,
            gatewayPolicy: enabled ? GatewayAuthorityPolicy(payloadLimits: limits, signingLimits: limits,
                maximumControls: maximum, candidateLifetimeMillis: 1000, clockEpoch: epoch ?? clockEpoch) : nil)
    }
    private func setup(_ fixture: Fixture, maximum: Int = 20) throws -> JournalDatabase {
        let db = try open(fixture, initialize: true, maximum: maximum)
        try db.write { try $0.configureGatewayAuthority(trust().registration) }
        return db
    }
    private func prepare(_ db: JournalDatabase, head: UInt64 = 0, token: String = "synthetic-token", wall: UInt64 = 1000,
                         now: UInt64 = 100, trusted: GatewayAuthorityTrust? = nil, peer: UInt8 = 6) throws -> GatewayAuthorityEnvelope {
        let trust = try trusted ?? self.trust()
        return try db.write {
            try $0.prepareGatewayCandidate(registrationToken: token, authenticatedPhoneID: id(peer), authenticatedEnrollmentEpoch: trust.enrollment.epoch,
                trust: trust, expectedHead: head, nowUnixMillis: wall, now: moment(now), sign: sign)
        }
    }
    private func candidate(_ envelope: GatewayAuthorityEnvelope) throws -> GatewayTokenCandidate {
        try .decode(envelope.canonicalPayload, limits: limits)
    }
    private func proof(_ envelope: GatewayAuthorityEnvelope) throws -> Data {
        try GatewayTokenProof(binding: candidate(envelope).binding).encode(limits: limits)
    }
    private func consume(_ db: JournalDatabase, _ envelope: GatewayAuthorityEnvelope, head: UInt64 = 1,
                         wall: UInt64 = 1010, now: UInt64 = 110, peer: UInt8 = 6,
                         trusted: GatewayAuthorityTrust? = nil, proofBytes: Data? = nil) throws -> GatewayAuthorityEnvelope {
        let trust = try trusted ?? self.trust()
        return try db.write {
            try $0.consumeGatewayProof(canonicalProof: proofBytes ?? proof(envelope), authenticatedPhoneID: id(peer), authenticatedEnrollmentEpoch: trust.enrollment.epoch,
                trust: trust, expectedHead: head, nowUnixMillis: wall, now: moment(now), sign: sign)
        }
    }

    func testCandidateProofAndActivationShareDurableControlHead() throws {
        let fixture = try Fixture(), db = try setup(fixture), first = try prepare(db)
        XCTAssertEqual(first.kind, 1); XCTAssertEqual(first.revision, 1)
        let candidate = try candidate(first)
        XCTAssertEqual(candidate.binding.tokenDigest, Data(SHA256.hash(data: Data("synthetic-token".utf8))))
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 1)
        XCTAssertEqual(try db.read { try $0.pendingGatewayControl(operationID: first.operationID, trust: trust(), nowUnixMillis: 1000, now: moment()) }?.signature, first.signature)
        let activation = try consume(db, first)
        XCTAssertEqual(activation.kind, 2); XCTAssertEqual(activation.revision, 2)
        XCTAssertEqual(try GatewayMappingActivation.decode(activation.canonicalPayload, limits: limits).binding, candidate.binding)
        XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM gateway_root_candidates_v1 WHERE consumed IS NOT NULL"), "1")
        XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM gateway_outbox_v1"), "2")
        XCTAssertNil(try db.read { try $0.pendingGatewayControl(operationID: first.operationID, trust: trust(), nowUnixMillis: 1010, now: moment(110)) })
        XCTAssertEqual(try db.read { try $0.pendingGatewayControl(operationID: activation.operationID, trust: trust(), nowUnixMillis: 1010, now: moment(110)) }?.signature, activation.signature)
        XCTAssertThrowsError(try consume(db, first, head: 2)) { XCTAssertEqual($0 as? GatewayAuthorityError, .alreadyConsumed) }
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 2)
        XCTAssertEqual(String(reflecting: activation), "GatewayAuthorityEnvelope(redacted)")
    }

    func testWrongPeerWrongProofAndRevokedTrustNeverCallSigner() throws {
        let fixture = try Fixture(), db = try setup(fixture), first = try prepare(db)
        for trusted in [try trust(active: false), try trust(epoch: 8), try trust(phone: 9)] {
            XCTAssertThrowsError(try consume(db, first, trusted: trusted))
        }
        XCTAssertThrowsError(try consume(db, first, peer: 9))
        let other = try GatewayTokenBinding(ownerID: id(1), macID: id(2), accountID: id(3), gatewayID: id(4), lifecycleEpoch: id(5),
            phoneID: id(6), enrollmentEpoch: id(7), candidateID: candidate(first).binding.candidateID,
            tokenDigest: candidate(first).binding.tokenDigest, challenge: id(99, count: 32), enrollmentTag: id(6, count: 32))
        var signed = false
        XCTAssertThrowsError(try db.write {
            try $0.consumeGatewayProof(canonicalProof: GatewayTokenProof(binding: other).encode(limits: limits), authenticatedPhoneID: id(6),
                authenticatedEnrollmentEpoch: id(7), trust: trust(), expectedHead: 1, nowUnixMillis: 1010, now: moment(110),
                sign: { value in signed = true; return try sign(value) })
        })
        XCTAssertFalse(signed)
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 1)
        _ = try consume(db, first)
    }

    func testNewTokenChoiceSupersedesOldProofAndOutboxWithoutActivatingAnything() throws {
        let fixture = try Fixture(), db = try setup(fixture), first = try prepare(db), second = try prepare(db, head: 1, token: "rotated")
        XCTAssertThrowsError(try consume(db, first, head: 2)) { XCTAssertEqual($0 as? GatewayAuthorityError, .superseded) }
        XCTAssertThrowsError(try db.read { try $0.pendingGatewayControl(operationID: first.operationID, trust: trust(), nowUnixMillis: 1010, now: moment(110)) })
        XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM gateway_root_candidates_v1 WHERE consumed IS NOT NULL"), "0")
        _ = try consume(db, second, head: 2)
    }

    func testStorageFailureRollsBackProofOutboxAndHeadTogether() throws {
        for trigger in ["BEFORE INSERT ON gateway_outbox_v1", "BEFORE UPDATE ON gateway_root_candidates_v1", "BEFORE UPDATE ON gateway_authority_v1"] {
            let fixture = try Fixture(), db = try setup(fixture), first = try prepare(db)
            try fixture.sql("CREATE TRIGGER reject_write \(trigger) BEGIN SELECT RAISE(ABORT,'fixture'); END")
            XCTAssertThrowsError(try consume(db, first))
            XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM gateway_root_candidates_v1 WHERE consumed IS NOT NULL"), "0")
            XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM gateway_outbox_v1"), "1")
            XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 1)
            try fixture.sql("DROP TRIGGER reject_write")
            _ = try consume(db, first)
        }
    }

    func testSwallowedMutationFailureStillRollsBackOtherJournalWrites() throws {
        let fixture = try Fixture(), db = try setup(fixture), first = try prepare(db)
        XCTAssertThrowsError(try db.write {
            _ = try? $0.consumeGatewayProof(canonicalProof: proof(first), authenticatedPhoneID: id(9), authenticatedEnrollmentEpoch: id(7),
                trust: trust(), expectedHead: 1, nowUnixMillis: 1010, now: moment(110), sign: sign)
            _ = try $0.prepareGatewayCandidate(registrationToken: "next", authenticatedPhoneID: id(6), authenticatedEnrollmentEpoch: id(7),
                trust: trust(), expectedHead: 1, nowUnixMillis: 1010, now: moment(110), sign: sign)
        }) { XCTAssertEqual($0 as? JournalDatabaseError, .transactionFailed) }
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 1)
        _ = try consume(db, first)
    }

    func testExpiredAndRestartedCandidatesRequireFreshNonceFromCurrentDesiredState() throws {
        let fixture = try Fixture(), db = try setup(fixture), first = try prepare(db)
        XCTAssertThrowsError(try consume(db, first, wall: 2000, now: 1100)) { XCTAssertEqual($0 as? GatewayAuthorityError, .expired) }
        try db.close()
        let nextEpoch = UUID(), reopened = try open(fixture, epoch: nextEpoch)
        XCTAssertThrowsError(try reopened.read {
            try $0.pendingGatewayControl(operationID: first.operationID, trust: trust(), nowUnixMillis: 2000, now: moment(100, epoch: nextEpoch))
        }) { XCTAssertEqual($0 as? GatewayAuthorityError, .expired) }
        let fresh = try reopened.write {
            try $0.renewDesiredGatewayCandidate(trust: trust(), expectedHead: 1, nowUnixMillis: 2000, now: moment(100, epoch: nextEpoch), sign: sign)
        }
        XCTAssertNotEqual(try candidate(fresh).binding.challenge, try candidate(first).binding.challenge)
        XCTAssertNotEqual(try candidate(fresh).binding.candidateID, try candidate(first).binding.candidateID)
        XCTAssertEqual(fresh.registrationToken, first.registrationToken)
        XCTAssertEqual(fresh.revision, 2)
        XCTAssertEqual(try candidate(fresh).expiresAtUnixMillis, 3000)
    }

    func testBadSignatureCapacityAndWrongHeadCannotCommit() throws {
        let fixture = try Fixture(), db = try setup(fixture, maximum: 2), first = try prepare(db)
        XCTAssertThrowsError(try db.write {
            try $0.consumeGatewayProof(canonicalProof: proof(first), authenticatedPhoneID: id(6), authenticatedEnrollmentEpoch: id(7),
                trust: trust(), expectedHead: 1, nowUnixMillis: 1010, now: moment(110), sign: { _ in Data(repeating: 0, count: 64) })
        }) { XCTAssertEqual($0 as? GatewayAuthorityError, .invalidSignature) }
        _ = try consume(db, first)
        XCTAssertThrowsError(try prepare(db, head: 2, now: 110)) { XCTAssertEqual($0 as? GatewayAuthorityError, .capacityExceeded) }
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 2)
        XCTAssertThrowsError(try prepare(db, head: 1, now: 110)) { XCTAssertEqual($0 as? GatewayAuthorityError, .headMismatch) }
        XCTAssertThrowsError(try db.read { _ in }) { XCTAssertEqual($0 as? JournalDatabaseError, .unavailable) }
    }

    func testDisabledReadOnlyAndEscapedTransactionNeverWrite() throws {
        let fixture = try Fixture(), disabled = try open(fixture, initialize: true, enabled: false)
        XCTAssertThrowsError(try disabled.write { try $0.configureGatewayAuthority(trust().registration) }) { XCTAssertEqual($0 as? GatewayAuthorityError, .disabled) }
        try disabled.close()
        let db = try open(fixture)
        XCTAssertThrowsError(try db.read { try $0.configureGatewayAuthority(trust().registration) }) { XCTAssertEqual($0 as? JournalDatabaseError, .readOnly) }
        let escaped = try db.write { $0 }
        XCTAssertThrowsError(try escaped.configureGatewayAuthority(trust().registration)) { XCTAssertEqual($0 as? JournalDatabaseError, .expiredTransaction) }
        try db.write { try $0.configureGatewayAuthority(trust().registration) }
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 0)
    }

    func testAuthorityControlsDriveTheRealGatewayCandidateAndActivationChecks() throws {
        let fixture = try Fixture(), root = try setup(fixture), first = try prepare(root), trusted = try trust()
        let gateway = try fixture.gateway(identity: trusted.registration, limits: limits, epoch: clockEpoch)
        func gatewayTrust(_ head: UInt64) throws -> GatewayCandidateTrust {
            let r = trusted.registration
            return try GatewayCandidateTrust(ownerID: r.ownerID, macID: r.macID, accountID: r.accountID, gatewayID: r.gatewayID,
                lifecycleEpoch: r.lifecycleEpoch, rootPublicKey: r.rootPublicKey, active: true, revision: UUID(),
                appliedControlRevision: head, enrollment: trusted.enrollment)
        }
        _ = try gateway.admitCandidate(canonicalPayload: first.canonicalPayload, signature: first.signature, wireVersion: 1,
            registrationToken: XCTUnwrap(first.registrationToken), trust: gatewayTrust(0), nowUnixMillis: 1000, now: moment())
        XCTAssertNil(try gateway.activeMapping(trust: gatewayTrust(1)))
        let snapshot = try gatewayTrust(1)
        let reservation = try gateway.reserveProbe(candidateOperationID: first.operationID, trust: snapshot, nowUnixMillis: 1000, now: moment())
        let probe = try gateway.takeProbe(reservation, trust: snapshot, nowUnixMillis: 1000, now: moment())
        let binding = try candidate(first).binding
        XCTAssertEqual(probe.payload.challenge, binding.challenge)
        XCTAssertEqual(probe.payload.candidateID, binding.candidateID)
        try gateway.finishProbe(reservation, outcome: .accepted, now: moment())
        // This fixture stands in for receipt through the authenticated phone channel, not proof of that channel's implementation.
        let activation = try consume(root, first)
        _ = try gateway.applyRecipient(canonicalPayload: activation.canonicalPayload, signature: activation.signature, wireVersion: 1,
            kind: .activation, trust: gatewayTrust(1), nowUnixMillis: 1010, now: moment(110))
        XCTAssertEqual(try gateway.activeMapping(trust: gatewayTrust(2))?.registrationToken, first.registrationToken)
        let retry = try gateway.applyRecipient(canonicalPayload: activation.canonicalPayload, signature: activation.signature, wireVersion: 1,
            kind: .activation, trust: gatewayTrust(2), nowUnixMillis: 1010, now: moment(110))
        XCTAssertFalse(retry.inserted)
        let removal = try revoke(root, head: 2)
        _ = try gateway.applyRecipient(canonicalPayload: removal.canonicalPayload, signature: removal.signature, wireVersion: 1,
            kind: .phoneRevocation, trust: gatewayTrust(2), nowUnixMillis: 1010, now: moment(110))
        XCTAssertNil(try gateway.activeMapping(trust: gatewayTrust(3)))
        XCTAssertTrue(try root.read { try $0.gatewayEnrollmentRevoked(trust: trusted) })
        let removedAgain = try gateway.applyRecipient(canonicalPayload: removal.canonicalPayload, signature: removal.signature, wireVersion: 1,
            kind: .phoneRevocation, trust: gatewayTrust(3), nowUnixMillis: 1010, now: moment(110))
        XCTAssertFalse(removedAgain.inserted)
    }

    func testKnownSchemaThreeMigrationPreservesAuditIdentityAndRequiresExplicitChoice() throws {
        let fixture = try Fixture(), db = try open(fixture, initialize: true)
        let descriptor = try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(id(2)), 2: .bytes(id(3)), 3: .bytes(id(40)),
            4: .unsigned(7), 5: .unsigned(1), 6: .null, 7: .null, 8: .null,
        ]), limits: limits), limits: limits)
        _ = try db.write { try $0.createEpoch(descriptor) }
        try db.close()
        try fixture.sql("DROP TABLE gateway_recovered_revocations_v1; DROP TABLE gateway_reconciled_controls_v1; DROP TABLE gateway_acknowledgment_v1; DROP TABLE routing_operations_v1; DROP TABLE routing_state_v1; DROP TABLE approval_enrollments_v1; DROP TABLE approval_authority_v1; DROP TABLE gateway_revocations_v1; DROP TABLE gateway_desired_tokens_v1; DROP TABLE gateway_root_candidates_v1; DROP TABLE gateway_outbox_v1; DROP TABLE gateway_authority_v1; PRAGMA user_version=3")
        XCTAssertThrowsError(try open(fixture))
        let migrated = try open(fixture, migrate: 3)
        XCTAssertEqual(try fixture.scalar("PRAGMA user_version"), "10")
        XCTAssertNotNil(try migrated.read { try $0.epoch(id(40)) })
        XCTAssertThrowsError(try migrated.read { try $0.gatewayAuthorityHead(trust().registration) }) { XCTAssertEqual($0 as? GatewayAuthorityError, .unconfigured) }
        try migrated.write { try $0.configureGatewayAuthority(trust().registration) }
        XCTAssertEqual(try migrated.read { try $0.gatewayAuthorityHead(trust().registration) }, 0)
    }

    func testFailedSchemaThreeMigrationLeavesVersionAndOldTablesIntact() throws {
        let fixture = try Fixture(), db = try open(fixture, initialize: true)
        try db.close()
        try fixture.sql("DROP TABLE gateway_recovered_revocations_v1; DROP TABLE gateway_reconciled_controls_v1; DROP TABLE gateway_acknowledgment_v1; DROP TABLE routing_operations_v1; DROP TABLE routing_state_v1; DROP TABLE approval_enrollments_v1; DROP TABLE approval_authority_v1; DROP TABLE gateway_revocations_v1; DROP TABLE gateway_desired_tokens_v1; DROP TABLE gateway_root_candidates_v1; DROP TABLE gateway_outbox_v1; DROP TABLE gateway_authority_v1; PRAGMA user_version=3; CREATE TABLE gateway_outbox_v1(conflict INTEGER)")
        XCTAssertThrowsError(try open(fixture, migrate: 3))
        XCTAssertEqual(try fixture.scalar("PRAGMA user_version"), "3")
        XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM sqlite_schema WHERE name='gateway_authority_v1'"), "0")
        XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM sqlite_schema WHERE name='consumption_outcomes_v1'"), "1")
        try fixture.sql("DROP TABLE gateway_outbox_v1")
        let recovered = try open(fixture, migrate: 3)
        try recovered.close()
    }

    func testCorruptHeadTokenConsumptionAndRestoredDesiredPointerRetireOwner() throws {
        for mutation in ["UPDATE gateway_authority_v1 SET head=zeroblob(8)",
                         "UPDATE gateway_outbox_v1 SET signature=zeroblob(64)",
                         "UPDATE gateway_outbox_v1 SET payload=x'01'",
                         "UPDATE gateway_outbox_v1 SET token=x'616263' WHERE kind=1",
                         "UPDATE gateway_root_candidates_v1 SET consumed=NULL"] {
            let fixture = try Fixture(), db = try setup(fixture), first = try prepare(db)
            _ = try consume(db, first)
            try fixture.sql(mutation)
            XCTAssertThrowsError(try consume(db, first, head: 2)) { XCTAssertEqual($0 as? GatewayAuthorityError, .corruptData) }
            XCTAssertThrowsError(try db.read { _ in }) { XCTAssertEqual($0 as? JournalDatabaseError, .unavailable) }
        }
        let fixture = try Fixture(), db = try setup(fixture), first = try prepare(db)
        _ = try prepare(db, head: 1)
        let oldID = try candidate(first).binding.candidateID.map { String(format: "%02x", $0) }.joined()
        try fixture.sql("UPDATE gateway_desired_tokens_v1 SET candidate=x'\(oldID)'")
        XCTAssertThrowsError(try consume(db, first, head: 2)) { XCTAssertEqual($0 as? GatewayAuthorityError, .corruptData) }
        XCTAssertThrowsError(try db.read { _ in }) { XCTAssertEqual($0 as? JournalDatabaseError, .unavailable) }
    }

    func testWallAndMonotonicExpiryAreIndependentAndBadClockRetiresOwner() throws {
        for (wall, now): (UInt64, UInt64) in [(2000, 100), (1000, 1100), (999, 100)] {
            let fixture = try Fixture(), db = try setup(fixture), first = try prepare(db)
            XCTAssertThrowsError(try consume(db, first, wall: wall, now: now)) { XCTAssertEqual($0 as? GatewayAuthorityError, .expired) }
            XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 1)
        }
        let fixture = try Fixture(), db = try setup(fixture), first = try prepare(db)
        XCTAssertThrowsError(try consume(db, first, now: 99)) { XCTAssertEqual($0 as? GatewayAuthorityError, .invalidClock) }
        XCTAssertThrowsError(try db.read { _ in }) { XCTAssertEqual($0 as? JournalDatabaseError, .unavailable) }
    }

    func testCandidateCreationFailureNeverReplacesCurrentDesiredToken() throws {
        let fixture = try Fixture(), db = try setup(fixture), first = try prepare(db)
        try fixture.sql("CREATE TRIGGER reject_head BEFORE UPDATE ON gateway_authority_v1 BEGIN SELECT RAISE(ABORT,'fixture'); END")
        XCTAssertThrowsError(try prepare(db, head: 1, token: "uncommitted"))
        XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM gateway_outbox_v1"), "1")
        try fixture.sql("DROP TRIGGER reject_head")
        let fresh = try db.write { try $0.renewDesiredGatewayCandidate(trust: trust(), expectedHead: 1, nowUnixMillis: 1000, now: moment(), sign: sign) }
        XCTAssertEqual(fresh.registrationToken, first.registrationToken)
        XCTAssertThrowsError(try prepare(db, head: 2, token: "contains space")) { XCTAssertEqual($0 as? GatewayAuthorityError, .invalidToken) }
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 2)
    }

    func testRevocationRejectsStaleActiveTrustAndLateProofWithoutSigning() throws {
        let fixture = try Fixture(), db = try setup(fixture), first = try prepare(db)
        let removal = try revoke(db, head: 1, trusted: trust(active: false))
        XCTAssertEqual(removal.kind, 3); XCTAssertEqual(removal.revision, 2)
        XCTAssertNil(removal.registrationToken)
        XCTAssertTrue(try db.read { try $0.gatewayEnrollmentRevoked(trust: trust()) })
        XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM gateway_desired_tokens_v1"), "0")
        var signed = false
        XCTAssertThrowsError(try db.write {
            try $0.consumeGatewayProof(canonicalProof: proof(first), authenticatedPhoneID: id(6), authenticatedEnrollmentEpoch: id(7),
                trust: trust(), expectedHead: 2, nowUnixMillis: 1010, now: moment(110), sign: { value in signed = true; return try sign(value) })
        }) { XCTAssertEqual($0 as? GatewayAuthorityError, .unavailableEnrollment) }
        XCTAssertFalse(signed)
        XCTAssertThrowsError(try prepare(db, head: 2, now: 110)) { XCTAssertEqual($0 as? GatewayAuthorityError, .unavailableEnrollment) }
        XCTAssertThrowsError(try db.write {
            try $0.renewDesiredGatewayCandidate(trust: trust(), expectedHead: 2, nowUnixMillis: 1010, now: moment(110), sign: sign)
        }) { XCTAssertEqual($0 as? GatewayAuthorityError, .unavailableEnrollment) }
        XCTAssertThrowsError(try db.read {
            try $0.pendingGatewayControl(operationID: first.operationID, trust: trust(), nowUnixMillis: 1010, now: moment(110))
        }) { XCTAssertEqual($0 as? GatewayAuthorityError, .unavailableEnrollment) }
        XCTAssertEqual(try db.read { try $0.pendingGatewayRevocation(operationID: removal.operationID, trust: trust(active: false),
            nowUnixMillis: 1010, now: moment(110)) }?.signature, removal.signature)
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 2)
    }

    func testInactiveGatewaySuppressesRemovalDeliveryWithoutClearingRevocation() throws {
        let fixture = try Fixture(), db = try setup(fixture), trusted = try trust(active: false)
        let inactive = GatewayAuthorityTrust(registration: trusted.registration, enrollment: trusted.enrollment, active: false)
        let removal = try revoke(db, head: 0, trusted: inactive)
        XCTAssertTrue(try db.read { try $0.gatewayEnrollmentRevoked(trust: inactive) })
        XCTAssertThrowsError(try db.read { try $0.pendingGatewayRevocation(operationID: removal.operationID, trust: inactive,
            nowUnixMillis: 1010, now: moment(110)) }) { XCTAssertEqual($0 as? GatewayAuthorityError, .unavailableRegistration) }
        XCTAssertEqual(try db.read { try $0.pendingGatewayRevocation(operationID: removal.operationID, trust: trusted,
            nowUnixMillis: 1010, now: moment(110)) }?.signature, removal.signature)
        XCTAssertTrue(try db.read { try $0.gatewayEnrollmentRevoked(trust: trusted) })
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trusted.registration) }, 1)
    }

    func testRevocationSurvivesExpiryAndRestartAndRefreshesOnlyRemoval() throws {
        let fixture = try Fixture(), db = try setup(fixture)
        let removal = try revoke(db, head: 0)
        XCTAssertThrowsError(try db.read { try $0.pendingGatewayRevocation(operationID: removal.operationID, trust: trust(),
            nowUnixMillis: 2010, now: moment(1110)) }) { XCTAssertEqual($0 as? GatewayAuthorityError, .expired) }
        XCTAssertTrue(try db.read { try $0.gatewayEnrollmentRevoked(trust: trust()) })
        try db.close()
        let reopened = try open(fixture)
        XCTAssertTrue(try reopened.read { try $0.gatewayEnrollmentRevoked(trust: trust()) })
        XCTAssertThrowsError(try reopened.read { try $0.pendingGatewayRevocation(operationID: removal.operationID, trust: trust(),
            nowUnixMillis: 1010, now: moment(110)) }) { XCTAssertEqual($0 as? GatewayAuthorityError, .expired) }
        XCTAssertThrowsError(try prepare(reopened, head: 1, now: 110)) { XCTAssertEqual($0 as? GatewayAuthorityError, .unavailableEnrollment) }
        let fresh = try revoke(reopened, head: 1, trusted: trust(active: false), wall: 3000, now: 500)
        XCTAssertNotEqual(fresh.operationID, removal.operationID); XCTAssertEqual(fresh.revision, 2)
        XCTAssertEqual(try GatewayPhoneRevocation.decode(fresh.canonicalPayload, limits: limits).binding,
                       try GatewayPhoneRevocation.decode(removal.canonicalPayload, limits: limits).binding)
        XCTAssertEqual(try reopened.read { try $0.pendingGatewayRevocation(operationID: fresh.operationID, trust: trust(active: false),
            nowUnixMillis: 3000, now: moment(500)) }?.signature, fresh.signature)
        XCTAssertThrowsError(try reopened.read { try $0.pendingGatewayRevocation(operationID: removal.operationID, trust: trust(),
            nowUnixMillis: 3000, now: moment(500)) }) { XCTAssertEqual($0 as? GatewayAuthorityError, .superseded) }
        XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM gateway_revocations_v1"), "2")
        XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM gateway_outbox_v1"), "0")
    }

    func testOldEpochRemovalPreservesNewEnrollmentAndOtherPhones() throws {
        let fixture = try Fixture(), db = try setup(fixture)
        _ = try prepare(db)
        let newer = try prepare(db, head: 1, trusted: trust(epoch: 8)), other = try prepare(db, head: 2, trusted: trust(phone: 9), peer: 9)
        _ = try revoke(db, head: 3)
        XCTAssertFalse(try db.read { try $0.gatewayEnrollmentRevoked(trust: trust(epoch: 8)) })
        XCTAssertFalse(try db.read { try $0.gatewayEnrollmentRevoked(trust: trust(phone: 9)) })
        _ = try consume(db, newer, head: 4, trusted: trust(epoch: 8))
        _ = try consume(db, other, head: 5, peer: 9, trusted: trust(phone: 9))
        _ = try revoke(db, head: 6)
        XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM gateway_desired_tokens_v1"), "2")
        let fresh = try db.write { try $0.renewDesiredGatewayCandidate(trust: trust(epoch: 8), expectedHead: 7,
            nowUnixMillis: 1010, now: moment(110), sign: sign) }
        XCTAssertEqual(try candidate(fresh).binding.enrollmentEpoch, id(8))
    }

    func testRevocationFailureRollsBackTombstoneDesiredStateAndCounter() throws {
        for trigger in ["BEFORE INSERT ON gateway_revocations_v1", "BEFORE DELETE ON gateway_desired_tokens_v1", "BEFORE UPDATE ON gateway_authority_v1"] {
            let fixture = try Fixture(), db = try setup(fixture), first = try prepare(db)
            try fixture.sql("CREATE TRIGGER reject_write \(trigger) BEGIN SELECT RAISE(ABORT,'fixture'); END")
            XCTAssertThrowsError(try revoke(db, head: 1))
            XCTAssertFalse(try db.read { try $0.gatewayEnrollmentRevoked(trust: trust()) })
            XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 1)
            XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM gateway_desired_tokens_v1"), "1")
            try fixture.sql("DROP TRIGGER reject_write")
            _ = try consume(db, first)
        }
    }

    func testRevocationIsAtomicWithAuditAndRejectsReadOnlyOrEscapedTransactions() throws {
        let fixture = try Fixture(), db = try setup(fixture)
        let descriptor = try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(id(2)), 2: .bytes(id(3)), 3: .bytes(id(40)),
            4: .unsigned(7), 5: .unsigned(1), 6: .null, 7: .null, 8: .null,
        ]), limits: limits), limits: limits)
        let writer = try db.write { try $0.createEpoch(descriptor) }
        let event = try AuditEventMetadata(eventID: id(41), macID: id(2), accountID: id(3), journalEpoch: id(40),
            sequence: 1, requestID: nil, eventTimeMs: nil, authorityReceiptTimeMs: nil, kind: .enrollmentRevoked,
            category: .enrollment, action: nil, decisionPhoneID: nil, authentication: .localAdministrator,
            outcome: .accepted, reason: .revoked, droppedEventCount: nil, peerDeviceID: id(6)).encode(limits: limits)
        XCTAssertThrowsError(try db.write {
            _ = try $0.revokeGatewayEnrollment(trust: trust(), expectedHead: 0, nowUnixMillis: 1010, now: moment(110), sign: sign)
            try $0.append(event, writer: writer, expectedHead: 0)
            throw Failure.injected
        })
        XCTAssertFalse(try db.read { try $0.gatewayEnrollmentRevoked(trust: trust()) })
        XCTAssertEqual(try db.read { try $0.epoch(id(40))?.head }, 0)
        XCTAssertThrowsError(try db.read {
            try $0.revokeGatewayEnrollment(trust: trust(), expectedHead: 0, nowUnixMillis: 1010, now: moment(110), sign: sign)
        }) { XCTAssertEqual($0 as? JournalDatabaseError, .readOnly) }
        let escaped = try db.write { $0 }
        XCTAssertThrowsError(try escaped.gatewayEnrollmentRevoked(trust: trust())) { XCTAssertEqual($0 as? JournalDatabaseError, .expiredTransaction) }
        try db.write {
            _ = try $0.revokeGatewayEnrollment(trust: trust(), expectedHead: 0, nowUnixMillis: 1010, now: moment(110), sign: sign)
            try $0.append(event, writer: writer, expectedHead: 0)
        }
        XCTAssertTrue(try db.read { try $0.gatewayEnrollmentRevoked(trust: trust()) })
        XCTAssertEqual(try db.read { try $0.page(epoch: id(40), after: 0, maximumRecords: 10, maximumBytes: 16384).canonicalRecords }, [event])
    }

    func testRevocationSignatureCapacityScopeAndIndependentDeadlines() throws {
        let fixture = try Fixture(), db = try setup(fixture, maximum: 2)
        XCTAssertThrowsError(try db.write {
            try $0.revokeGatewayEnrollment(trust: trust(), expectedHead: 0, nowUnixMillis: 1010, now: moment(110), sign: { _ in id(0, count: 64) })
        }) { XCTAssertEqual($0 as? GatewayAuthorityError, .invalidSignature) }
        XCTAssertFalse(try db.read { try $0.gatewayEnrollmentRevoked(trust: trust()) })
        let removal = try revoke(db, head: 0)
        for (wall, now): (UInt64, UInt64) in [(2010, 110), (1009, 110), (1010, 1110)] {
            XCTAssertThrowsError(try db.read { try $0.pendingGatewayRevocation(operationID: removal.operationID, trust: trust(),
                nowUnixMillis: wall, now: moment(now)) }) { XCTAssertEqual($0 as? GatewayAuthorityError, .expired) }
        }
        _ = try revoke(db, head: 1, now: 1110)
        XCTAssertThrowsError(try revoke(db, head: 2, now: 1110)) { XCTAssertEqual($0 as? GatewayAuthorityError, .capacityExceeded) }
        XCTAssertTrue(try db.read { try $0.gatewayEnrollmentRevoked(trust: trust()) })
        XCTAssertThrowsError(try db.read { try $0.pendingGatewayRevocation(operationID: removal.operationID, trust: trust(phone: 9),
            nowUnixMillis: 1010, now: moment(1110)) }) { XCTAssertEqual($0 as? GatewayAuthorityError, .wrongScope) }
    }

    func testRevocationCorruptionRetiresOwner() throws {
        for mutation in ["UPDATE gateway_revocations_v1 SET signature=zeroblob(64)",
                         "UPDATE gateway_revocations_v1 SET payload=x'01'", "UPDATE gateway_revocations_v1 SET phone=zeroblob(16)",
                         "UPDATE gateway_revocations_v1 SET deadline=started", "DELETE FROM gateway_revocations_v1"] {
            let fixture = try Fixture(), db = try setup(fixture)
            _ = try revoke(db, head: 0)
            try fixture.sql(mutation)
            XCTAssertThrowsError(try db.read { try $0.gatewayEnrollmentRevoked(trust: trust()) }) { XCTAssertEqual($0 as? GatewayAuthorityError, .corruptData) }
            XCTAssertThrowsError(try db.read { _ in }) { XCTAssertEqual($0 as? JournalDatabaseError, .unavailable) }
        }
    }

    func testSchemaFourMigrationPreservesCandidateAndAddsNoRevocation() throws {
        let fixture = try Fixture(), db = try setup(fixture), first = try prepare(db)
        try db.close()
        try fixture.sql("DROP TABLE gateway_recovered_revocations_v1; DROP TABLE gateway_reconciled_controls_v1; DROP TABLE gateway_acknowledgment_v1; DROP TABLE routing_operations_v1; DROP TABLE routing_state_v1; DROP TABLE approval_enrollments_v1; DROP TABLE approval_authority_v1; DROP TABLE gateway_revocations_v1; PRAGMA user_version=4")
        XCTAssertThrowsError(try open(fixture))
        let migrated = try open(fixture, migrate: 4)
        XCTAssertEqual(try migrated.read { try $0.gatewayAuthorityHead(trust().registration) }, 1)
        XCTAssertFalse(try migrated.read { try $0.gatewayEnrollmentRevoked(trust: trust()) })
        let fresh = try migrated.write { try $0.renewDesiredGatewayCandidate(trust: trust(), expectedHead: 1,
            nowUnixMillis: 1000, now: moment(), sign: sign) }
        XCTAssertEqual(fresh.registrationToken, first.registrationToken)
        XCTAssertEqual(try fixture.scalar("PRAGMA user_version"), "10")
    }

    func testFailedSchemaFourMigrationKeepsVersionAndExistingControls() throws {
        let fixture = try Fixture(), db = try setup(fixture)
        _ = try prepare(db); try db.close()
        try fixture.sql("PRAGMA user_version=4")
        XCTAssertThrowsError(try open(fixture, migrate: 4))
        XCTAssertEqual(try fixture.scalar("PRAGMA user_version"), "4")
        XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM gateway_outbox_v1"), "1")
        try fixture.sql("DROP TABLE gateway_recovered_revocations_v1; DROP TABLE gateway_reconciled_controls_v1; DROP TABLE gateway_acknowledgment_v1; DROP TABLE routing_operations_v1; DROP TABLE routing_state_v1; DROP TABLE approval_enrollments_v1; DROP TABLE approval_authority_v1; DROP TABLE gateway_revocations_v1")
        let migrated = try open(fixture, migrate: 4)
        XCTAssertEqual(try migrated.read { try $0.gatewayAuthorityHead(trust().registration) }, 1)
    }

    private func enrollForRecovery(_ db: JournalDatabase, tag: UInt8 = 6, empty: Bool = false, onWriter: (AuditEpochWriter) -> Void = { _ in }) throws -> UUID {
        let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1)
        let capabilities = ContractCapabilities(contracts: [contract: []])
        let revision = try db.write { try $0.configureApprovalAuthority(capabilities: capabilities, allowedContracts: [contract]) }
        if empty { return revision }
        let descriptor = try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(id(2)), 2: .bytes(id(3)), 3: .bytes(id(20)),
            4: .unsigned(7), 5: .unsigned(1), 6: .null, 7: .null, 8: .null,
        ]), limits: limits), limits: limits)
        let writer = try db.write { try $0.createEpoch(descriptor) }
        onWriter(writer)
        let value = try StoredApprovalEnrollment(epoch: id(7), notificationTag: id(tag, count: 32),
            identityPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
            approval: ApprovalEnrollment(phoneID: id(6), active: true, capabilities: capabilities, keys: [
                EnrolledApprovalKey(id: id(11), keyClass: .biometric, publicKey: P256.Signing.PrivateKey().publicKey.x963Representation),
                EnrolledApprovalKey(id: id(12), keyClass: .decision, publicKey: P256.Signing.PrivateKey().publicKey.x963Representation),
            ]))
        return try db.write { try $0.addApprovalEnrollment(value, expectedTrustRevision: revision,
            eventID: id(21), receiptTimeMs: 1000, writer: writer, expectedAuditHead: 0) }
    }

    private func lostDelivery(_ db: JournalDatabase) throws -> [GatewayAuthorityEnvelope] {
        var controls: [GatewayAuthorityEnvelope] = []
        do {
            try db.write { tx in
                let trusted = try trust()
                let next = try tx.prepareGatewayCandidate(registrationToken: "lost-remote-token", authenticatedPhoneID: id(6),
                    authenticatedEnrollmentEpoch: id(7), trust: trusted, expectedHead: 1, nowUnixMillis: 1010, now: moment(110), sign: sign)
                controls.append(next)
                controls.append(try tx.consumeGatewayProof(canonicalProof: proof(next), authenticatedPhoneID: id(6),
                    authenticatedEnrollmentEpoch: id(7), trust: trusted, expectedHead: 2, nowUnixMillis: 1010, now: moment(110), sign: sign))
                throw Failure.injected
            }
        } catch Failure.injected { }
        return controls
    }

    private func recover(_ db: JournalDatabase, _ history: VerifiedGatewayHistory, revision: UUID, local: UInt64 = 1) throws -> GatewayHistoryRecoveryResult {
        try db.write { try $0.reconcileGatewayDeliveryHistory(history, registrationActive: true,
            expectedTrustRevision: revision, expectedLocalRevision: local, now: moment(120)) }
    }

    func testCompleteDeliveryRecoveryRetiresOldProofAndRenewsOnlyLocalDesiredToken() throws {
        let f = try Fixture(), db = try setup(f), revision = try enrollForRecovery(db)
        let first = try prepare(db, token: "current-local-token"), lost = try lostDelivery(db)
        let history = try XCTUnwrap(gatewayEvidence([first] + lost, after: 1).1)
        XCTAssertEqual(try recover(db, history, revision: revision).disposition, .reconciled)
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 3)
        XCTAssertEqual(try db.read { try $0.gatewayAcknowledgment(trust().registration) }?.revision, 3)
        XCTAssertEqual(try db.read { try $0.approvalTrustSnapshot() }.revision, revision)
        for entry in lost {
            XCTAssertNil(try db.read { try $0.pendingGatewayControl(operationID: entry.operationID,
                trust: trust(), nowUnixMillis: 1020, now: moment(120)) })
        }
        XCTAssertThrowsError(try consume(db, first, head: 3, wall: 1020, now: 120)) {
            XCTAssertEqual($0 as? GatewayAuthorityError, .expired)
        }
        let fresh = try db.write { try $0.renewDesiredGatewayCandidate(phoneID: id(6), enrollmentEpoch: id(7),
            registration: trust().registration, registrationActive: true, expectedTrustRevision: revision,
            expectedHead: 3, nowUnixMillis: 1020, now: moment(120), sign: sign) }
        XCTAssertEqual(fresh.revision, 4); XCTAssertEqual(fresh.registrationToken, "current-local-token")
        XCTAssertNotEqual(try candidate(fresh).binding.challenge, try candidate(first).binding.challenge)
        XCTAssertEqual(try f.scalar("SELECT count(*) FROM gateway_reconciled_controls_v1"), "2")
        try db.close()
        let reopened = try open(f)
        XCTAssertEqual(try reopened.read { try $0.gatewayAuthorityHead(trust().registration) }, 4)
        XCTAssertEqual(try reopened.read { try $0.gatewayAcknowledgment(trust().registration) }?.revision, 3)
    }

    func testRecoveryRejectsUnknownEnrollmentAndChangedTagsWithoutAdoption() throws {
        for empty in [true, false] {
            let f = try Fixture(), db = try setup(f), revision = try enrollForRecovery(db, tag: 99, empty: empty)
            let first = try prepare(db), lost = try lostDelivery(db)
            let history = try XCTUnwrap(gatewayEvidence([first] + lost, after: 1).1)
            XCTAssertEqual(try recover(db, history, revision: revision).disposition, .requiresTrustRecovery)
            XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 1)
            XCTAssertEqual(try f.scalar("SELECT count(*) FROM gateway_reconciled_controls_v1"), "0")
            XCTAssertNil(try db.read { try $0.gatewayAcknowledgment(trust().registration) })
        }
    }

    func testRecoveredRevocationCannotUseDeliveryOnlyCounterRepair() throws {
        let sourceFixture = try Fixture(), source = try setup(sourceFixture), candidate = try prepare(source), removal = try revoke(source, head: 1)
        let history = try XCTUnwrap(gatewayEvidence([candidate, removal], after: 0).1)
        let f = try Fixture(), db = try setup(f), revision = try enrollForRecovery(db)
        XCTAssertEqual(try recover(db, history, revision: revision, local: 0).disposition, .requiresTrustRecovery)
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 0)
        XCTAssertEqual(try f.scalar("SELECT count(*) FROM gateway_reconciled_controls_v1"), "0")
    }

    private func recoverRemoval(_ db: JournalDatabase, _ removal: GatewayAuthorityEnvelope, revision: UUID,
                                writer: AuditEpochWriter) throws -> UUID {
        try db.write { try $0.recoverGatewayRevocation(canonicalPayload: removal.canonicalPayload, signature: removal.signature,
            registration: trust().registration, expectedTrustRevision: revision, eventID: id(22), receiptTimeMs: 1020,
            writer: writer, expectedAuditHead: 1) }
    }

    func testRestrictedRemovalHistoryReconcilesWithoutRestoringAuthorityOrReplayingControl() throws {
        let sourceFixture = try Fixture(), source = try setup(sourceFixture), first = try prepare(source)
        let activation = try consume(source, first), removal = try revoke(source, head: 2)
        let history = try XCTUnwrap(gatewayEvidence([first, activation, removal], after: 0).1)
        let f = try Fixture(), db = try setup(f)
        var writer: AuditEpochWriter?
        let before = try enrollForRecovery(db, onWriter: { writer = $0 })
        let revision = try recoverRemoval(db, removal, revision: before, writer: XCTUnwrap(writer))
        XCTAssertEqual(try recover(db, history, revision: revision, local: 0).disposition, .reconciled)
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 3)
        XCTAssertEqual(try db.read { try $0.gatewayAcknowledgment(trust().registration) }?.operationID, removal.operationID)
        XCTAssertEqual(try db.read { try $0.approvalTrustSnapshot() }.revision, revision)
        XCTAssertTrue(try db.read { try $0.approvalTrustSnapshot() }.enrollments.isEmpty)
        XCTAssertEqual(try f.scalar("SELECT count(*) FROM gateway_reconciled_controls_v1"), "2")
        XCTAssertEqual(try f.scalar("SELECT count(*) FROM gateway_revocations_v1"), "1")
        XCTAssertThrowsError(try db.read { try $0.pendingGatewayRevocation(operationID: removal.operationID,
            trust: trust(active: false), nowUnixMillis: 1020, now: moment(120)) }) {
            XCTAssertEqual($0 as? GatewayAuthorityError, .expired)
        }
        XCTAssertThrowsError(try prepare(db, head: 3, wall: 1020, now: 120)) {
            XCTAssertEqual($0 as? GatewayAuthorityError, .unavailableEnrollment)
        }
        XCTAssertEqual(try recover(db, history, revision: revision, local: 0).disposition, .localHeadChanged)
        let refreshed = try revoke(db, head: 3, trusted: trust(active: false), wall: 1020, now: 120)
        XCTAssertEqual(refreshed.revision, 4)
        XCTAssertNotEqual(refreshed.operationID, removal.operationID)
        XCTAssertNotNil(try db.read { try $0.pendingGatewayRevocation(operationID: refreshed.operationID,
            trust: trust(active: false), nowUnixMillis: 1020, now: moment(120)) })
        try db.close()
        let reopened = try open(f)
        XCTAssertEqual(try reopened.read { try $0.gatewayAuthorityHead(trust().registration) }, 4)
        XCTAssertEqual(try reopened.read { try $0.gatewayAcknowledgment(trust().registration) }?.revision, 3)
        XCTAssertTrue(try reopened.read { try $0.gatewayEnrollmentRevoked(trust: trust()) })
    }

    func testRevocationRestrictionAndHistoryRepairCanCommitTogetherAtSharedBoundary() throws {
        let f = try Fixture(), db = try setup(f)
        var writer: AuditEpochWriter?, removal: GatewayAuthorityEnvelope?
        let before = try enrollForRecovery(db, onWriter: { writer = $0 })
        let first = try prepare(db)
        do {
            try db.write {
                removal = try $0.revokeGatewayEnrollment(trust: trust(), expectedHead: 1,
                    nowUnixMillis: 1010, now: moment(110), sign: sign)
                throw Failure.injected
            }
        } catch Failure.injected { }
        let evidence = try XCTUnwrap(removal), history = try XCTUnwrap(gatewayEvidence([first, evidence], after: 1).1)
        let revision = try db.write { tx in
            let revision = try tx.recoverGatewayRevocation(canonicalPayload: evidence.canonicalPayload, signature: evidence.signature,
                registration: trust().registration, expectedTrustRevision: before, eventID: id(22), receiptTimeMs: 1020,
                writer: XCTUnwrap(writer), expectedAuditHead: 1)
            let result = try tx.reconcileGatewayDeliveryHistory(history, registrationActive: true,
                expectedTrustRevision: revision, expectedLocalRevision: 1, now: moment(120))
            XCTAssertEqual(result.disposition, .reconciled)
            return revision
        }
        XCTAssertNotEqual(revision, before)
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 2)
        XCTAssertEqual(try db.read { try $0.gatewayAcknowledgment(trust().registration) }?.revision, 2)
        XCTAssertEqual(try f.scalar("SELECT count(*) FROM gateway_desired_tokens_v1"), "0")
        XCTAssertTrue(try db.read { try $0.approvalTrustSnapshot() }.enrollments.isEmpty)
        XCTAssertEqual(try db.write { try $0.recoverGatewayRevocation(canonicalPayload: evidence.canonicalPayload, signature: evidence.signature,
            registration: trust().registration, expectedTrustRevision: revision, eventID: id(23), receiptTimeMs: 1020,
            writer: XCTUnwrap(writer), expectedAuditHead: 2) }, revision)
    }

    func testReconciliationRequiresBothPermanentEvidenceAndInactiveEnrollment() throws {
        let sourceFixture = try Fixture(), source = try setup(sourceFixture), first = try prepare(source), removal = try revoke(source, head: 1)
        let history = try XCTUnwrap(gatewayEvidence([first, removal], after: 0).1)
        for missingEvidence in [true, false] {
            let f = try Fixture(), db = try setup(f)
            var writer: AuditEpochWriter?
            let before = try enrollForRecovery(db, onWriter: { writer = $0 })
            let revision = try recoverRemoval(db, removal, revision: before, writer: XCTUnwrap(writer))
            if missingEvidence { try f.sql("DELETE FROM gateway_recovered_revocations_v1") }
            else { try f.sql("UPDATE approval_enrollments_v1 SET active=1") }
            XCTAssertEqual(try recover(db, history, revision: revision, local: 0).disposition, .requiresTrustRecovery)
            XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 0)
            XCTAssertEqual(try f.scalar("SELECT count(*) FROM gateway_revocations_v1"), "0")
        }
    }

    func testRestrictedRemovalReconciliationRollsBackWithoutUndoingCommittedRestriction() throws {
        let sourceFixture = try Fixture(), source = try setup(sourceFixture), first = try prepare(source), removal = try revoke(source, head: 1)
        let history = try XCTUnwrap(gatewayEvidence([first, removal], after: 0).1)
        for target in ["gateway_reconciled_controls_v1", "gateway_revocations_v1", "gateway_authority_v1", "gateway_acknowledgment_v1"] {
            let f = try Fixture(), db = try setup(f)
            var writer: AuditEpochWriter?
            let before = try enrollForRecovery(db, onWriter: { writer = $0 })
            let revision = try recoverRemoval(db, removal, revision: before, writer: XCTUnwrap(writer))
            let operation = target == "gateway_authority_v1" ? "UPDATE" : "INSERT"
            try f.sql("CREATE TRIGGER reject_recovery BEFORE \(operation) ON \(target) BEGIN SELECT RAISE(ABORT,'fixture'); END")
            XCTAssertThrowsError(try recover(db, history, revision: revision, local: 0))
            XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 0)
            XCTAssertEqual(try f.scalar("SELECT count(*) FROM gateway_revocations_v1"), "0")
            XCTAssertEqual(try f.scalar("SELECT count(*) FROM gateway_reconciled_controls_v1"), "0")
            XCTAssertTrue(try db.read { try $0.gatewayEnrollmentRevoked(trust: trust()) })
            XCTAssertTrue(try db.read { try $0.approvalTrustSnapshot() }.enrollments.isEmpty)
            XCTAssertNil(try db.read { try $0.gatewayAcknowledgment(trust().registration) })
            try f.sql("DROP TRIGGER reject_recovery")
            XCTAssertEqual(try recover(db, history, revision: revision, local: 0).disposition, .reconciled)
        }
    }

    func testRecoveredRemovalOperationCannotBeReusedByDifferentHistoricalControl() throws {
        let sourceFixture = try Fixture(), source = try setup(sourceFixture), first = try prepare(source), removal = try revoke(source, head: 1)
        let history = try XCTUnwrap(gatewayEvidence([first, removal], after: 0).1)
        let original = try GatewayPhoneRevocation.decode(removal.canonicalPayload, limits: limits)
        for operation in [first.operationID, removal.operationID] {
            let f = try Fixture(), db = try setup(f)
            var writer: AuditEpochWriter?
            let before = try enrollForRecovery(db, onWriter: { writer = $0 })
            let other = try GatewayPhoneRevocation(binding: original.binding, revision: original.revision, operationID: operation,
                issuedAtUnixMillis: original.issuedAtUnixMillis, expiresAtUnixMillis: original.expiresAtUnixMillis + 1)
            let evidence = try GatewayAuthorityEnvelope(kind: 3, operationID: operation, revision: other.revision,
                canonicalPayload: other.encode(limits: limits), signature: sign(other), registrationToken: nil)
            let revision = try recoverRemoval(db, evidence, revision: before, writer: XCTUnwrap(writer))
            XCTAssertEqual(try recover(db, history, revision: revision, local: 0).disposition, .conflictingLocalHistory)
            XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 0)
            XCTAssertEqual(try f.scalar("SELECT count(*) FROM gateway_reconciled_controls_v1"), "0")
            XCTAssertTrue(try db.read { try $0.gatewayEnrollmentRevoked(trust: trust()) })
        }
    }

    func testRestrictedRemovalHistoryCapacityAndUnknownTagStillRefuseAdoption() throws {
        let sourceFixture = try Fixture(), source = try setup(sourceFixture), first = try prepare(source), removal = try revoke(source, head: 1)
        let history = try XCTUnwrap(gatewayEvidence([first, removal], after: 0).1)
        for capacity in [true, false] {
            let f = try Fixture(), db = try setup(f, maximum: capacity ? 2 : 20)
            var writer: AuditEpochWriter?
            let before = try enrollForRecovery(db, tag: capacity ? 6 : 99, onWriter: { writer = $0 })
            let revision = try recoverRemoval(db, removal, revision: before, writer: XCTUnwrap(writer))
            if capacity {
                XCTAssertThrowsError(try recover(db, history, revision: revision, local: 0)) {
                    XCTAssertEqual($0 as? GatewayAuthorityError, .capacityExceeded)
                }
            } else {
                XCTAssertEqual(try recover(db, history, revision: revision, local: 0).disposition, .requiresTrustRecovery)
            }
            XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 0)
            XCTAssertTrue(try db.read { try $0.gatewayEnrollmentRevoked(trust: trust()) })
        }
    }

    func testRecoveryRechecksLocalCounterTrustRevisionRegistrationAndTransactionMode() throws {
        let f = try Fixture(), db = try setup(f), revision = try enrollForRecovery(db)
        let first = try prepare(db), lost = try lostDelivery(db)
        let history = try XCTUnwrap(gatewayEvidence([first] + lost, after: 1).1)
        XCTAssertThrowsError(try recover(db, history, revision: UUID())) { XCTAssertEqual($0 as? EnrollmentJournalError, .staleRevision) }
        XCTAssertThrowsError(try db.write { try $0.reconcileGatewayDeliveryHistory(history, registrationActive: false,
            expectedTrustRevision: revision, expectedLocalRevision: 1, now: moment(120)) }) { XCTAssertEqual($0 as? GatewayAuthorityError, .unavailableRegistration) }
        XCTAssertThrowsError(try db.read { try $0.reconcileGatewayDeliveryHistory(history, registrationActive: true,
            expectedTrustRevision: revision, expectedLocalRevision: 1, now: moment(120)) }) { XCTAssertEqual($0 as? JournalDatabaseError, .readOnly) }
        _ = try prepare(db, head: 1, now: 120)
        XCTAssertEqual(try recover(db, history, revision: revision).disposition, .localHeadChanged)
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 2)
    }

    func testRecoveryRollsBackReceiptsCounterAcknowledgmentAndCandidateRetirementTogether() throws {
        for target in ["gateway_reconciled_controls_v1", "gateway_root_candidates_v1", "gateway_authority_v1", "gateway_acknowledgment_v1"] {
            let f = try Fixture(), db = try setup(f), revision = try enrollForRecovery(db)
            let first = try prepare(db), lost = try lostDelivery(db)
            let history = try XCTUnwrap(gatewayEvidence([first] + lost, after: 1).1)
            let event = target == "gateway_root_candidates_v1" || target == "gateway_authority_v1" ? "UPDATE" : "INSERT"
            try f.sql("CREATE TRIGGER reject_recovery BEFORE \(event) ON \(target) BEGIN SELECT RAISE(ABORT,'fixture'); END")
            XCTAssertThrowsError(try recover(db, history, revision: revision))
            XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 1)
            XCTAssertEqual(try f.scalar("SELECT count(*) FROM gateway_reconciled_controls_v1"), "0")
            XCTAssertNil(try db.read { try $0.gatewayAcknowledgment(trust().registration) })
            XCTAssertNotNil(try db.read { try $0.pendingGatewayControl(operationID: first.operationID,
                trust: trust(), nowUnixMillis: 1020, now: moment(120)) })
            try f.sql("DROP TRIGGER reject_recovery")
            XCTAssertEqual(try recover(db, history, revision: revision).disposition, .reconciled)
        }
    }

    func testRecoveryCapacityFailureDoesNotPartiallyAdoptHistory() throws {
        let f = try Fixture(), db = try setup(f, maximum: 2), revision = try enrollForRecovery(db)
        let first = try prepare(db)
        let sourceFixture = try Fixture(), source = try setup(sourceFixture)
        _ = try prepare(source)
        let lost = try lostDelivery(source)
        let history = try XCTUnwrap(gatewayEvidence([first] + lost, after: 1).1)
        XCTAssertThrowsError(try recover(db, history, revision: revision)) { XCTAssertEqual($0 as? GatewayAuthorityError, .capacityExceeded) }
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, first.revision)
        XCTAssertEqual(try f.scalar("SELECT count(*) FROM gateway_reconciled_controls_v1"), "0")
    }

    func testRecoveryRejectsAnOperationAlreadyRetainedAtAnotherRevision() throws {
        let f = try Fixture(), db = try setup(f), revision = try enrollForRecovery(db), first = try prepare(db)
        let boundary = try prepare(db, head: 1)
        let original = try candidate(first)
        let reused = try GatewayTokenCandidate(binding: original.binding, revision: 3, operationID: first.operationID,
            issuedAtUnixMillis: original.issuedAtUnixMillis, expiresAtUnixMillis: original.expiresAtUnixMillis)
        let envelope = try GatewayAuthorityEnvelope(kind: 1, operationID: first.operationID, revision: 3,
            canonicalPayload: reused.encode(limits: limits), signature: sign(reused), registrationToken: first.registrationToken)
        let history = try XCTUnwrap(gatewayEvidence([boundary, envelope], after: 2).1)
        XCTAssertEqual(try recover(db, history, revision: revision, local: 2).disposition, .conflictingLocalHistory)
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 2)
        XCTAssertEqual(try f.scalar("SELECT count(*) FROM gateway_reconciled_controls_v1"), "0")
    }

    func testRecoveryRejectsAConflictingSharedBoundaryWithoutRetiringCandidates() throws {
        let f = try Fixture(), db = try setup(f), revision = try enrollForRecovery(db), first = try prepare(db)
        let sourceFixture = try Fixture(), source = try setup(sourceFixture), remote = try prepare(source)
        let activation = try consume(source, remote)
        let history = try XCTUnwrap(gatewayEvidence([remote, activation], after: 1).1)
        XCTAssertEqual(try recover(db, history, revision: revision).disposition, .conflictingLocalHistory)
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 1)
        XCTAssertEqual(try f.scalar("SELECT count(*) FROM gateway_reconciled_controls_v1"), "0")
        XCTAssertNotNil(try db.read { try $0.pendingGatewayControl(operationID: first.operationID,
            trust: trust(), nowUnixMillis: 1020, now: moment(120)) })
    }

    func testRecoveryRequiresTheSharedReceiptEvenWhenTheSuffixIsComplete() throws {
        let f = try Fixture(), db = try setup(f), revision = try enrollForRecovery(db)
        let first = try prepare(db), lost = try lostDelivery(db)
        let history = try XCTUnwrap(gatewayEvidence([first] + lost, after: 1, includeBoundary: false).1)
        XCTAssertEqual(try recover(db, history, revision: revision).disposition, .conflictingLocalHistory)
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 1)
        XCTAssertEqual(try f.scalar("SELECT count(*) FROM gateway_reconciled_controls_v1"), "0")
    }

    func testRecoveryDoesNotHideALocalRevocationBehindAnEqualGatewayCounter() throws {
        let sourceFixture = try Fixture(), source = try setup(sourceFixture), remote = try prepare(source)
        let activation = try consume(source, remote)
        let history = try XCTUnwrap(gatewayEvidence([remote, activation], after: 1).1)
        let f = try Fixture(), db = try setup(f), revision = try enrollForRecovery(db)
        _ = try revoke(db, head: 0)
        XCTAssertEqual(try recover(db, history, revision: revision).disposition, .conflictingLocalHistory)
        XCTAssertTrue(try db.read { try $0.gatewayEnrollmentRevoked(trust: trust()) })
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 1)
        XCTAssertEqual(try f.scalar("SELECT count(*) FROM gateway_reconciled_controls_v1"), "0")
    }

    func testRecoveredReceiptCorruptionRetiresTheStorageOwner() throws {
        let f = try Fixture(), db = try setup(f), revision = try enrollForRecovery(db)
        let first = try prepare(db), lost = try lostDelivery(db)
        let history = try XCTUnwrap(gatewayEvidence([first] + lost, after: 1).1)
        _ = try recover(db, history, revision: revision)
        try f.sql("UPDATE gateway_reconciled_controls_v1 SET signature=zeroblob(64)")
        XCTAssertThrowsError(try db.read { try $0.gatewayAuthorityHead(trust().registration) }) {
            XCTAssertEqual($0 as? GatewayAuthorityError, .corruptData)
        }
        XCTAssertThrowsError(try db.read { _ in }) { XCTAssertEqual($0 as? JournalDatabaseError, .unavailable) }
    }

    func testSchemaEightMigrationPreservesDesiredStateAndStartsWithoutRecoveredHistory() throws {
        let f = try Fixture(), db = try setup(f), first = try prepare(db)
        try db.close()
        try f.sql("DROP TABLE gateway_recovered_revocations_v1; DROP TABLE gateway_reconciled_controls_v1; PRAGMA user_version=8")
        XCTAssertThrowsError(try open(f))
        let migrated = try open(f, migrate: 8)
        XCTAssertEqual(try f.scalar("PRAGMA user_version"), "10")
        XCTAssertEqual(try migrated.read { try $0.gatewayAuthorityHead(trust().registration) }, 1)
        XCTAssertEqual(try f.scalar("SELECT count(*) FROM gateway_reconciled_controls_v1"), "0")
        let fresh = try migrated.write { try $0.renewDesiredGatewayCandidate(trust: trust(), expectedHead: 1,
            nowUnixMillis: 1020, now: moment(120), sign: sign) }
        XCTAssertEqual(fresh.registrationToken, first.registrationToken)
    }

    private func verifiedHead(_ controls: [GatewayAuthorityEnvelope]) throws -> VerifiedGatewayHead {
        try gatewayEvidence(controls).0
    }
    private func gatewayEvidence(_ controls: [GatewayAuthorityEnvelope], after: UInt64? = nil, includeBoundary: Bool = true) throws -> (VerifiedGatewayHead, VerifiedGatewayHistory?) {
        let f = try Fixture(), trusted = try trust()
        let gateway = try f.gateway(identity: trusted.registration, limits: limits, epoch: clockEpoch)
        defer { try? gateway.close() }
        for control in controls {
            let r = trusted.registration
            let snapshot = try GatewayCandidateTrust(ownerID: r.ownerID, macID: r.macID, accountID: r.accountID,
                gatewayID: r.gatewayID, lifecycleEpoch: r.lifecycleEpoch, rootPublicKey: r.rootPublicKey,
                active: true, revision: UUID(), appliedControlRevision: gateway.head(), enrollment: trusted.enrollment)
            if control.kind == 1 {
                _ = try gateway.admitCandidate(canonicalPayload: control.canonicalPayload, signature: control.signature,
                    wireVersion: 1, registrationToken: XCTUnwrap(control.registrationToken), trust: snapshot,
                    nowUnixMillis: 1010, now: moment(110))
            } else {
                _ = try gateway.applyRecipient(canonicalPayload: control.canonicalPayload, signature: control.signature,
                    wireVersion: 1, kind: XCTUnwrap(GatewayRecipientKind(rawValue: control.kind)), trust: snapshot,
                    nowUnixMillis: 1010, now: moment(110))
            }
        }
        let gatewayKey = P256.Signing.PrivateKey()
        let owner = try GatewayHeadQueryOwner(registration: trusted.registration,
            gatewayPublicKey: gatewayKey.publicKey.x963Representation, clockEpoch: clockEpoch)
        let query = try owner.makeQuery(now: moment(110))
        let reply = try gateway.headReply(canonicalQuery: query) { try gatewayKey.signature(for: $0).rawRepresentation }
        let head = try owner.accept(reply, now: moment(111))
        guard let after else { return (head, nil) }
        let lowerBound = after == 0 || !includeBoundary ? after : after - 1
        let collector = try GatewayHistoryCollector(head: head, afterRevision: lowerBound)
        let historyQuery = try owner.makeHistoryQuery(afterRevision: lowerBound, throughRevision: head.evidence.revision, now: moment(111))
        let historyReply = try gateway.controlHistoryReply(canonicalQuery: historyQuery) { try gatewayKey.signature(for: $0).rawRepresentation }
        let page = try owner.acceptHistory(historyReply, now: moment(112))
        return (head, try XCTUnwrap(collector.accept(page)))
    }

    func testKnownAcknowledgmentsPersistWithoutChangingAuthorityOrReplayingControls() throws {
        let f = try Fixture(), db = try setup(f)
        XCTAssertNil(try db.read { try $0.gatewayAcknowledgment(trust().registration) })
        let empty = try verifiedHead([])
        let zero = try db.write { try $0.acknowledgeGatewayHead(empty) }
        XCTAssertEqual(zero.disposition, .recorded); XCTAssertEqual(zero.acknowledged?.revision, 0)
        let candidate = try prepare(db), activation = try consume(db, candidate), removal = try revoke(db, head: 2)
        var controls: [GatewayAuthorityEnvelope] = []
        for control in [candidate, activation, removal] {
            controls.append(control)
            let verified = try verifiedHead(controls)
            let result = try db.write { try $0.acknowledgeGatewayHead(verified) }
            XCTAssertEqual(result.disposition, .recorded)
            XCTAssertEqual(result.localRevision, 3); XCTAssertEqual(result.reportedRevision, control.revision)
            XCTAssertEqual(result.acknowledged?.operationID, control.operationID)
            XCTAssertEqual(try db.write { try $0.acknowledgeGatewayHead(verified) }.disposition, .alreadyRecorded)
        }
        XCTAssertEqual(try db.write { try $0.acknowledgeGatewayHead(empty) }.disposition, .olderThanRecorded)
        XCTAssertTrue(try db.read { try $0.gatewayEnrollmentRevoked(trust: trust()) })
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 3)
        XCTAssertEqual(try f.scalar("SELECT count(*) FROM gateway_desired_tokens_v1"), "0")
        try db.close()
        let reopened = try open(f)
        XCTAssertEqual(try reopened.read { try $0.gatewayAcknowledgment(trust().registration) }?.revision, 3)
        XCTAssertTrue(try reopened.read { try $0.gatewayEnrollmentRevoked(trust: trust()) })
    }

    func testMissingDeliveryAndRevocationHistoryCannotAdvanceAcknowledgment() throws {
        let f = try Fixture(), db = try setup(f), candidate = try prepare(db)
        let known = try verifiedHead([candidate])
        _ = try db.write { try $0.acknowledgeGatewayHead(known) }
        let otherFixture = try Fixture(), other = try setup(otherFixture)
        let missing = try prepare(other)
        let removal = try revoke(other, head: 1)
        for controls in [[missing], [missing, removal]] {
            let evidence = try verifiedHead(controls)
            let result = try db.write { try $0.acknowledgeGatewayHead(evidence) }
            XCTAssertEqual(result.disposition, .missingLocalHistory)
            XCTAssertEqual(result.acknowledged?.operationID, candidate.operationID)
        }
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(trust().registration) }, 1)
        XCTAssertEqual(try f.scalar("SELECT count(*) FROM gateway_revocations_v1"), "0")
        XCTAssertEqual(try f.scalar("SELECT count(*) FROM gateway_outbox_v1"), "1")
    }

    func testConflictingKnownOperationCannotBeAcknowledgedEvenBelowPriorHead() throws {
        let f = try Fixture(), db = try setup(f), first = try prepare(db)
        let next = try prepare(db, head: 1, now: 110)
        _ = try db.write { try $0.acknowledgeGatewayHead(verifiedHead([next])) }
        let original = try candidate(first)
        let changed = try GatewayTokenCandidate(binding: original.binding, revision: original.revision,
            operationID: original.operationID, issuedAtUnixMillis: 1001, expiresAtUnixMillis: 2000)
        let forged = GatewayAuthorityEnvelope(kind: 1, operationID: first.operationID, revision: first.revision,
            canonicalPayload: try changed.encode(limits: limits), signature: try sign(changed), registrationToken: first.registrationToken)
        let result = try db.write { try $0.acknowledgeGatewayHead(verifiedHead([forged])) }
        XCTAssertEqual(result.disposition, .conflictingLocalHistory)
        XCTAssertEqual(result.acknowledged?.revision, 2)
    }

    func testAcknowledgmentRollbackAndReadOnlyRejectionLeavePriorEvidenceIntact() throws {
        let f = try Fixture(), db = try setup(f), first = try prepare(db)
        let evidence = try verifiedHead([first])
        XCTAssertThrowsError(try db.read { try $0.acknowledgeGatewayHead(evidence) })
        try f.sql("CREATE TRIGGER reject_ack BEFORE INSERT ON gateway_acknowledgment_v1 BEGIN SELECT RAISE(ABORT,'fixture'); END")
        XCTAssertThrowsError(try db.write { try $0.acknowledgeGatewayHead(evidence) })
        XCTAssertNil(try db.read { try $0.gatewayAcknowledgment(trust().registration) })
        try f.sql("DROP TRIGGER reject_ack")
        XCTAssertEqual(try db.write { try $0.acknowledgeGatewayHead(evidence) }.disposition, .recorded)
        let next = try prepare(db, head: 1, now: 110), nextEvidence = try verifiedHead([next])
        try f.sql("CREATE TRIGGER reject_ack BEFORE UPDATE ON gateway_acknowledgment_v1 BEGIN SELECT RAISE(ABORT,'fixture'); END")
        XCTAssertThrowsError(try db.write { try $0.acknowledgeGatewayHead(nextEvidence) })
        XCTAssertEqual(try db.read { try $0.gatewayAcknowledgment(trust().registration) }?.revision, 1)
        try f.sql("DROP TRIGGER reject_ack")
        XCTAssertEqual(try db.write { try $0.acknowledgeGatewayHead(nextEvidence) }.acknowledged?.revision, 2)
    }

    func testAcknowledgmentCannotCrossRegistrationScope() throws {
        let f = try Fixture(), db = try open(f, initialize: true), r = try trust().registration
        let other = try GatewayRegistrationIdentity(ownerID: id(90), macID: r.macID, accountID: r.accountID,
            gatewayID: r.gatewayID, lifecycleEpoch: r.lifecycleEpoch, rootPublicKey: r.rootPublicKey)
        try db.write { try $0.configureGatewayAuthority(other) }
        let verified = try verifiedHead([])
        XCTAssertThrowsError(try db.write { try $0.acknowledgeGatewayHead(verified) }) {
            XCTAssertEqual($0 as? GatewayAuthorityError, .wrongScope)
        }
        XCTAssertNil(try db.read { try $0.gatewayAcknowledgment(other) })
        XCTAssertEqual(try db.read { try $0.gatewayAuthorityHead(other) }, 0)
    }

    func testAcknowledgmentCorruptionDoesNotBecomeDeliveryEvidence() throws {
        let f = try Fixture(), db = try setup(f), first = try prepare(db)
        _ = try db.write { try $0.acknowledgeGatewayHead(verifiedHead([first])) }
        try f.sql("UPDATE gateway_acknowledgment_v1 SET operation=zeroblob(16)")
        XCTAssertThrowsError(try db.read { try $0.gatewayAcknowledgment(trust().registration) }) {
            XCTAssertEqual($0 as? GatewayAuthorityError, .corruptData)
        }
        XCTAssertThrowsError(try db.read { _ in }) { XCTAssertEqual($0 as? JournalDatabaseError, .unavailable) }
    }

    func testSchemaSevenMigrationStartsWithUnknownAcknowledgmentAndPreservesControlHistory() throws {
        let f = try Fixture(), db = try setup(f), first = try prepare(db)
        try db.close()
        try f.sql("DROP TABLE gateway_recovered_revocations_v1; DROP TABLE gateway_reconciled_controls_v1; DROP TABLE gateway_acknowledgment_v1; PRAGMA user_version=7")
        XCTAssertThrowsError(try open(f))
        let migrated = try open(f, migrate: 7)
        XCTAssertEqual(try f.scalar("PRAGMA user_version"), "10")
        XCTAssertEqual(try migrated.read { try $0.gatewayAuthorityHead(trust().registration) }, 1)
        XCTAssertNil(try migrated.read { try $0.gatewayAcknowledgment(trust().registration) })
        let result = try migrated.write { try $0.acknowledgeGatewayHead(verifiedHead([first])) }
        XCTAssertEqual(result.disposition, .recorded)
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
        func gateway(identity: GatewayRegistrationIdentity, limits: CBORLimits, epoch: UUID) throws -> GatewayDatabase {
            let directory = root.appendingPathComponent("gateway").path
            try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            for name in ["writer.lock", "gateway.sqlite"] {
                let fd = Darwin.open(directory + "/" + name, O_CREAT | O_EXCL | O_WRONLY, 0o600)
                guard fd >= 0 else { throw Failure.injected }; Darwin.close(fd)
            }
            return try GatewayDatabase(lease: ProtectedGatewayLease(anchor: root.path, relativeDirectory: "gateway", serviceUID: geteuid(), ancestorUID: geteuid()),
                identity: identity, payloadLimits: limits, signingLimits: limits, maximumOperations: 20,
                maximumPendingPerEnrollment: 5, maximumLifetimeMillis: 1000, clockEpoch: epoch, busyMilliseconds: 100,
                initialize: true, probePolicy: GatewayProbePolicy(maximumAttempts: 2, minimumRetryDelayMillis: 50, maximumTTLSeconds: 60))
        }
        func sql(_ sql: String) throws {
            try connection { db in guard sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else { throw Failure.injected } }
        }
        func scalar(_ sql: String) throws -> String? {
            try connection { db in
                var stmt: OpaquePointer?
                guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK, let stmt else { throw Failure.injected }
                defer { sqlite3_finalize(stmt) }
                guard sqlite3_step(stmt) == SQLITE_ROW else { throw Failure.injected }
                return sqlite3_column_text(stmt, 0).map { String(cString: $0) }
            }
        }
        private func connection<T>(_ body: (OpaquePointer) throws -> T) throws -> T {
            var db: OpaquePointer?
            guard sqlite3_open(path, &db) == SQLITE_OK, let db else { throw Failure.injected }
            defer { sqlite3_close(db) }
            return try body(db)
        }
    }
}
