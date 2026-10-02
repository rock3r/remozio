import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import SQLite3
import XCTest
@testable import RemozioCore

final class GatewayDatabaseTests: XCTestCase {
    private let key = P256.Signing.PrivateKey()
    private let epoch = UUID()
    private let token = "synthetic-token"
    private var limits: CBORLimits { get throws { try CBORLimits(maxBytes: 2048, maxDepth: 8, maxItems: 128) } }
    private func id(_ n: UInt8, _ count: Int = 16) -> Data { Data(repeating: n, count: count) }
    private func identity(owner: UInt8 = 1) throws -> GatewayRegistrationIdentity {
        try GatewayRegistrationIdentity(ownerID: id(owner), macID: id(2), accountID: id(3), gatewayID: id(4),
            lifecycleEpoch: id(5), rootPublicKey: key.publicKey.x963Representation)
    }
    private func trust(head: UInt64, phone: UInt8 = 6, active: Bool = true, phoneEpoch: UInt8 = 7) throws -> GatewayCandidateTrust {
        try GatewayCandidateTrust(ownerID: id(1), macID: id(2), accountID: id(3), gatewayID: id(4), lifecycleEpoch: id(5),
            rootPublicKey: key.publicKey.x963Representation, active: true, revision: UUID(), appliedControlRevision: head,
            enrollment: GatewayPhoneEnrollment(phoneID: id(phone), epoch: id(phoneEpoch), tag: id(phone, 32), active: active))
    }
    private func candidate(_ n: UInt8 = 1, revision: UInt64 = 1, phone: UInt8 = 6, operation: UInt8? = nil,
                           issued: UInt64 = 1000, expires: UInt64 = 2000, challenge: UInt8? = nil, phoneEpoch: UInt8 = 7) throws -> GatewayTokenCandidate {
        try GatewayTokenCandidate(binding: GatewayTokenBinding(ownerID: id(1), macID: id(2), accountID: id(3), gatewayID: id(4),
            lifecycleEpoch: id(5), phoneID: id(phone), enrollmentEpoch: id(phoneEpoch), candidateID: id(n),
            tokenDigest: Data(SHA256.hash(data: Data(token.utf8))), challenge: id(challenge ?? n, 32), enrollmentTag: id(phone, 32)),
            revision: revision, operationID: id(operation ?? n), issuedAtUnixMillis: issued, expiresAtUnixMillis: expires)
    }
    private func admit(_ db: GatewayDatabase, _ candidate: GatewayTokenCandidate? = nil, head: UInt64 = 0,
                       wall: UInt64 = 1000, monotonic: UInt64 = 100, clock: UUID? = nil, signature: Data? = nil,
                       active: Bool = true) throws -> GatewayCandidateAdmission {
        let candidate = try candidate ?? self.candidate(), payload = try candidate.encode(limits: limits)
        let input = try GatewayTokenCandidateSigningInput.make(wireVersion: 1, canonicalPayload: payload, payloadLimits: limits, inputLimits: limits)
        return try db.admitCandidate(canonicalPayload: payload, signature: signature ?? key.signature(for: input).rawRepresentation,
            wireVersion: 1, registrationToken: token, trust: trust(head: head, phone: candidate.binding.phoneID.first!, active: active, phoneEpoch: candidate.binding.enrollmentEpoch.first!),
            nowUnixMillis: wall, now: AuthorityMoment(epoch: clock ?? epoch, milliseconds: monotonic))
    }
    private func open(_ fixture: Fixture, initialize: Bool = false, owner: UInt8 = 1, maximum: Int = 10, pending: Int = 2,
                      lifetime: UInt64 = 1000, busy: UInt32 = 100, registration: GatewayRegistrationIdentity? = nil, migrate: Bool = false) throws -> GatewayDatabase {
        try GatewayDatabase(lease: fixture.lease(), identity: registration ?? identity(owner: owner), payloadLimits: limits, signingLimits: limits,
            maximumOperations: maximum, maximumPendingPerEnrollment: pending, maximumLifetimeMillis: lifetime,
            clockEpoch: epoch, busyMilliseconds: busy, initialize: initialize, migrateLegacyStore: migrate)
    }
    private func fails(_ expected: GatewayDatabaseError, _ action: () throws -> Any, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try action(), file: file, line: line) { XCTAssertEqual($0 as? GatewayDatabaseError, expected, file: file, line: line) }
    }

    func testCommittedReceiptHeadAndHistoricalRetrySurviveReopenWithoutPendingToken() throws {
        let fixture = try Fixture()
        XCTAssertThrowsError(try open(fixture))
        let db = try open(fixture, initialize: true), result = try admit(db)
        XCTAssertTrue(result.inserted); XCTAssertEqual(try db.head(), 1)
        XCTAssertEqual(try db.receipt(operationID: id(1))?.canonicalPayload, result.receipt.canonicalPayload)
        XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM gateway_candidates_v1 WHERE token IS NOT NULL"), 1)
        let retry = try admit(db, head: 1, wall: 99999, monotonic: 200)
        XCTAssertFalse(retry.inserted); XCTAssertEqual(retry.receipt.signature, result.receipt.signature)
        XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM gateway_candidates_v1"), 1)
        try db.close()
        let reopened = try open(fixture)
        XCTAssertEqual(try reopened.head(), 1)
        XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM gateway_candidates_v1 WHERE token IS NOT NULL"), 0)
        XCTAssertFalse(try admit(reopened, head: 1, wall: 99999, monotonic: 0).inserted)
        XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM gateway_candidates_v1 WHERE token IS NOT NULL"), 0)
        XCTAssertEqual(String(reflecting: result.receipt), "GatewayCandidateReceipt(redacted)")
    }

    func testOperationCandidateAndChallengeConflictsNeverAdvanceHead() throws {
        let fixture = try Fixture(), db = try open(fixture, initialize: true)
        _ = try admit(db)
        fails(.operationConflict) { try admit(db, candidate(2, revision: 2, operation: 1), head: 1) }
        fails(.operationConflict) { try admit(db, candidate(1, revision: 2, operation: 2, challenge: 2), head: 1) }
        fails(.operationConflict) { try admit(db, candidate(3, revision: 2, challenge: 1), head: 1) }
        XCTAssertEqual(try db.head(), 1)
        XCTAssertNil(try db.receipt(operationID: id(2)))
        XCTAssertTrue(try admit(db, candidate(2, revision: 2), head: 1).inserted)
    }

    func testCurrentTrustHeadAndSignatureAreRequiredEvenForDuplicates() throws {
        let fixture = try Fixture(), db = try open(fixture, initialize: true)
        fails(.headMismatch) { try admit(db, head: 1) }
        XCTAssertThrowsError(try admit(db, signature: Data(repeating: 0, count: 64)))
        XCTAssertThrowsError(try admit(db, active: false))
        XCTAssertThrowsError(try admit(db, wall: 2000))
        XCTAssertEqual(try db.head(), 0)
        _ = try admit(db)
        XCTAssertThrowsError(try admit(db, head: 1, signature: Data(repeating: 0, count: 64)))
        XCTAssertThrowsError(try admit(db, head: 1, active: false))
        fails(.headMismatch) { try admit(db, head: 0) }
        XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM gateway_candidates_v1"), 1)
    }

    func testExpiryClearsLogicalTokenWithoutRestoringItOnRetry() throws {
        let fixture = try Fixture(), db = try open(fixture, initialize: true, pending: 1)
        _ = try admit(db)
        try db.expireCandidates(now: AuthorityMoment(epoch: epoch, milliseconds: 1099))
        XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM gateway_candidates_v1 WHERE token IS NOT NULL"), 1)
        try db.expireCandidates(now: AuthorityMoment(epoch: epoch, milliseconds: 1100))
        XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM gateway_candidates_v1 WHERE token IS NOT NULL"), 0)
        XCTAssertFalse(try admit(db, head: 1, wall: 2000, monotonic: 1100).inserted)
        XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM gateway_candidates_v1 WHERE token IS NOT NULL"), 0)
        XCTAssertTrue(try admit(db, candidate(2, revision: 2, issued: 2000, expires: 3000), head: 1, wall: 2000, monotonic: 1100).inserted)
        XCTAssertEqual(try db.head(), 2)
    }

    func testPerEnrollmentPendingQuotaAndTotalReceiptBound() throws {
        let fixture = try Fixture(), db = try open(fixture, initialize: true, maximum: 3, pending: 1)
        _ = try admit(db)
        fails(.capacityExceeded) { try admit(db, candidate(2, revision: 2), head: 1) }
        XCTAssertEqual(try db.head(), 1)
        _ = try admit(db, candidate(2, revision: 2, phone: 9), head: 1)
        try db.expireCandidates(now: AuthorityMoment(epoch: epoch, milliseconds: 1100))
        _ = try admit(db, candidate(3, revision: 3, issued: 2000, expires: 3000), head: 2, wall: 2000, monotonic: 1100)
        fails(.capacityExceeded) { try admit(db, candidate(4, revision: 4, phone: 9, issued: 2000, expires: 3000), head: 3, wall: 2000, monotonic: 1100) }
        XCTAssertEqual(try db.head(), 3)
        XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM gateway_candidates_v1"), 3)
        XCTAssertFalse(try admit(db, head: 3, wall: 2000, monotonic: 1100).inserted)
    }

    func testFailedHeadWriteRollsBackCandidateAndQuotaTogether() throws {
        let fixture = try Fixture(), db = try open(fixture, initialize: true, pending: 1)
        try fixture.sql("CREATE TRIGGER reject_head BEFORE UPDATE OF head ON gateway_identity_v1 BEGIN SELECT RAISE(ABORT,'fixture'); END")
        XCTAssertThrowsError(try admit(db))
        XCTAssertEqual(try db.head(), 0); XCTAssertNil(try db.receipt(operationID: id(1)))
        XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM gateway_candidates_v1"), 0)
        try fixture.sql("DROP TRIGGER reject_head")
        XCTAssertTrue(try admit(db).inserted)
    }

    func testUnsignedRevisionPersistsWithoutSignedNarrowing() throws {
        let fixture = try Fixture(), db = try open(fixture, initialize: true)
        _ = try admit(db, candidate(revision: .max))
        XCTAssertEqual(try db.head(), .max)
        XCTAssertEqual(try db.receipt(operationID: id(1))?.candidate.revision, .max)
        XCTAssertThrowsError(try admit(db, candidate(2, revision: .max), head: .max))
        try db.close()
        let reopened = try open(fixture)
        XCTAssertEqual(try reopened.head(), .max)
        XCTAssertFalse(try admit(reopened, candidate(revision: .max), head: .max).inserted)
    }

    func testScopeVersionAndReinitializationFailuresDoNotReplaceStore() throws {
        let fixture = try Fixture(), db = try open(fixture, initialize: true)
        _ = try admit(db); try db.close()
        fails(.wrongScope) { try open(fixture, owner: 42) }
        fails(.incompatibleStore) { try open(fixture, initialize: true) }
        try fixture.sql("PRAGMA user_version=99")
        fails(.incompatibleStore) { try open(fixture) }
        try fixture.sql("PRAGMA user_version=2")
        let reopened = try open(fixture)
        XCTAssertEqual(try reopened.head(), 1); try reopened.close()
        try fixture.sql("DROP TABLE gateway_candidates_v1")
        XCTAssertThrowsError(try open(fixture))
        XCTAssertThrowsError(try open(fixture, initialize: true))
    }

    func testEveryRegistrationFieldAndPinnedKeyRemainBoundToTheFile() throws {
        let fixture = try Fixture(), db = try open(fixture, initialize: true)
        try db.close()
        let fields = [id(1), id(2), id(3), id(4), id(5), key.publicKey.x963Representation]
        func identity(_ f: [Data]) throws -> GatewayRegistrationIdentity {
            try GatewayRegistrationIdentity(ownerID: f[0], macID: f[1], accountID: f[2], gatewayID: f[3], lifecycleEpoch: f[4], rootPublicKey: f[5])
        }
        for i in fields.indices {
            var changed = fields
            if i == 5 { changed[i] = P256.Signing.PrivateKey().publicKey.x963Representation }
            else { changed[i][0] ^= 1 }
            fails(.wrongScope) { try open(fixture, registration: identity(changed)) }
            changed[i] = Data()
            fails(.invalidConfiguration) { try identity(changed) }
        }
        let reopened = try open(fixture)
        XCTAssertEqual(try reopened.head(), 0)
    }

    func testCorruptSignedReceiptRetiresOwner() throws {
        let fixture = try Fixture(), db = try open(fixture, initialize: true)
        _ = try admit(db)
        try fixture.sql("UPDATE gateway_candidates_v1 SET signature=zeroblob(64)")
        fails(.corruptData) { try db.receipt(operationID: id(1)) }
        fails(.unavailable) { try db.head() }
    }

    func testClockChangesRetireOwnerAndRestartDoesNotRenewOldCandidates() throws {
        for changed in [AuthorityMoment(epoch: UUID(), milliseconds: 200), AuthorityMoment(epoch: epoch, milliseconds: 99)] {
            let fixture = try Fixture(), db = try open(fixture, initialize: true)
            _ = try admit(db)
            fails(.invalidClock) { try db.expireCandidates(now: changed) }
            fails(.unavailable) { try db.head() }
            try db.close()
            let reopened = try open(fixture)
            XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM gateway_candidates_v1 WHERE token IS NOT NULL"), 0)
            XCTAssertTrue(try admit(reopened, candidate(2, revision: 2), head: 1, monotonic: 0).inserted)
        }
    }

    func testReplacementRetiresOwnerAndCloseReleasesLease() throws {
        let fixture = try Fixture(), db = try open(fixture, initialize: true)
        XCTAssertEqual(rename(fixture.path, fixture.path + ".old"), 0)
        try Fixture.file(fixture.path)
        XCTAssertThrowsError(try db.head())
        fails(.unavailable) { try db.head() }
        try db.close(); try db.close()
        fails(.closed) { try db.head() }
        try FileManager.default.removeItem(atPath: fixture.path)
        XCTAssertEqual(rename(fixture.path + ".old", fixture.path), 0)
        let reopened = try open(fixture)
        XCTAssertEqual(try reopened.head(), 0)
    }

    func testConfigurationAndMalformedFileFailuresReleaseLeaseWithoutReset() throws {
        let fixture = try Fixture()
        fails(.invalidConfiguration) { try open(fixture, initialize: true, maximum: 0) }
        fails(.invalidConfiguration) { try open(fixture, initialize: true, pending: 11) }
        fails(.invalidConfiguration) { try open(fixture, initialize: true, lifetime: 0) }
        fails(.invalidConfiguration) { try open(fixture, initialize: true, busy: 60001) }
        let malformed = Data("not a database".utf8)
        try malformed.write(to: URL(fileURLWithPath: fixture.path)); XCTAssertEqual(chmod(fixture.path, 0o600), 0)
        XCTAssertThrowsError(try open(fixture, initialize: true))
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: fixture.path)), malformed)
        let lease = try fixture.lease(); lease.close()
    }

    private func activation(_ candidate: GatewayTokenCandidate, revision: UInt64 = 2, operation: UInt8 = 50,
                            issued: UInt64 = 1000, expires: UInt64 = 2000) throws -> GatewayMappingActivation {
        try GatewayMappingActivation(binding: candidate.binding, revision: revision, operationID: id(operation),
            issuedAtUnixMillis: issued, expiresAtUnixMillis: expires)
    }
    private func revoke(_ db: GatewayDatabase, revision: UInt64 = 3, head: UInt64 = 2, operation: UInt8 = 60,
                        phone: UInt8 = 6, phoneEpoch: UInt8 = 7, active: Bool = false,
                        wall: UInt64 = 1000, monotonic: UInt64 = 100) throws -> GatewayRecipientApplication {
        let control = try GatewayPhoneRevocation(binding: GatewayPhoneEpochBinding(ownerID: id(1), macID: id(2), accountID: id(3),
            gatewayID: id(4), lifecycleEpoch: id(5), phoneID: id(phone), enrollmentEpoch: id(phoneEpoch)),
            revision: revision, operationID: id(operation), issuedAtUnixMillis: 1000, expiresAtUnixMillis: 2000)
        return try apply(db, payload: control.encode(limits: limits), kind: .phoneRevocation, head: head,
            phone: phone, phoneEpoch: phoneEpoch, active: active, wall: wall, monotonic: monotonic)
    }
    private func activate(_ db: GatewayDatabase, _ activation: GatewayMappingActivation, head: UInt64,
                          active: Bool = true, wall: UInt64 = 1000, monotonic: UInt64 = 100) throws -> GatewayRecipientApplication {
        try apply(db, payload: activation.encode(limits: limits), kind: .activation, head: head,
            phone: activation.binding.phoneID.first!, phoneEpoch: activation.binding.enrollmentEpoch.first!, active: active, wall: wall, monotonic: monotonic)
    }
    private func apply(_ db: GatewayDatabase, payload: Data, kind: GatewayRecipientKind, head: UInt64,
                       phone: UInt8 = 6, phoneEpoch: UInt8 = 7, active: Bool = true,
                       wall: UInt64 = 1000, monotonic: UInt64 = 100, signature: Data? = nil,
                       trusted: GatewayCandidateTrust? = nil, version: UInt64 = 1) throws -> GatewayRecipientApplication {
        let input = try GatewayRecipientSigningInput.make(wireVersion: 1, kind: kind, canonicalPayload: payload, payloadLimits: limits, inputLimits: limits)
        return try db.applyRecipient(canonicalPayload: payload, signature: signature ?? key.signature(for: input).rawRepresentation,
            wireVersion: version, kind: kind, trust: trusted ?? trust(head: head, phone: phone, active: active, phoneEpoch: phoneEpoch),
            nowUnixMillis: wall, now: AuthorityMoment(epoch: epoch, milliseconds: monotonic))
    }

    func testActivationConsumesCandidateAndMappingSurvivesRestartWithHistoricalReceipt() throws {
        let fixture = try Fixture(), db = try open(fixture, initialize: true), candidate = try candidate()
        _ = try admit(db, candidate)
        XCTAssertNil(try db.activeMapping(trust: trust(head: 1)))
        let control = try activation(candidate), result = try activate(db, control, head: 1)
        XCTAssertTrue(result.inserted); XCTAssertEqual(try db.head(), 2)
        let mapping = try XCTUnwrap(db.activeMapping(trust: trust(head: 2)))
        XCTAssertEqual(mapping.activation, control); XCTAssertEqual(mapping.registrationToken, token)
        XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM gateway_candidates_v1 WHERE token IS NOT NULL"), 0)
        XCTAssertEqual(String(reflecting: mapping), "GatewayActiveMapping(redacted)")
        XCTAssertEqual(String(reflecting: result.receipt), "GatewayRecipientReceipt(redacted)")
        XCTAssertEqual(try db.recipientReceipt(operationID: id(50))?.signature, result.receipt.signature)
        XCTAssertFalse(try activate(db, control, head: 2, wall: 9999).inserted)
        fails(.unavailableCandidate) { try activate(db, activation(candidate, revision: 3, operation: 51), head: 2) }
        try db.close()
        let reopened = try open(fixture)
        XCTAssertEqual(try reopened.activeMapping(trust: trust(head: 2))?.registrationToken, token)
        XCTAssertFalse(try activate(reopened, control, head: 2, wall: 9999, monotonic: 0).inserted)
        XCTAssertEqual(try reopened.head(), 2)
    }

    func testRevocationPersistsInvalidatesAllPendingAndCannotBeUndoneByLateControls() throws {
        let fixture = try Fixture(), db = try open(fixture, initialize: true), first = try candidate()
        _ = try admit(db, first); let activated = try activation(first); _ = try activate(db, activated, head: 1)
        let next = try candidate(2, revision: 3); _ = try admit(db, next, head: 2)
        let result = try revoke(db, revision: 4, head: 3)
        XCTAssertTrue(result.inserted); XCTAssertTrue(try db.isPhoneRevoked(phoneID: id(6), enrollmentEpoch: id(7)))
        XCTAssertNil(try db.activeMapping(trust: trust(head: 4)))
        XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM gateway_candidates_v1 WHERE token IS NOT NULL"), 0)
        XCTAssertFalse(try activate(db, activated, head: 4, active: false, wall: 9999).inserted)
        fails(.revokedEnrollment) { try activate(db, activation(next, revision: 5, operation: 51), head: 4) }
        fails(.revokedEnrollment) { try admit(db, candidate(3, revision: 5), head: 4) }
        XCTAssertFalse(try revoke(db, revision: 4, head: 4, wall: 9999).inserted)
        try db.close()
        let reopened = try open(fixture)
        XCTAssertTrue(try reopened.isPhoneRevoked(phoneID: id(6), enrollmentEpoch: id(7)))
        XCTAssertNil(try reopened.activeMapping(trust: trust(head: 4)))
        fails(.revokedEnrollment) { try admit(reopened, candidate(3, revision: 5), head: 4) }
    }

    func testRevocationBeforeAnyProbeBlocksThatEpochButNotOtherPhonesOrFreshEnrollment() throws {
        let fixture = try Fixture(), db = try open(fixture, initialize: true)
        _ = try revoke(db, revision: 1, head: 0)
        fails(.revokedEnrollment) { try admit(db, candidate(revision: 2), head: 1) }
        let other = try candidate(2, revision: 2, phone: 9); _ = try admit(db, other, head: 1)
        _ = try activate(db, activation(other, revision: 3, operation: 51), head: 2)
        let fresh = try candidate(3, revision: 4, phoneEpoch: 8); _ = try admit(db, fresh, head: 3)
        _ = try activate(db, activation(fresh, revision: 5, operation: 52), head: 4)
        _ = try revoke(db, revision: 6, head: 5, operation: 61)
        XCTAssertNotNil(try db.activeMapping(trust: trust(head: 6, phone: 9)))
        XCTAssertNotNil(try db.activeMapping(trust: trust(head: 6, phoneEpoch: 8)))
        XCTAssertNil(try db.activeMapping(trust: trust(head: 6)))
        XCTAssertTrue(try db.isPhoneRevoked(phoneID: id(6), enrollmentEpoch: id(7)))
        XCTAssertFalse(try db.isPhoneRevoked(phoneID: id(6), enrollmentEpoch: id(8)))
    }

    func testNewEnvelopeCannotRenewOriginalCandidateDeadlineOrRestartIt() throws {
        for (wall, moment) in [(UInt64(1100), UInt64(1100)), (UInt64(2000), UInt64(100))] {
            let fixture = try Fixture(), db = try open(fixture, initialize: true), candidate = try candidate()
            _ = try admit(db, candidate)
            fails(.unavailableCandidate) { try activate(db, activation(candidate, issued: wall, expires: wall + 1000), head: 1, wall: wall, monotonic: moment) }
            XCTAssertEqual(try db.head(), 1)
        }
        let fixture = try Fixture(), db = try open(fixture, initialize: true), candidate = try candidate()
        _ = try admit(db, candidate); try db.close()
        let reopened = try open(fixture)
        fails(.unavailableCandidate) { try activate(reopened, activation(candidate), head: 1, monotonic: 0) }
    }

    func testReplacementKeepsOldMappingOnFailureAndRejectsOlderPendingCandidate() throws {
        let fixture = try Fixture(), db = try open(fixture, initialize: true), first = try candidate()
        _ = try admit(db, first); _ = try activate(db, activation(first), head: 1)
        let older = try candidate(2, revision: 3), newer = try candidate(3, revision: 4)
        _ = try admit(db, older, head: 2); _ = try admit(db, newer, head: 3)
        XCTAssertThrowsError(try activate(db, activation(newer, revision: 5, operation: 51), head: 4, active: false))
        XCTAssertEqual(try db.activeMapping(trust: trust(head: 4))?.activation.binding.candidateID, first.binding.candidateID)
        _ = try activate(db, activation(newer, revision: 5, operation: 51), head: 4)
        fails(.unavailableCandidate) { try activate(db, activation(older, revision: 6, operation: 52), head: 5) }
        XCTAssertEqual(try db.activeMapping(trust: trust(head: 5))?.activation.binding.candidateID, newer.binding.candidateID)
        XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM gateway_candidates_v1 WHERE token IS NOT NULL"), 0)
    }

    func testOperationIDsAndRevisionsAreGlobalAcrossAllKinds() throws {
        let fixture = try Fixture(), db = try open(fixture, initialize: true), candidate = try candidate()
        _ = try admit(db, candidate)
        fails(.operationConflict) { try activate(db, activation(candidate, operation: 1), head: 1) }
        XCTAssertThrowsError(try activate(db, activation(candidate, revision: 1), head: 1))
        _ = try activate(db, activation(candidate), head: 1)
        fails(.operationConflict) { try admit(db, self.candidate(2, revision: 3, operation: 50), head: 2) }
        fails(.operationConflict) { try revoke(db, operation: 50) }
        fails(.operationConflict) { try activate(db, activation(candidate, revision: 3), head: 2) }
        XCTAssertEqual(try db.head(), 2)
        _ = try revoke(db, revision: .max)
        XCTAssertEqual(try db.head(), .max)
        XCTAssertEqual(try db.recipientReceipt(operationID: id(60))?.revision, .max)
    }

    func testRecipientLifetimeSignatureVersionAndCurrentTrustAreRequired() throws {
        let fixture = try Fixture(), db = try open(fixture, initialize: true), candidate = try candidate()
        _ = try admit(db, candidate); let payload = try activation(candidate).encode(limits: limits)
        XCTAssertThrowsError(try apply(db, payload: payload, kind: .activation, head: 1, wall: 999))
        XCTAssertThrowsError(try apply(db, payload: payload, kind: .activation, head: 1, wall: 2000))
        XCTAssertThrowsError(try activate(db, activation(candidate, expires: 2001), head: 1))
        XCTAssertThrowsError(try apply(db, payload: payload, kind: .activation, head: 1, signature: id(0, 64)))
        XCTAssertThrowsError(try apply(db, payload: payload, kind: .activation, head: 1, version: 2))
        fails(.headMismatch) { try apply(db, payload: payload, kind: .activation, head: 0) }
        fails(.wrongScope) { try apply(db, payload: payload, kind: .activation, head: 1, phone: 9) }
        fails(.wrongScope) { try apply(db, payload: payload, kind: .activation, head: 1, phoneEpoch: 8) }
        let wrong = try GatewayCandidateTrust(ownerID: id(42), macID: id(2), accountID: id(3), gatewayID: id(4), lifecycleEpoch: id(5),
            rootPublicKey: key.publicKey.x963Representation, active: true, revision: UUID(), appliedControlRevision: 1,
            enrollment: GatewayPhoneEnrollment(phoneID: id(6), epoch: id(7), tag: id(6, 32), active: true))
        fails(.wrongScope) { try apply(db, payload: payload, kind: .activation, head: 1, trusted: wrong) }
        XCTAssertEqual(try db.head(), 1)
        _ = try apply(db, payload: payload, kind: .activation, head: 1)
        XCTAssertThrowsError(try apply(db, payload: payload, kind: .activation, head: 2, signature: id(0, 64)))
    }

    func testActivationAndRevocationRollbackReceiptsHeadTokensAndMappingTogether() throws {
        for table in ["gateway_identity_v1", "gateway_mappings_v2", "gateway_candidates_v1"] {
            let fixture = try Fixture(), db = try open(fixture, initialize: true), candidate = try candidate()
            _ = try admit(db, candidate)
            let event = table == "gateway_mappings_v2" ? "INSERT" : "UPDATE"
            try fixture.sql("CREATE TRIGGER reject_write BEFORE \(event) ON \(table) BEGIN SELECT RAISE(ABORT,'fixture'); END")
            XCTAssertThrowsError(try activate(db, activation(candidate), head: 1))
            XCTAssertEqual(try db.head(), 1); XCTAssertNil(try db.recipientReceipt(operationID: id(50)))
            XCTAssertNil(try db.activeMapping(trust: trust(head: 1)))
            XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM gateway_candidates_v1 WHERE token IS NOT NULL"), 1)
            try fixture.sql("DROP TRIGGER reject_write")
            _ = try activate(db, activation(candidate), head: 1)
            try fixture.sql("CREATE TRIGGER reject_delete BEFORE DELETE ON gateway_mappings_v2 BEGIN SELECT RAISE(ABORT,'fixture'); END")
            XCTAssertThrowsError(try revoke(db))
            XCTAssertEqual(try db.head(), 2); XCTAssertFalse(try db.isPhoneRevoked(phoneID: id(6), enrollmentEpoch: id(7)))
            XCTAssertNotNil(try db.activeMapping(trust: trust(head: 2)))
            XCTAssertNil(try db.recipientReceipt(operationID: id(60)))
            try fixture.sql("DROP TRIGGER reject_delete"); _ = try revoke(db)
        }
    }

    func testCombinedCapacityDoesNotEvictReceiptsOrTombstones() throws {
        let fixture = try Fixture(), db = try open(fixture, initialize: true, maximum: 3)
        let candidate = try candidate(); _ = try admit(db, candidate); _ = try activate(db, activation(candidate), head: 1)
        _ = try revoke(db)
        fails(.capacityExceeded) { try admit(db, self.candidate(2, revision: 4, phone: 9), head: 3) }
        fails(.capacityExceeded) { try revoke(db, revision: 4, head: 3, operation: 61, phone: 9) }
        XCTAssertFalse(try revoke(db, head: 3, wall: 9999).inserted)
        XCTAssertTrue(try db.isPhoneRevoked(phoneID: id(6), enrollmentEpoch: id(7)))
        XCTAssertEqual(try db.head(), 3)
    }

    func testCorruptRecipientSignatureTokenAndMappingRetireOwner() throws {
        for sql in ["UPDATE gateway_recipients_v2 SET signature=zeroblob(64)",
                    "UPDATE gateway_mappings_v2 SET token=x'616263'",
                    "UPDATE gateway_mappings_v2 SET enrollment=zeroblob(16)",
                    "UPDATE gateway_candidates_v1 SET signature=zeroblob(64)"] {
            let fixture = try Fixture(), db = try open(fixture, initialize: true), candidate = try candidate()
            _ = try admit(db, candidate); _ = try activate(db, activation(candidate), head: 1)
            try fixture.sql(sql)
            fails(.corruptData) { try db.activeMapping(trust: trust(head: 2)) }
            fails(.unavailable) { try db.head() }
        }
        let fixture = try Fixture(), db = try open(fixture, initialize: true)
        _ = try revoke(db, revision: 1, head: 0)
        try fixture.sql("UPDATE gateway_recipients_v2 SET signature=zeroblob(64)")
        fails(.corruptData) { try db.isPhoneRevoked(phoneID: id(6), enrollmentEpoch: id(7)) }
        fails(.unavailable) { try db.head() }
    }

    func testExplicitLegacyMigrationPreservesCandidateReceiptAndHead() throws {
        let fixture = try Fixture(), db = try open(fixture, initialize: true)
        let receipt = try admit(db).receipt; try db.close()
        try fixture.sql("DROP TABLE gateway_mappings_v2; DROP TABLE gateway_recipients_v2; PRAGMA user_version=1")
        fails(.incompatibleStore) { try open(fixture) }
        XCTAssertEqual(try fixture.scalar("PRAGMA user_version"), 1)
        let migrated = try open(fixture, migrate: true)
        XCTAssertEqual(try fixture.scalar("PRAGMA user_version"), 2)
        XCTAssertEqual(try migrated.head(), 1)
        XCTAssertEqual(try migrated.receipt(operationID: id(1))?.canonicalPayload, receipt.canonicalPayload)
        XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM gateway_candidates_v1 WHERE token IS NOT NULL"), 0)
        _ = try revoke(migrated, revision: 2, head: 1)
        try migrated.close()
        XCTAssertTrue(try open(fixture).isPhoneRevoked(phoneID: id(6), enrollmentEpoch: id(7)))
    }

    func testLegacyMigrationFailureRollsBackWithoutResettingHistory() throws {
        let fixture = try Fixture(), db = try open(fixture, initialize: true)
        _ = try admit(db); try db.close()
        try fixture.sql("DROP TABLE gateway_mappings_v2; DROP TABLE gateway_recipients_v2; PRAGMA user_version=1; CREATE TABLE gateway_mappings_v2(block INTEGER)")
        XCTAssertThrowsError(try open(fixture, migrate: true))
        XCTAssertEqual(try fixture.scalar("PRAGMA user_version"), 1)
        XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM sqlite_schema WHERE name='gateway_recipients_v2'"), 0)
        XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM gateway_candidates_v1"), 1)
        try fixture.sql("DROP TABLE gateway_mappings_v2")
        let migrated = try open(fixture, migrate: true)
        XCTAssertEqual(try migrated.head(), 1)
    }

    func testFailedReplacementAndRevocationPreserveExistingMappingAndPendingToken() throws {
        let fixture = try Fixture(), db = try open(fixture, initialize: true), first = try candidate()
        _ = try admit(db, first); _ = try activate(db, activation(first), head: 1)
        let next = try candidate(2, revision: 3); _ = try admit(db, next, head: 2)
        try fixture.sql("CREATE TRIGGER reject_head BEFORE UPDATE OF head ON gateway_identity_v1 BEGIN SELECT RAISE(ABORT,'fixture'); END")
        XCTAssertThrowsError(try activate(db, activation(next, revision: 4, operation: 51), head: 3))
        XCTAssertThrowsError(try revoke(db, revision: 4, head: 3))
        XCTAssertEqual(try db.head(), 3)
        XCTAssertEqual(try db.activeMapping(trust: trust(head: 3))?.activation.binding, first.binding)
        XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM gateway_candidates_v1 WHERE token IS NOT NULL"), 1)
        XCTAssertEqual(try fixture.scalar("SELECT count(*) FROM gateway_recipients_v2"), 1)
        XCTAssertFalse(try db.isPhoneRevoked(phoneID: id(6), enrollmentEpoch: id(7)))
        try fixture.sql("DROP TRIGGER reject_head")
        _ = try activate(db, activation(next, revision: 4, operation: 51), head: 3)
        XCTAssertEqual(try db.activeMapping(trust: trust(head: 4))?.activation.binding, next.binding)
    }

    func testActivationMatchesEveryRetainedCandidateFieldAndStoredToken() throws {
        let fixture = try Fixture(), db = try open(fixture, initialize: true), candidate = try candidate()
        _ = try admit(db, candidate)
        let payload = try activation(candidate).encode(limits: limits)
        guard case let .map(original) = try DeterministicCBOR.decode(payload, limits: limits),
              case let .map(binding) = original[1] else { return XCTFail() }
        for field in binding.keys {
            var nested = binding, changed = original
            guard case var .bytes(bytes) = nested[field] else { return XCTFail() }
            bytes[0] ^= 1; nested[field] = .bytes(bytes); changed[1] = .map(nested)
            let altered = try DeterministicCBOR.encode(.map(changed), limits: limits)
            XCTAssertThrowsError(try apply(db, payload: altered, kind: .activation, head: 1))
            XCTAssertEqual(try db.head(), 1)
        }
        let candidateInput = try GatewayTokenCandidateSigningInput.make(wireVersion: 1, canonicalPayload: candidate.encode(limits: limits),
            payloadLimits: limits, inputLimits: limits)
        XCTAssertThrowsError(try apply(db, payload: payload, kind: .activation, head: 1, signature: key.signature(for: candidateInput).rawRepresentation))
        try fixture.sql("UPDATE gateway_candidates_v1 SET token=x'616263'")
        fails(.corruptData) { try activate(db, activation(candidate), head: 1) }
        fails(.unavailable) { try db.head() }
    }

    func testMappingReadsRequireCurrentScopeAndRejectAnOlderStoredMapping() throws {
        let fixture = try Fixture(), db = try open(fixture, initialize: true), first = try candidate()
        _ = try admit(db, first); _ = try activate(db, activation(first), head: 1)
        XCTAssertNil(try db.activeMapping(trust: trust(head: 2, active: false)))
        XCTAssertNil(try db.activeMapping(trust: trust(head: 2, phone: 9)))
        XCTAssertNil(try db.activeMapping(trust: trust(head: 2, phoneEpoch: 8)))
        fails(.headMismatch) { try db.activeMapping(trust: trust(head: 1)) }
        let next = try candidate(2, revision: 3); _ = try admit(db, next, head: 2)
        _ = try activate(db, activation(next, revision: 4, operation: 51), head: 3)
        let oldOperation = id(50).map { String(format: "%02x", $0) }.joined()
        try fixture.sql("UPDATE gateway_mappings_v2 SET operation=x'\(oldOperation)'")
        fails(.corruptData) { try db.activeMapping(trust: trust(head: 4)) }
        fails(.unavailable) { try db.head() }
    }

    private final class Fixture {
        let root: URL
        var directory: String { root.appendingPathComponent("store").path }
        var path: String { directory + "/gateway.sqlite" }
        init() throws {
            guard geteuid() != 0 else { throw XCTSkip("Gateway fixture requires an unprivileged process") }
            guard let canonical = realpath(FileManager.default.temporaryDirectory.path, nil) else { throw GatewayDatabaseError.storage(errno) }
            defer { free(canonical) }
            root = URL(fileURLWithPath: String(cString: canonical)).appendingPathComponent(UUID().uuidString)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            try Self.file(directory + "/writer.lock"); try Self.file(path)
        }
        deinit { try? FileManager.default.removeItem(at: root) }
        func lease() throws -> ProtectedGatewayLease {
            try ProtectedGatewayLease(anchor: root.path, relativeDirectory: "store", serviceUID: geteuid(), ancestorUID: geteuid())
        }
        static func file(_ path: String) throws {
            let fd = Darwin.open(path, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0o600)
            guard fd >= 0 else { throw GatewayDatabaseError.storage(errno) }; Darwin.close(fd)
        }
        func sql(_ sql: String) throws { try connection { if sqlite3_exec($0, sql, nil, nil, nil) != SQLITE_OK { throw GatewayDatabaseError.storage(sqlite3_errcode($0)) } } }
        func scalar(_ sql: String) throws -> Int64 {
            try connection { db in
                var stmt: OpaquePointer?
                guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK, let stmt else { throw GatewayDatabaseError.storage(sqlite3_errcode(db)) }
                defer { sqlite3_finalize(stmt) }
                guard sqlite3_step(stmt) == SQLITE_ROW else { throw GatewayDatabaseError.storage(sqlite3_errcode(db)) }
                return sqlite3_column_int64(stmt, 0)
            }
        }
        private func connection<T>(_ body: (OpaquePointer) throws -> T) throws -> T {
            var db: OpaquePointer?
            let rc = sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE, nil)
            guard rc == SQLITE_OK, let db else { if let db { sqlite3_close(db) }; throw GatewayDatabaseError.storage(rc) }
            defer { sqlite3_close(db) }
            return try body(db)
        }
    }
}
