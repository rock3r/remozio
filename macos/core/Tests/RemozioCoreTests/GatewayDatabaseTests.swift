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
    private func trust(head: UInt64, phone: UInt8 = 6, active: Bool = true) throws -> GatewayCandidateTrust {
        try GatewayCandidateTrust(ownerID: id(1), macID: id(2), accountID: id(3), gatewayID: id(4), lifecycleEpoch: id(5),
            rootPublicKey: key.publicKey.x963Representation, active: true, revision: UUID(), appliedControlRevision: head,
            enrollment: GatewayPhoneEnrollment(phoneID: id(phone), epoch: id(7), tag: id(phone, 32), active: active))
    }
    private func candidate(_ n: UInt8 = 1, revision: UInt64 = 1, phone: UInt8 = 6, operation: UInt8? = nil,
                           issued: UInt64 = 1000, expires: UInt64 = 2000, challenge: UInt8? = nil) throws -> GatewayTokenCandidate {
        try GatewayTokenCandidate(binding: GatewayTokenBinding(ownerID: id(1), macID: id(2), accountID: id(3), gatewayID: id(4),
            lifecycleEpoch: id(5), phoneID: id(phone), enrollmentEpoch: id(7), candidateID: id(n),
            tokenDigest: Data(SHA256.hash(data: Data(token.utf8))), challenge: id(challenge ?? n, 32), enrollmentTag: id(phone, 32)),
            revision: revision, operationID: id(operation ?? n), issuedAtUnixMillis: issued, expiresAtUnixMillis: expires)
    }
    private func admit(_ db: GatewayDatabase, _ candidate: GatewayTokenCandidate? = nil, head: UInt64 = 0,
                       wall: UInt64 = 1000, monotonic: UInt64 = 100, clock: UUID? = nil, signature: Data? = nil,
                       active: Bool = true) throws -> GatewayCandidateAdmission {
        let candidate = try candidate ?? self.candidate(), payload = try candidate.encode(limits: limits)
        let input = try GatewayTokenCandidateSigningInput.make(wireVersion: 1, canonicalPayload: payload, payloadLimits: limits, inputLimits: limits)
        return try db.admitCandidate(canonicalPayload: payload, signature: signature ?? key.signature(for: input).rawRepresentation,
            wireVersion: 1, registrationToken: token, trust: trust(head: head, phone: candidate.binding.phoneID.first!, active: active),
            nowUnixMillis: wall, now: AuthorityMoment(epoch: clock ?? epoch, milliseconds: monotonic))
    }
    private func open(_ fixture: Fixture, initialize: Bool = false, owner: UInt8 = 1, maximum: Int = 10, pending: Int = 2,
                      lifetime: UInt64 = 1000, busy: UInt32 = 100, registration: GatewayRegistrationIdentity? = nil) throws -> GatewayDatabase {
        try GatewayDatabase(lease: fixture.lease(), identity: registration ?? identity(owner: owner), payloadLimits: limits, signingLimits: limits,
            maximumOperations: maximum, maximumPendingPerEnrollment: pending, maximumLifetimeMillis: lifetime,
            clockEpoch: epoch, busyMilliseconds: busy, initialize: initialize)
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
        try fixture.sql("PRAGMA user_version=1")
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
