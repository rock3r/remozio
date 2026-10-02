import CryptoKit
import Foundation
import RemozioProtocol
import SQLite3

public enum GatewayAuthorityError: Error, Equatable {
    case disabled, invalidConfiguration, unconfigured, wrongScope, unavailableEnrollment, unavailableRegistration, invalidToken
    case headMismatch, capacityExceeded, corruptData, invalidSignature, invalidClock, expired, superseded, alreadyConsumed
}

/// Protected host state. Neither candidate nor proof fields establish this trust.
public struct GatewayAuthorityTrust: Sendable {
    public let registration: GatewayRegistrationIdentity
    public let enrollment: GatewayPhoneEnrollment
    public let active: Bool
    public init(registration: GatewayRegistrationIdentity, enrollment: GatewayPhoneEnrollment, active: Bool) {
        self.registration = registration; self.enrollment = enrollment; self.active = active
    }
}

public struct GatewayAuthorityPolicy: Sendable {
    public let payloadLimits: CBORLimits
    public let signingLimits: CBORLimits
    public let maximumControls: Int
    public let candidateLifetimeMillis: UInt64
    public let clockEpoch: UUID
    public init(payloadLimits: CBORLimits, signingLimits: CBORLimits, maximumControls: Int,
                candidateLifetimeMillis: UInt64, clockEpoch: UUID) throws {
        guard (2...100_000).contains(maximumControls), (1...86_400_000).contains(candidateLifetimeMillis),
              payloadLimits.maxBytes <= 65_536, signingLimits.maxBytes <= 131_072 else {
            throw GatewayAuthorityError.invalidConfiguration
        }
        self.payloadLimits = payloadLimits; self.signingLimits = signingLimits; self.maximumControls = maximumControls
        self.candidateLifetimeMillis = candidateLifetimeMillis; self.clockEpoch = clockEpoch
    }
}

/// A retained signed control, not permission to publish. Recheck current trust and outbox eligibility before sending.
public struct GatewayAuthorityEnvelope: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let kind: UInt64
    public let operationID: Data
    public let revision: UInt64
    public let canonicalPayload: Data
    public let signature: Data
    // Protected operational data. It must never appear in audit history or phone fetch metadata.
    let registrationToken: String?
    public var description: String { "GatewayAuthorityEnvelope(redacted)" }
    public var debugDescription: String { description }
}

/// Private table owner. Every call runs within the journal owner's transaction and protected writer lease.
final class GatewayAuthorityJournal {
    private let db: OpaquePointer
    private let mac: Data
    private let account: Data
    private let policy: GatewayAuthorityPolicy
    private let run = UUID()
    private var lastMoment: UInt64?

    init(connection: OpaquePointer, macID: Data, accountID: Data, policy: GatewayAuthorityPolicy) {
        db = connection; mac = macID; account = accountID; self.policy = policy
    }

    static func createSchema(_ db: OpaquePointer) throws {
        let sql = """
            CREATE TABLE main.gateway_authority_v1(id INTEGER PRIMARY KEY CHECK(id=1), identity BLOB NOT NULL, head BLOB NOT NULL CHECK(length(head)=8)) STRICT;
            CREATE TABLE main.gateway_outbox_v1(
                operation BLOB PRIMARY KEY CHECK(length(operation)=16), revision BLOB NOT NULL UNIQUE CHECK(length(revision)=8),
                kind INTEGER NOT NULL CHECK(kind IN (1,2)), candidate BLOB NOT NULL CHECK(length(candidate)=16),
                payload BLOB NOT NULL, signature BLOB NOT NULL CHECK(length(signature)=64), token BLOB
            ) STRICT, WITHOUT ROWID;
            CREATE UNIQUE INDEX main.gateway_single_activation_v1 ON gateway_outbox_v1(candidate) WHERE kind=2;
            CREATE TABLE main.gateway_root_candidates_v1(
                candidate BLOB PRIMARY KEY CHECK(length(candidate)=16), phone BLOB NOT NULL CHECK(length(phone)=16),
                enrollment BLOB NOT NULL CHECK(length(enrollment)=16), operation BLOB NOT NULL UNIQUE REFERENCES gateway_outbox_v1(operation),
                run BLOB NOT NULL CHECK(length(run)=16), started BLOB NOT NULL CHECK(length(started)=8),
                deadline BLOB NOT NULL CHECK(length(deadline)=8), consumed BLOB REFERENCES gateway_outbox_v1(operation)
            ) STRICT, WITHOUT ROWID;
            CREATE TABLE main.gateway_desired_tokens_v1(
                phone BLOB PRIMARY KEY CHECK(length(phone)=16), candidate BLOB NOT NULL UNIQUE REFERENCES gateway_root_candidates_v1(candidate)
            ) STRICT, WITHOUT ROWID;
            """
        let result = sqlite3_exec(db, sql, nil, nil, nil)
        guard result == SQLITE_OK else { throw JournalDatabaseError.storage(result) }
    }

    static func createRevocationSchema(_ db: OpaquePointer) throws {
        let sql = """
            CREATE TABLE main.gateway_revocations_v1(
                operation BLOB PRIMARY KEY CHECK(length(operation)=16), revision BLOB NOT NULL UNIQUE CHECK(length(revision)=8),
                phone BLOB NOT NULL CHECK(length(phone)=16), enrollment BLOB NOT NULL CHECK(length(enrollment)=16),
                payload BLOB NOT NULL, signature BLOB NOT NULL CHECK(length(signature)=64),
                run BLOB NOT NULL CHECK(length(run)=16), started BLOB NOT NULL CHECK(length(started)=8),
                deadline BLOB NOT NULL CHECK(length(deadline)=8)
            ) STRICT, WITHOUT ROWID;
            CREATE INDEX main.gateway_revoked_epoch_v1 ON gateway_revocations_v1(phone,enrollment,revision DESC);
            """
        let result = sqlite3_exec(db, sql, nil, nil, nil)
        guard result == SQLITE_OK else { throw JournalDatabaseError.storage(result) }
    }

    func configure(_ identity: GatewayRegistrationIdentity) throws {
        try scope(identity)
        let encoded = try identity.encode()
        if let previous = try statement("SELECT identity FROM main.gateway_authority_v1 WHERE id=1", [], { stmt -> Data? in
            let result = sqlite3_step(stmt)
            if result == SQLITE_DONE { return nil }
            guard result == SQLITE_ROW else { throw JournalDatabaseError.storage(result) }
            return try blob(stmt, 0, maximum: 512)
        }) {
            guard previous == encoded else { throw GatewayAuthorityError.wrongScope }
            return
        }
        try statement("SELECT (SELECT count(*) FROM main.gateway_outbox_v1)+(SELECT count(*) FROM main.gateway_root_candidates_v1)+(SELECT count(*) FROM main.gateway_desired_tokens_v1)+(SELECT count(*) FROM main.gateway_revocations_v1)", []) {
            guard sqlite3_step($0) == SQLITE_ROW, sqlite3_column_int64($0, 0) == 0 else { throw GatewayAuthorityError.corruptData }
        }
        try statement("INSERT INTO main.gateway_authority_v1 VALUES(1,?,?)", [encoded, uint(0)]) { try done($0) }
    }

    func head(_ identity: GatewayRegistrationIdentity) throws -> UInt64 {
        try scope(identity)
        return try statement("SELECT identity,head FROM main.gateway_authority_v1 WHERE id=1", []) {
            guard sqlite3_step($0) == SQLITE_ROW else { throw GatewayAuthorityError.unconfigured }
            guard try blob($0, 0, maximum: 512) == identity.encode() else { throw GatewayAuthorityError.wrongScope }
            let value = try unsigned(blob($0, 1, maximum: 8))
            let count = try statement("SELECT (SELECT count(*) FROM main.gateway_outbox_v1)+(SELECT count(*) FROM main.gateway_revocations_v1)", []) { stmt -> UInt64 in
                guard sqlite3_step(stmt) == SQLITE_ROW, let count = UInt64(exactly: sqlite3_column_int64(stmt, 0)) else { throw GatewayAuthorityError.corruptData }
                return count
            }
            guard value == count else { throw GatewayAuthorityError.corruptData }
            if value > 0 {
                try statement("SELECT operation,revision FROM main.gateway_outbox_v1 UNION ALL SELECT operation,revision FROM main.gateway_revocations_v1 ORDER BY revision DESC LIMIT 1", []) { stmt in
                    guard sqlite3_step(stmt) == SQLITE_ROW, let latest = try envelope(blob(stmt, 0, maximum: 16), identity: identity),
                          latest.revision == value else { throw GatewayAuthorityError.corruptData }
                }
            }
            return value
        }
    }

    func prepare(token: String, authenticatedPhoneID: Data, authenticatedEnrollmentEpoch: Data, trust: GatewayAuthorityTrust,
                 expectedHead: UInt64, wall: UInt64, now: AuthorityMoment,
                 sign: (GatewayTokenCandidate) throws -> Data) throws -> GatewayAuthorityEnvelope {
        try authenticate(phone: authenticatedPhoneID, epoch: authenticatedEnrollmentEpoch, trust: trust)
        try clock(now)
        guard !token.isEmpty, token.utf8.count <= 16384, token.utf8.allSatisfy({ (33...126).contains($0) }) else {
            throw GatewayAuthorityError.invalidToken
        }
        try requireHead(expectedHead, identity: trust.registration)
        let (expiry, overflow) = wall.addingReportingOverflow(policy.candidateLifetimeMillis)
        let (deadline, monoOverflow) = now.milliseconds.addingReportingOverflow(policy.candidateLifetimeMillis)
        guard !overflow, !monoOverflow else { throw GatewayAuthorityError.invalidClock }
        let r = trust.registration, e = trust.enrollment, candidateID = uuid(UUID()), operation = uuid(UUID())
        let challenge = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
        let binding = try GatewayTokenBinding(ownerID: r.ownerID, macID: mac, accountID: account, gatewayID: r.gatewayID,
            lifecycleEpoch: r.lifecycleEpoch, phoneID: e.phoneID, enrollmentEpoch: e.epoch, candidateID: candidateID,
            tokenDigest: Data(SHA256.hash(data: Data(token.utf8))), challenge: challenge, enrollmentTag: e.tag)
        let candidate = try GatewayTokenCandidate(binding: binding, revision: expectedHead + 1, operationID: operation,
            issuedAtUnixMillis: wall, expiresAtUnixMillis: expiry)
        let payload = try candidate.encode(limits: policy.payloadLimits), signature = try sign(candidate)
        guard try GatewayTokenCandidateSignature.verify(signature: signature, publicKey: r.rootPublicKey, wireVersion: 1,
            canonicalPayload: payload, payloadLimits: policy.payloadLimits, inputLimits: policy.signingLimits) else { throw GatewayAuthorityError.invalidSignature }
        let envelope = GatewayAuthorityEnvelope(kind: 1, operationID: operation, revision: candidate.revision,
            canonicalPayload: payload, signature: signature, registrationToken: token)
        try insert(envelope, candidate: candidateID)
        try statement("INSERT INTO main.gateway_root_candidates_v1 VALUES(?,?,?,?,?,?,?,NULL)",
            [candidateID, e.phoneID, e.epoch, operation, uuid(run), uint(now.milliseconds), uint(deadline)]) { try done($0) }
        try statement("INSERT INTO main.gateway_desired_tokens_v1 VALUES(?,?) ON CONFLICT(phone) DO UPDATE SET candidate=excluded.candidate",
            [e.phoneID, candidateID]) { try done($0) }
        try advance(from: expectedHead, to: candidate.revision)
        return envelope
    }

    /// Reissue current retained desired state after expiry or restart; never refresh an arbitrary historical outbox entry.
    func renewDesired(trust: GatewayAuthorityTrust, expectedHead: UInt64, wall: UInt64, now: AuthorityMoment,
                      sign: (GatewayTokenCandidate) throws -> Data) throws -> GatewayAuthorityEnvelope {
        try authenticate(phone: trust.enrollment.phoneID, epoch: trust.enrollment.epoch, trust: trust)
        try requireHead(expectedHead, identity: trust.registration)
        _ = try desiredCandidate(trust.enrollment.phoneID)
        let token: String = try statement("""
            SELECT c.operation FROM main.gateway_desired_tokens_v1 d
            JOIN main.gateway_root_candidates_v1 c ON d.candidate=c.candidate WHERE d.phone=?
            """, [trust.enrollment.phoneID]) {
            guard sqlite3_step($0) == SQLITE_ROW,
                  let entry = try envelope(blob($0, 0, maximum: 16), identity: trust.registration), entry.kind == 1,
                  let token = entry.registrationToken else { throw GatewayAuthorityError.unconfigured }
            let candidate = try storedCandidate(entry.canonicalPayload)
            guard candidate.binding.phoneID == trust.enrollment.phoneID, candidate.binding.enrollmentEpoch == trust.enrollment.epoch,
                  candidate.binding.enrollmentTag == trust.enrollment.tag else { throw GatewayAuthorityError.wrongScope }
            guard candidate.binding.tokenDigest == Data(SHA256.hash(data: Data(token.utf8))) else { throw GatewayAuthorityError.corruptData }
            return token
        }
        return try prepare(token: token, authenticatedPhoneID: trust.enrollment.phoneID, authenticatedEnrollmentEpoch: trust.enrollment.epoch,
            trust: trust, expectedHead: expectedHead, wall: wall, now: now, sign: sign)
    }

    func consume(proofBytes: Data, authenticatedPhoneID: Data, authenticatedEnrollmentEpoch: Data, trust: GatewayAuthorityTrust,
                 expectedHead: UInt64, wall: UInt64, now: AuthorityMoment,
                 sign: (GatewayMappingActivation) throws -> Data) throws -> GatewayAuthorityEnvelope {
        try authenticate(phone: authenticatedPhoneID, epoch: authenticatedEnrollmentEpoch, trust: trust)
        try clock(now); try requireHead(expectedHead, identity: trust.registration)
        let proof = try GatewayTokenProof.decode(proofBytes, limits: policy.payloadLimits)
        let retained = try candidate(proof.binding.candidateID, trust: trust, wall: wall, now: now)
        guard proof.binding == retained.value.binding else { throw GatewayAuthorityError.wrongScope }
        guard retained.consumed == nil else { throw GatewayAuthorityError.alreadyConsumed }
        let activation = try GatewayMappingActivation(binding: retained.value.binding, revision: expectedHead + 1,
            operationID: uuid(UUID()), issuedAtUnixMillis: wall, expiresAtUnixMillis: retained.value.expiresAtUnixMillis)
        let payload = try activation.encode(limits: policy.payloadLimits), signature = try sign(activation)
        guard try GatewayRecipientSignature.verify(signature: signature, publicKey: trust.registration.rootPublicKey, wireVersion: 1,
            kind: .activation, canonicalPayload: payload, payloadLimits: policy.payloadLimits, inputLimits: policy.signingLimits) else {
            throw GatewayAuthorityError.invalidSignature
        }
        let envelope = GatewayAuthorityEnvelope(kind: 2, operationID: activation.operationID, revision: activation.revision,
            canonicalPayload: payload, signature: signature, registrationToken: nil)
        try insert(envelope, candidate: proof.binding.candidateID)
        try statement("UPDATE main.gateway_root_candidates_v1 SET consumed=? WHERE candidate=? AND consumed IS NULL",
            [activation.operationID, proof.binding.candidateID]) {
            try done($0); guard sqlite3_changes(db) == 1 else { throw GatewayAuthorityError.alreadyConsumed }
        }
        try advance(from: expectedHead, to: activation.revision)
        return envelope
    }

    func pending(operationID: Data, trust: GatewayAuthorityTrust, wall: UInt64, now: AuthorityMoment) throws -> GatewayAuthorityEnvelope? {
        try authenticate(phone: trust.enrollment.phoneID, epoch: trust.enrollment.epoch, trust: trust)
        try clock(now); _ = try head(trust.registration)
        guard let envelope = try envelope(operationID, identity: trust.registration) else { return nil }
        guard envelope.kind != 3 else { throw GatewayAuthorityError.wrongScope }
        let candidateID: Data
        if envelope.kind == 1 { candidateID = try storedCandidate(envelope.canonicalPayload).binding.candidateID }
        else { candidateID = try storedActivation(envelope.canonicalPayload).binding.candidateID }
        let retained = try candidate(candidateID, trust: trust, wall: wall, now: now)
        if envelope.kind == 1 { guard retained.consumed == nil else { return nil } }
        else { guard retained.consumed == envelope.operationID else { throw GatewayAuthorityError.corruptData } }
        return envelope
    }

    func revoked(trust: GatewayAuthorityTrust) throws -> Bool {
        _ = try head(trust.registration)
        return try latestRevocation(trust: trust) != nil
    }

    /// The signed row is both the permanent epoch tombstone and its retryable delivery control.
    func revoke(trust: GatewayAuthorityTrust, expectedHead: UInt64, wall: UInt64, now: AuthorityMoment,
                sign: (GatewayPhoneRevocation) throws -> Data) throws -> GatewayAuthorityEnvelope {
        try scope(trust.registration); try clock(now); try requireHead(expectedHead, identity: trust.registration)
        _ = try latestRevocation(trust: trust)
        let (expiry, overflow) = wall.addingReportingOverflow(policy.candidateLifetimeMillis)
        let (deadline, monoOverflow) = now.milliseconds.addingReportingOverflow(policy.candidateLifetimeMillis)
        guard !overflow, !monoOverflow else { throw GatewayAuthorityError.invalidClock }
        let r = trust.registration, e = trust.enrollment
        let binding = try GatewayPhoneEpochBinding(ownerID: r.ownerID, macID: mac, accountID: account, gatewayID: r.gatewayID,
            lifecycleEpoch: r.lifecycleEpoch, phoneID: e.phoneID, enrollmentEpoch: e.epoch)
        let value = try GatewayPhoneRevocation(binding: binding, revision: expectedHead + 1, operationID: uuid(UUID()),
            issuedAtUnixMillis: wall, expiresAtUnixMillis: expiry)
        let payload = try value.encode(limits: policy.payloadLimits), signature = try sign(value)
        guard try GatewayRecipientSignature.verify(signature: signature, publicKey: r.rootPublicKey, wireVersion: 1,
            kind: .phoneRevocation, canonicalPayload: payload, payloadLimits: policy.payloadLimits, inputLimits: policy.signingLimits) else {
            throw GatewayAuthorityError.invalidSignature
        }
        try capacity()
        try statement("INSERT INTO main.gateway_revocations_v1 VALUES(?,?,?,?,?,?,?,?,?)",
            [value.operationID, uint(value.revision), e.phoneID, e.epoch, payload, signature, uuid(run), uint(now.milliseconds), uint(deadline)]) { try done($0) }
        try statement("""
            DELETE FROM main.gateway_desired_tokens_v1 WHERE phone=? AND candidate IN
                (SELECT candidate FROM main.gateway_root_candidates_v1 WHERE phone=? AND enrollment=?)
            """, [e.phoneID, e.phoneID, e.epoch]) { try done($0) }
        try advance(from: expectedHead, to: value.revision)
        return GatewayAuthorityEnvelope(kind: 3, operationID: value.operationID, revision: value.revision,
            canonicalPayload: payload, signature: signature, registrationToken: nil)
    }

    func pendingRevocation(operationID: Data, trust: GatewayAuthorityTrust, wall: UInt64, now: AuthorityMoment) throws -> GatewayAuthorityEnvelope? {
        try clock(now); _ = try head(trust.registration)
        guard trust.active else { throw GatewayAuthorityError.unavailableRegistration }
        guard let entry = try revocation(operationID, identity: trust.registration) else { return nil }
        guard entry.value.binding.phoneID == trust.enrollment.phoneID,
              entry.value.binding.enrollmentEpoch == trust.enrollment.epoch else { throw GatewayAuthorityError.wrongScope }
        guard try latestRevocation(trust: trust)?.envelope.operationID == operationID else { throw GatewayAuthorityError.superseded }
        guard entry.run == uuid(run), entry.started <= now.milliseconds, now.milliseconds < entry.deadline,
              entry.value.issuedAtUnixMillis <= wall, wall < entry.value.expiresAtUnixMillis else { throw GatewayAuthorityError.expired }
        return entry.envelope
    }

    private struct Revocation {
        let value: GatewayPhoneRevocation
        let envelope: GatewayAuthorityEnvelope
        let run: Data
        let started: UInt64
        let deadline: UInt64
    }
    private func latestRevocation(trust: GatewayAuthorityTrust) throws -> Revocation? {
        try statement("SELECT operation FROM main.gateway_revocations_v1 WHERE phone=? AND enrollment=? ORDER BY revision DESC LIMIT 1",
            [trust.enrollment.phoneID, trust.enrollment.epoch]) {
            let result = sqlite3_step($0)
            if result == SQLITE_DONE { return nil }
            guard result == SQLITE_ROW, let entry = try revocation(blob($0, 0, maximum: 16), identity: trust.registration),
                  entry.value.binding.phoneID == trust.enrollment.phoneID,
                  entry.value.binding.enrollmentEpoch == trust.enrollment.epoch else { throw GatewayAuthorityError.corruptData }
            return entry
        }
    }
    private func revocation(_ operation: Data, identity: GatewayRegistrationIdentity) throws -> Revocation? {
        guard operation.count == 16 else { throw GatewayAuthorityError.wrongScope }
        return try statement("SELECT revision,phone,enrollment,payload,signature,run,started,deadline FROM main.gateway_revocations_v1 WHERE operation=?", [operation]) {
            let result = sqlite3_step($0)
            if result == SQLITE_DONE { return nil }
            guard result == SQLITE_ROW else { throw JournalDatabaseError.storage(result) }
            let payload = try blob($0, 3, maximum: policy.payloadLimits.maxBytes), signature = try blob($0, 4, maximum: 64)
            let value: GatewayPhoneRevocation
            do { value = try GatewayPhoneRevocation.decode(payload, limits: policy.payloadLimits) }
            catch { throw GatewayAuthorityError.corruptData }
            guard try GatewayRecipientSignature.verify(signature: signature, publicKey: identity.rootPublicKey, wireVersion: 1,
                      kind: .phoneRevocation, canonicalPayload: payload, payloadLimits: policy.payloadLimits, inputLimits: policy.signingLimits),
                  GatewayStoredRecipient.revocation(value).matches(identity), value.operationID == operation,
                  try unsigned(blob($0, 0, maximum: 8)) == value.revision,
                  try blob($0, 1, maximum: 16) == value.binding.phoneID,
                  try blob($0, 2, maximum: 16) == value.binding.enrollmentEpoch else { throw GatewayAuthorityError.corruptData }
            let started = try unsigned(blob($0, 6, maximum: 8)), deadline = try unsigned(blob($0, 7, maximum: 8))
            guard deadline > started, deadline - started == value.expiresAtUnixMillis - value.issuedAtUnixMillis else { throw GatewayAuthorityError.corruptData }
            return Revocation(value: value, envelope: GatewayAuthorityEnvelope(kind: 3, operationID: operation, revision: value.revision,
                canonicalPayload: payload, signature: signature, registrationToken: nil), run: try blob($0, 5, maximum: 16), started: started, deadline: deadline)
        }
    }

    private struct Retained { let value: GatewayTokenCandidate; let consumed: Data? }
    private func candidate(_ id: Data, trust: GatewayAuthorityTrust, wall: UInt64, now: AuthorityMoment) throws -> Retained {
        guard try desiredCandidate(trust.enrollment.phoneID) == id else { throw GatewayAuthorityError.superseded }
        return try statement("""
            SELECT c.phone,c.enrollment,c.operation,c.run,c.started,c.deadline,c.consumed,d.candidate
            FROM main.gateway_root_candidates_v1 c LEFT JOIN main.gateway_desired_tokens_v1 d ON c.phone=d.phone WHERE c.candidate=?
            """, [id]) {
            guard sqlite3_step($0) == SQLITE_ROW else { throw GatewayAuthorityError.wrongScope }
            guard try blob($0, 0, maximum: 16) == trust.enrollment.phoneID,
                  try blob($0, 1, maximum: 16) == trust.enrollment.epoch else { throw GatewayAuthorityError.wrongScope }
            guard try blob($0, 7, maximum: 16) == id else { throw GatewayAuthorityError.superseded }
            guard try blob($0, 3, maximum: 16) == uuid(run), try unsigned(blob($0, 4, maximum: 8)) <= now.milliseconds,
                  try now.milliseconds < unsigned(blob($0, 5, maximum: 8)) else { throw GatewayAuthorityError.expired }
            guard let entry = try envelope(blob($0, 2, maximum: 16), identity: trust.registration), entry.kind == 1,
                  let token = entry.registrationToken else { throw GatewayAuthorityError.corruptData }
            let value = try storedCandidate(entry.canonicalPayload)
            guard value.binding.candidateID == id, value.binding.phoneID == trust.enrollment.phoneID,
                  value.binding.enrollmentEpoch == trust.enrollment.epoch, value.binding.enrollmentTag == trust.enrollment.tag,
                  value.binding.tokenDigest == Data(SHA256.hash(data: Data(token.utf8))) else { throw GatewayAuthorityError.corruptData }
            guard value.issuedAtUnixMillis <= wall, wall < value.expiresAtUnixMillis else { throw GatewayAuthorityError.expired }
            let consumed = sqlite3_column_type($0, 6) == SQLITE_NULL ? nil : try blob($0, 6, maximum: 16)
            let activation = try statement("SELECT operation FROM main.gateway_outbox_v1 WHERE candidate=? AND kind=2", [id]) { stmt -> GatewayAuthorityEnvelope? in
                let result = sqlite3_step(stmt)
                if result == SQLITE_DONE { return nil }
                guard result == SQLITE_ROW, let entry = try envelope(blob(stmt, 0, maximum: 16), identity: trust.registration),
                      sqlite3_step(stmt) == SQLITE_DONE else { throw GatewayAuthorityError.corruptData }
                let activation = try storedActivation(entry.canonicalPayload)
                guard activation.binding == value.binding, activation.revision > value.revision,
                      activation.expiresAtUnixMillis == value.expiresAtUnixMillis else { throw GatewayAuthorityError.corruptData }
                return entry
            }
            guard activation?.operationID == consumed else { throw GatewayAuthorityError.corruptData }
            return Retained(value: value, consumed: consumed)
        }
    }

    private func desiredCandidate(_ phone: Data) throws -> Data? {
        try statement("""
            SELECT d.candidate,c.candidate FROM main.gateway_desired_tokens_v1 d
            JOIN main.gateway_root_candidates_v1 c ON c.phone=d.phone
            JOIN main.gateway_outbox_v1 o ON o.operation=c.operation
            WHERE d.phone=? ORDER BY o.revision DESC LIMIT 1
            """, [phone]) {
            let result = sqlite3_step($0)
            if result == SQLITE_DONE { return nil }
            guard result == SQLITE_ROW else { throw JournalDatabaseError.storage(result) }
            let desired = try blob($0, 0, maximum: 16)
            guard desired.count == 16, try blob($0, 1, maximum: 16) == desired else { throw GatewayAuthorityError.corruptData }
            return desired
        }
    }

    private func envelope(_ operation: Data, identity: GatewayRegistrationIdentity) throws -> GatewayAuthorityEnvelope? {
        guard operation.count == 16 else { throw GatewayAuthorityError.wrongScope }
        if let revoked = try revocation(operation, identity: identity) { return revoked.envelope }
        return try statement("SELECT revision,kind,candidate,payload,signature,token FROM main.gateway_outbox_v1 WHERE operation=?", [operation]) {
            let result = sqlite3_step($0)
            if result == SQLITE_DONE { return nil }
            guard result == SQLITE_ROW else { throw JournalDatabaseError.storage(result) }
            let revision = try unsigned(blob($0, 0, maximum: 8))
            guard sqlite3_column_type($0, 1) == SQLITE_INTEGER, let kind = UInt64(exactly: sqlite3_column_int64($0, 1)) else { throw GatewayAuthorityError.corruptData }
            let payload = try blob($0, 3, maximum: policy.payloadLimits.maxBytes), signature = try blob($0, 4, maximum: 64)
            let binding: GatewayTokenBinding, storedOperation: Data, storedRevision: UInt64
            let valid: Bool
            switch kind {
            case 1:
                let value = try storedCandidate(payload)
                binding = value.binding; storedOperation = value.operationID; storedRevision = value.revision
                valid = try GatewayTokenCandidateSignature.verify(signature: signature, publicKey: identity.rootPublicKey,
                    wireVersion: 1, canonicalPayload: payload, payloadLimits: policy.payloadLimits, inputLimits: policy.signingLimits)
            case 2:
                let value = try storedActivation(payload)
                binding = value.binding; storedOperation = value.operationID; storedRevision = value.revision
                valid = try GatewayRecipientSignature.verify(signature: signature, publicKey: identity.rootPublicKey,
                    wireVersion: 1, kind: .activation, canonicalPayload: payload, payloadLimits: policy.payloadLimits, inputLimits: policy.signingLimits)
            default: throw GatewayAuthorityError.corruptData
            }
            guard valid, identity.matches(binding), storedOperation == operation, storedRevision == revision,
                  try blob($0, 2, maximum: 16) == binding.candidateID else { throw GatewayAuthorityError.corruptData }
            let token = sqlite3_column_type($0, 5) == SQLITE_NULL ? nil : try String(data: blob($0, 5, maximum: 16384), encoding: .utf8)
            guard (kind == 1) == (token != nil) else { throw GatewayAuthorityError.corruptData }
            if let token {
                guard !token.isEmpty, token.utf8.allSatisfy({ (33...126).contains($0) }) else { throw GatewayAuthorityError.corruptData }
            }
            return GatewayAuthorityEnvelope(kind: kind, operationID: operation, revision: revision, canonicalPayload: payload,
                signature: signature, registrationToken: token)
        }
    }
    private func storedCandidate(_ payload: Data) throws -> GatewayTokenCandidate {
        do { return try GatewayTokenCandidate.decode(payload, limits: policy.payloadLimits) }
        catch { throw GatewayAuthorityError.corruptData }
    }
    private func storedActivation(_ payload: Data) throws -> GatewayMappingActivation {
        do { return try GatewayMappingActivation.decode(payload, limits: policy.payloadLimits) }
        catch { throw GatewayAuthorityError.corruptData }
    }

    private func capacity() throws {
        let count = try statement("SELECT (SELECT count(*) FROM main.gateway_outbox_v1)+(SELECT count(*) FROM main.gateway_revocations_v1)", []) { stmt in
            guard sqlite3_step(stmt) == SQLITE_ROW else { throw GatewayAuthorityError.corruptData }; return sqlite3_column_int64(stmt, 0)
        }
        guard count < policy.maximumControls else { throw GatewayAuthorityError.capacityExceeded }
    }
    private func insert(_ entry: GatewayAuthorityEnvelope, candidate: Data) throws {
        try capacity()
        try statement("INSERT INTO main.gateway_outbox_v1 VALUES(?,?,\(entry.kind),?,?,?,?)",
            [entry.operationID, uint(entry.revision), candidate, entry.canonicalPayload, entry.signature, entry.registrationToken.map { Data($0.utf8) }]) { try done($0) }
    }
    private func authenticate(phone: Data, epoch: Data, trust: GatewayAuthorityTrust) throws {
        try scope(trust.registration)
        guard trust.active, trust.enrollment.active else { throw GatewayAuthorityError.unavailableEnrollment }
        guard phone == trust.enrollment.phoneID, epoch == trust.enrollment.epoch else { throw GatewayAuthorityError.wrongScope }
        guard try !revoked(trust: trust) else { throw GatewayAuthorityError.unavailableEnrollment }
    }
    private func scope(_ identity: GatewayRegistrationIdentity) throws {
        guard sqlite3_get_autocommit(db) == 0 else { throw JournalDatabaseError.expiredTransaction }
        guard identity.macID == mac, identity.accountID == account else { throw GatewayAuthorityError.wrongScope }
    }
    private func clock(_ now: AuthorityMoment) throws {
        guard now.epoch == policy.clockEpoch, lastMoment.map({ now.milliseconds >= $0 }) ?? true else { throw GatewayAuthorityError.invalidClock }
        lastMoment = now.milliseconds
    }
    private func requireHead(_ expected: UInt64, identity: GatewayRegistrationIdentity) throws {
        guard expected < UInt64.max, try head(identity) == expected else { throw GatewayAuthorityError.headMismatch }
    }
    private func advance(from: UInt64, to: UInt64) throws {
        try statement("UPDATE main.gateway_authority_v1 SET head=? WHERE id=1 AND head=?", [uint(to), uint(from)]) {
            try done($0); guard sqlite3_changes(db) == 1 else { throw GatewayAuthorityError.headMismatch }
        }
    }
    private func statement<T>(_ sql: String, _ values: [Data?], _ body: (OpaquePointer) throws -> T) throws -> T {
        var stmt: OpaquePointer?
        let result = sqlite3_prepare_v2(db, sql, -1, &stmt, nil)
        guard result == SQLITE_OK, let stmt else { throw JournalDatabaseError.storage(result) }
        defer { sqlite3_finalize(stmt) }
        for (index, value) in values.enumerated() {
            let result: Int32
            if let value { result = value.withUnsafeBytes { sqlite3_bind_blob(stmt, Int32(index + 1), $0.baseAddress, Int32($0.count), unsafeBitCast(-1, to: sqlite3_destructor_type.self)) } }
            else { result = sqlite3_bind_null(stmt, Int32(index + 1)) }
            guard result == SQLITE_OK else { throw JournalDatabaseError.storage(result) }
        }
        return try body(stmt)
    }
    private func done(_ stmt: OpaquePointer) throws { guard sqlite3_step(stmt) == SQLITE_DONE else { throw JournalDatabaseError.storage(sqlite3_errcode(db)) } }
    private func blob(_ stmt: OpaquePointer, _ index: Int32, maximum: Int) throws -> Data {
        let count = Int(sqlite3_column_bytes(stmt, index))
        guard sqlite3_column_type(stmt, index) == SQLITE_BLOB, count > 0, count <= maximum,
              let bytes = sqlite3_column_blob(stmt, index) else { throw GatewayAuthorityError.corruptData }
        return Data(bytes: bytes, count: count)
    }
    private func uint(_ value: UInt64) -> Data { withUnsafeBytes(of: value.bigEndian) { Data($0) } }
    private func unsigned(_ value: Data) throws -> UInt64 {
        guard value.count == 8 else { throw GatewayAuthorityError.corruptData }
        return value.reduce(0) { ($0 << 8) | UInt64($1) }
    }
    private func uuid(_ value: UUID) -> Data { var value = value.uuid; return withUnsafeBytes(of: &value) { Data($0) } }
}
