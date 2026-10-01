import CryptoKit
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class GatewayCandidateVerifierTests: XCTestCase {
    private let key = P256.Signing.PrivateKey()
    private let token = "synthetic-registration-token"
    private let clockEpoch = UUID()
    private var limits: CBORLimits { get throws { try CBORLimits(maxBytes: 2048, maxDepth: 8, maxItems: 128) } }
    private func fields() -> [Data] {
        var result = (0..<11).map { index in
            Data(repeating: UInt8(index + 1), count: index < 8 ? 16 : 32)
        }
        result[8] = Data(SHA256.hash(data: Data(token.utf8)))
        return result
    }
    private func binding(_ fields: [Data]? = nil) throws -> GatewayTokenBinding {
        let f = fields ?? self.fields()
        return try GatewayTokenBinding(ownerID: f[0], macID: f[1], accountID: f[2], gatewayID: f[3], lifecycleEpoch: f[4],
            phoneID: f[5], enrollmentEpoch: f[6], candidateID: f[7], tokenDigest: f[8], challenge: f[9], enrollmentTag: f[10])
    }
    private func trust(active: Bool = true, enrollmentActive: Bool = true, revision: UInt64 = 4,
                       rootKey: Data? = nil, fields: [Data]? = nil) throws -> GatewayCandidateTrust {
        let f = fields ?? self.fields()
        return try GatewayCandidateTrust(ownerID: f[0], macID: f[1], accountID: f[2], gatewayID: f[3], lifecycleEpoch: f[4],
            rootPublicKey: rootKey ?? key.publicKey.x963Representation, active: active, revision: UUID(), appliedControlRevision: revision,
            enrollment: GatewayPhoneEnrollment(phoneID: f[5], epoch: f[6], tag: f[10], active: enrollmentActive))
    }
    private func candidate(fields: [Data]? = nil, revision: UInt64 = 5, issued: UInt64 = 1000, expires: UInt64 = 61000) throws -> GatewayTokenCandidate {
        try GatewayTokenCandidate(binding: binding(fields), revision: revision, operationID: Data(repeating: 22, count: 16),
            issuedAtUnixMillis: issued, expiresAtUnixMillis: expires)
    }
    private func verify(_ candidate: GatewayTokenCandidate? = nil, trust: GatewayCandidateTrust? = nil,
                        token: String? = nil, wall: UInt64 = 1000, monotonic: UInt64 = 500, maximum: UInt64 = 60000,
                        signature: Data? = nil, wire: UInt64 = 1) throws -> VerifiedGatewayCandidate {
        let candidate = try candidate ?? self.candidate(), payload = try candidate.encode(limits: limits)
        let input = try GatewayTokenCandidateSigningInput.make(wireVersion: 1, canonicalPayload: payload, payloadLimits: limits, inputLimits: limits)
        return try GatewayCandidateVerifier.verify(canonicalCandidate: payload, signature: signature ?? key.signature(for: input).rawRepresentation,
            wireVersion: wire, registrationToken: token ?? self.token, trust: trust ?? self.trust(), nowUnixMillis: wall,
            now: AuthorityMoment(epoch: clockEpoch, milliseconds: monotonic), maximumLifetimeMillis: maximum, payloadLimits: limits, signingLimits: limits)
    }
    private func fails(_ expected: GatewayCandidateVerificationError, _ action: () throws -> Any, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try action(), file: file, line: line) { XCTAssertEqual($0 as? GatewayCandidateVerificationError, expected, file: file, line: line) }
    }

    func testEvidenceRetainsExactCandidateTokenAndTrustedSnapshot() throws {
        let candidate = try candidate(), trust = try trust()
        let result = try verify(candidate, trust: trust, wall: 2000)
        XCTAssertEqual(result.candidate, candidate)
        XCTAssertEqual(result.payloadDigest, Data(SHA256.hash(data: try candidate.encode(limits: limits))))
        XCTAssertEqual(result.trustRevision, trust.revision)
        XCTAssertEqual(result.priorControlRevision, 4)
        XCTAssertEqual(result.admittedAt, AuthorityMoment(epoch: clockEpoch, milliseconds: 500))
        XCTAssertEqual(result.deadlineMilliseconds, 59500)
        XCTAssertEqual(result.registrationToken, token)
        XCTAssertEqual(String(reflecting: result), "VerifiedGatewayCandidate(redacted)")
        XCTAssertEqual(String(describing: result), "VerifiedGatewayCandidate(redacted)")
    }

    func testEveryGatewayIdentityMustMatchEvenWithAValidSignature() throws {
        for i in 0...4 {
            var f = fields(); f[i][0] ^= 1
            fails(.wrongGateway) { try verify(candidate(fields: f)) }
            fails(.wrongGateway) { try verify(trust: trust(fields: f)) }
        }
        fails(.unavailableGateway) { try verify(trust: trust(active: false)) }
    }

    func testPhoneEpochAndTagMustMatchCurrentActiveEnrollment() throws {
        for i in [5, 6, 10] {
            var f = fields(); f[i][0] ^= 1
            fails(.unavailableEnrollment) { try verify(candidate(fields: f)) }
            fails(.unavailableEnrollment) { try verify(trust: trust(fields: f)) }
        }
        fails(.unavailableEnrollment) { try verify(trust: trust(enrollmentActive: false)) }
    }

    func testControlRevisionMustAdvanceWithoutWrapping() throws {
        fails(.staleRevision) { try verify(candidate(revision: 3)) }
        fails(.staleRevision) { try verify(candidate(revision: 4)) }
        fails(.staleRevision) { try verify(candidate(revision: .max), trust: trust(revision: .max)) }
        XCTAssertEqual(try verify(candidate(revision: .max), trust: trust(revision: .max - 1)).candidate.revision, .max)
    }

    func testSignaturesRequirePinnedRootAndCandidateDomain() throws {
        fails(.invalidSignature) { try verify(trust: trust(rootKey: P256.Signing.PrivateKey().publicKey.x963Representation)) }
        fails(.invalidSignature) { try verify(signature: Data(repeating: 0, count: 64)) }
        fails(.invalidSignature) { try verify(signature: Data()) }
        let payload = try candidate().encode(limits: limits)
        let unrelatedInput = try DeterministicCBOR.encode(.map([0: .text("dev.remozio.approval"), 1: .unsigned(1),
            2: .unsigned(1), 3: .unsigned(1), 4: .bytes(payload)]), limits: limits)
        fails(.invalidSignature) { try verify(signature: key.signature(for: unrelatedInput).rawRepresentation) }
        for wire: UInt64 in [0, 2, .max] { XCTAssertThrowsError(try verify(wire: wire)) }
    }

    func testExactTokenDigestAndProviderTokenBounds() throws {
        fails(.wrongToken) { try verify(token: token + "x") }
        var f = fields(); f[8][0] ^= 1
        fails(.wrongToken) { try verify(candidate(fields: f)) }
        for invalid in ["", "space token", "line\nfeed", "é", "\u{7f}", String(repeating: "a", count: 16385)] {
            fails(.invalidToken) { try verify(token: invalid) }
        }
        let longest = String(repeating: "a", count: 16384)
        f[8] = Data(SHA256.hash(data: Data(longest.utf8)))
        XCTAssertEqual(try verify(candidate(fields: f), token: longest).registrationToken, longest)
    }

    func testWallTimeAndLifetimeBoundaries() throws {
        fails(.futureIssue) { try verify(wall: 999) }
        XCTAssertNoThrow(try verify(wall: 1000))
        XCTAssertEqual(try verify(wall: 61000 - 1).deadlineMilliseconds, 501)
        fails(.expired) { try verify(wall: 61000) }
        fails(.expired) { try verify(wall: .max) }
        fails(.excessiveLifetime) { try verify(maximum: 59999) }
        fails(.invalidPolicy) { try verify(maximum: 0) }
        let high = try candidate(issued: .max - 60000, expires: .max)
        XCTAssertEqual(try verify(high, wall: .max - 60000).deadlineMilliseconds, 60500)
        fails(.expired) { try verify(high, wall: .max) }
        let full = try candidate(issued: 0, expires: .max)
        fails(.excessiveLifetime) { try verify(full, wall: .max - 1) }
    }

    func testRemainingLifetimeBecomesFixedMonotonicDeadlineWithoutOverflow() throws {
        fails(.invalidClock) { try verify(monotonic: .max - 59999) }
        XCTAssertEqual(try verify(monotonic: .max - 60000).deadlineMilliseconds, .max)
        let evidence = try verify(wall: 60000, monotonic: 100)
        // Retained evidence contains no mutable wall clock or duration that a consumer can restart.
        XCTAssertEqual(evidence.deadlineMilliseconds, 1100)
        XCTAssertEqual(evidence.admittedAt.epoch, clockEpoch)
    }

    func testTrustedConstructorsRejectInvalidIdentitiesAndKeys() throws {
        for i in [0, 1, 2, 3, 4, 5, 6, 10] {
            var f = fields(); f[i] = Data()
            fails(.invalidTrustedState) { try trust(fields: f) }
        }
        for malformed in [Data(), Data(repeating: 4, count: 65), Data(repeating: 0, count: 33)] {
            fails(.invalidTrustedState) { try trust(rootKey: malformed) }
        }
    }

    func testMalformedPayloadAndExplicitLimitsFailBeforeEvidence() throws {
        let candidate = try candidate(), payload = try candidate.encode(limits: limits)
        let input = try GatewayTokenCandidateSigningInput.make(wireVersion: 1, canonicalPayload: payload, payloadLimits: limits, inputLimits: limits)
        let signature = try key.signature(for: input).rawRepresentation
        func check(_ bytes: Data, payloadLimits: CBORLimits, signingLimits: CBORLimits) throws -> VerifiedGatewayCandidate {
            try GatewayCandidateVerifier.verify(canonicalCandidate: bytes, signature: signature, wireVersion: 1,
                registrationToken: token, trust: trust(), nowUnixMillis: 1000, now: AuthorityMoment(epoch: clockEpoch, milliseconds: 0),
                maximumLifetimeMillis: 60000, payloadLimits: payloadLimits, signingLimits: signingLimits)
        }
        XCTAssertThrowsError(try check(payload + Data([0]), payloadLimits: limits, signingLimits: limits))
        XCTAssertThrowsError(try check(payload, payloadLimits: CBORLimits(maxBytes: payload.count - 1, maxDepth: 8, maxItems: 128), signingLimits: limits))
        XCTAssertThrowsError(try check(payload, payloadLimits: limits, signingLimits: CBORLimits(maxBytes: input.count - 1, maxDepth: 8, maxItems: 128)))
    }
}
