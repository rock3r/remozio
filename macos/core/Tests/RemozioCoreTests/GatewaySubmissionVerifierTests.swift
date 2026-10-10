import CryptoKit
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class GatewaySubmissionVerifierTests: XCTestCase {
    private let root = P256.Signing.PrivateKey(), credential = P256.Signing.PrivateKey(), epoch = UUID(), generation = UUID()
    private var limits: CBORLimits { get throws { try CBORLimits(maxBytes: 2048, maxDepth: 8, maxItems: 128) } }
    private func id(_ value: UInt8) -> Data { Data(repeating: value, count: 16) }
    private func registration(changed: Int? = nil, key: Data? = nil) throws -> GatewayRegistrationIdentity {
        let fields = (0..<5).map { id($0 == changed ? 90 : UInt8($0+1)) }
        return try GatewayRegistrationIdentity(ownerID: fields[0], macID: fields[1], accountID: fields[2], gatewayID: fields[3],
            lifecycleEpoch: fields[4], rootPublicKey: key ?? root.publicKey.x963Representation)
    }
    private func control(kind: GatewaySubmissionKind = .rotation, issued: UInt64 = 900, expires: UInt64 = 1100,
                         key: Data? = nil) throws -> GatewaySubmissionControl {
        let b = try GatewaySubmissionBinding(ownerID: id(1), macID: id(2), accountID: id(3), gatewayID: id(4), lifecycleEpoch: id(5))
        return try GatewaySubmissionControl(kind: kind, binding: b, revision: 7, operationID: id(6), issuedAtUnixMillis: issued,
            expiresAtUnixMillis: expires, credentialID: id(7), publicKey: kind == .rotation ? (key ?? credential.publicKey.x963Representation) : nil)
    }
    private func verify(_ value: GatewaySubmissionControl, active: Bool = true, head: UInt64 = 6, changed: Int? = nil,
                        key: Data? = nil, signer: P256.Signing.PrivateKey? = nil, maximum: UInt64 = 1000,
                        wall: UInt64 = 1000, milliseconds: UInt64 = 100) throws -> VerifiedGatewaySubmissionControl {
        let bytes = try value.encode(limits: limits), input = try GatewaySubmissionSigningInput.make(wireVersion: 1, kind: value.kind,
            canonicalPayload: bytes, payloadLimits: limits, inputLimits: limits)
        return try GatewaySubmissionVerifier.verify(canonicalPayload: bytes, signature: (signer ?? root).signature(for: input).rawRepresentation,
            wireVersion: 1, trust: GatewaySubmissionTrust(registration: registration(changed: changed, key: key), active: active,
                revision: generation, appliedControlRevision: head), nowUnixMillis: wall, now: AuthorityMoment(epoch: epoch, milliseconds: milliseconds),
            maximumLifetimeMillis: maximum, payloadLimits: limits, signingLimits: limits)
    }
    private func fails(_ expected: GatewaySubmissionVerificationError, _ operation: () throws -> Void) {
        XCTAssertThrowsError(try operation()) { XCTAssertEqual($0 as? GatewaySubmissionVerificationError, expected) }
    }
    func testBothControlsCaptureCurrentTrustAndRemainingOriginalLifetime() throws {
        for kind in [GatewaySubmissionKind.rotation, .revocation] {
            let value = try control(kind: kind), verified = try verify(value)
            XCTAssertEqual(verified.control, value); XCTAssertEqual(verified.trustRevision, generation)
            XCTAssertEqual(verified.priorControlRevision, 6); XCTAssertEqual(verified.admittedAt.epoch, epoch)
            XCTAssertEqual(verified.admittedAt.milliseconds, 100); XCTAssertEqual(verified.deadlineMilliseconds, 200)
            XCTAssertEqual(verified.payloadDigest, Data(SHA256.hash(data: try value.encode(limits: limits))))
            XCTAssertEqual(String(reflecting: verified), "VerifiedGatewaySubmissionControl(redacted)")
        }
    }
    func testRegistrationScopeAndProtectedRootKeyCannotBeReplacedByControlOrCredential() throws {
        let value = try control()
        for i in 0..<5 { fails(.wrongGateway) { _ = try verify(value, changed: i) } }
        fails(.invalidSignature) { _ = try verify(value, signer: credential) }
        fails(.invalidSignature) { _ = try verify(value, key: credential.publicKey.x963Representation) }
        fails(.unavailableGateway) { _ = try verify(value, active: false) }
    }
    func testFreshnessRevisionAndClockOverflowFailBeforeApplication() throws {
        let value = try control()
        fails(.staleRevision) { _ = try verify(value, head: 7) }
        fails(.staleRevision) { _ = try verify(value, head: .max) }
        fails(.futureIssue) { _ = try verify(value, wall: 899) }
        fails(.expired) { _ = try verify(value, wall: 1100) }
        fails(.excessiveLifetime) { _ = try verify(value, maximum: 199) }
        fails(.invalidPolicy) { _ = try verify(value, maximum: 0) }
        fails(.invalidClock) { _ = try verify(value, milliseconds: .max) }
        XCTAssertEqual(try verify(value, maximum: 200).deadlineMilliseconds, 200)
    }
    func testSignedInvalidCurvePointDoesNotBecomeAUsableCredential() throws {
        var point = Data(repeating: 0, count: 65); point[0] = 4
        let value = try control(key: point)
        XCTAssertEqual(try GatewaySubmissionControl.decode(value.encode(limits: limits), limits: limits).publicKey, point)
        fails(.invalidCredential) { _ = try verify(value) }
    }
    func testHistoricalAuthenticationDoesNotRefreshExpiredControl() throws {
        let value = try control(), bytes = try value.encode(limits: limits)
        let input = try GatewaySubmissionSigningInput.make(wireVersion: 1, kind: value.kind, canonicalPayload: bytes,
            payloadLimits: limits, inputLimits: limits)
        XCTAssertEqual(try GatewaySubmissionVerifier.authenticate(canonicalPayload: bytes, signature: root.signature(for: input).rawRepresentation,
            wireVersion: 1, registration: registration(), payloadLimits: limits, signingLimits: limits), value)
        fails(.expired) { _ = try verify(value, wall: 1100) }
    }
}
