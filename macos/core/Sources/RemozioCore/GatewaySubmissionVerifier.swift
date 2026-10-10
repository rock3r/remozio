import CryptoKit
import Foundation
import RemozioProtocol

public enum GatewaySubmissionVerificationError: Error, Equatable {
    case invalidPolicy, unavailableGateway, wrongGateway, staleRevision, invalidSignature, invalidCredential
    case futureIssue, expired, excessiveLifetime, invalidClock
}

/// Retained registration and control state. Incoming controls cannot establish or replace this trust.
public struct GatewaySubmissionTrust: Sendable {
    public let registration: GatewayRegistrationIdentity
    public let active: Bool
    public let revision: UUID
    public let appliedControlRevision: UInt64
    public init(registration: GatewayRegistrationIdentity, active: Bool, revision: UUID, appliedControlRevision: UInt64) {
        self.registration = registration; self.active = active; self.revision = revision
        self.appliedControlRevision = appliedControlRevision
    }
}

/// Local admission evidence. A durable transaction must still recheck trust, replay, capacity, and the original deadline.
public struct VerifiedGatewaySubmissionControl: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let control: GatewaySubmissionControl
    public let payloadDigest: Data
    public let trustRevision: UUID
    public let priorControlRevision: UInt64
    public let admittedAt: AuthorityMoment
    public let deadlineMilliseconds: UInt64
    fileprivate init(control: GatewaySubmissionControl, canonicalPayload: Data, trust: GatewaySubmissionTrust,
                     now: AuthorityMoment, deadline: UInt64) {
        self.control = control; payloadDigest = Data(SHA256.hash(data: canonicalPayload)); trustRevision = trust.revision
        priorControlRevision = trust.appliedControlRevision; admittedAt = now; deadlineMilliseconds = deadline
    }
    public var description: String { "VerifiedGatewaySubmissionControl(redacted)" }
    public var debugDescription: String { description }
}

public enum GatewaySubmissionVerifier {
    public static func verify(canonicalPayload: Data, signature: Data, wireVersion: UInt64, trust: GatewaySubmissionTrust,
                              nowUnixMillis: UInt64, now: AuthorityMoment, maximumLifetimeMillis: UInt64,
                              payloadLimits: CBORLimits, signingLimits: CBORLimits) throws -> VerifiedGatewaySubmissionControl {
        guard maximumLifetimeMillis > 0 else { throw GatewaySubmissionVerificationError.invalidPolicy }
        guard trust.active else { throw GatewaySubmissionVerificationError.unavailableGateway }
        let control = try authenticate(canonicalPayload: canonicalPayload, signature: signature, wireVersion: wireVersion,
            registration: trust.registration, payloadLimits: payloadLimits, signingLimits: signingLimits)
        guard control.revision > trust.appliedControlRevision else { throw GatewaySubmissionVerificationError.staleRevision }
        guard control.issuedAtUnixMillis <= nowUnixMillis else { throw GatewaySubmissionVerificationError.futureIssue }
        guard nowUnixMillis < control.expiresAtUnixMillis else { throw GatewaySubmissionVerificationError.expired }
        guard control.expiresAtUnixMillis - control.issuedAtUnixMillis <= maximumLifetimeMillis else {
            throw GatewaySubmissionVerificationError.excessiveLifetime
        }
        let (deadline, overflow) = now.milliseconds.addingReportingOverflow(control.expiresAtUnixMillis - nowUnixMillis)
        guard !overflow else { throw GatewaySubmissionVerificationError.invalidClock }
        return VerifiedGatewaySubmissionControl(control: control, canonicalPayload: canonicalPayload, trust: trust, now: now, deadline: deadline)
    }

    /// Historical authentication only. This grants no freshness, counter change, credential activation, or wake permission.
    static func authenticate(canonicalPayload: Data, signature: Data, wireVersion: UInt64, registration: GatewayRegistrationIdentity,
                             payloadLimits: CBORLimits, signingLimits: CBORLimits) throws -> GatewaySubmissionControl {
        let control = try GatewaySubmissionControl.decode(canonicalPayload, limits: payloadLimits), b = control.binding
        guard b.ownerID == registration.ownerID, b.macID == registration.macID, b.accountID == registration.accountID,
              b.gatewayID == registration.gatewayID, b.lifecycleEpoch == registration.lifecycleEpoch else {
            throw GatewaySubmissionVerificationError.wrongGateway
        }
        guard try GatewaySubmissionSignature.verify(signature: signature, publicKey: registration.rootPublicKey, wireVersion: wireVersion,
            kind: control.kind, canonicalPayload: canonicalPayload, payloadLimits: payloadLimits, inputLimits: signingLimits) else {
            throw GatewaySubmissionVerificationError.invalidSignature
        }
        if control.kind == .rotation {
            guard let key = control.publicKey, (try? P256.Signing.PublicKey(x963Representation: key)) != nil else {
                throw GatewaySubmissionVerificationError.invalidCredential
            }
        }
        return control
    }
}
