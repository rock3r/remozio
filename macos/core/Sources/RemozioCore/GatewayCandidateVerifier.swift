import CryptoKit
import Foundation
import RemozioProtocol

public enum GatewayCandidateVerificationError: Error, Equatable {
    case invalidTrustedState, invalidPolicy, unavailableGateway, wrongGateway, unavailableEnrollment
    case staleRevision, invalidSignature, invalidToken, wrongToken, futureIssue, expired, excessiveLifetime, invalidClock
}

/// Read from retained enrollment state. Incoming candidate fields cannot establish or replace this trust.
public struct GatewayPhoneEnrollment: Sendable {
    public let phoneID: Data
    public let epoch: Data
    public let tag: Data
    public let active: Bool
    public init(phoneID: Data, epoch: Data, tag: Data, active: Bool) throws {
        guard phoneID.count == 16, epoch.count == 16, tag.count == 32 else {
            throw GatewayCandidateVerificationError.invalidTrustedState
        }
        self.phoneID = phoneID; self.epoch = epoch; self.tag = tag; self.active = active
    }
}

/// One consistent gateway snapshot from protected setup and retained control history, never from a request.
public struct GatewayCandidateTrust: Sendable {
    public let ownerID: Data
    public let macID: Data
    public let accountID: Data
    public let gatewayID: Data
    public let lifecycleEpoch: Data
    public let rootPublicKey: Data
    public let active: Bool
    public let revision: UUID
    public let appliedControlRevision: UInt64
    public let enrollment: GatewayPhoneEnrollment
    public init(ownerID: Data, macID: Data, accountID: Data, gatewayID: Data, lifecycleEpoch: Data,
                rootPublicKey: Data, active: Bool, revision: UUID, appliedControlRevision: UInt64,
                enrollment: GatewayPhoneEnrollment) throws {
        guard [ownerID, macID, accountID, gatewayID, lifecycleEpoch].allSatisfy({ $0.count == 16 }),
              rootPublicKey.count == 65, rootPublicKey.first == 4,
              (try? P256.Signing.PublicKey(x963Representation: rootPublicKey)) != nil else {
            throw GatewayCandidateVerificationError.invalidTrustedState
        }
        self.ownerID = ownerID; self.macID = macID; self.accountID = accountID; self.gatewayID = gatewayID
        self.lifecycleEpoch = lifecycleEpoch; self.rootPublicKey = rootPublicKey; self.active = active
        self.revision = revision; self.appliedControlRevision = appliedControlRevision; self.enrollment = enrollment
    }
}

/// Local evidence only. Durable admission must recheck trust, replay state, quotas and the monotonic deadline.
public struct VerifiedGatewayCandidate: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let candidate: GatewayTokenCandidate
    public let payloadDigest: Data
    public let trustRevision: UUID
    public let priorControlRevision: UInt64
    public let admittedAt: AuthorityMoment
    public let deadlineMilliseconds: UInt64
    // The dedicated gateway stores this in protected operational state, never in audit records.
    let registrationToken: String
    fileprivate init(candidate: GatewayTokenCandidate, payloadDigest: Data, trust: GatewayCandidateTrust,
                     admittedAt: AuthorityMoment, deadlineMilliseconds: UInt64, registrationToken: String) {
        self.candidate = candidate; self.payloadDigest = payloadDigest; self.trustRevision = trust.revision
        self.priorControlRevision = trust.appliedControlRevision; self.admittedAt = admittedAt
        self.deadlineMilliseconds = deadlineMilliseconds; self.registrationToken = registrationToken
    }
    public var description: String { "VerifiedGatewayCandidate(redacted)" }
    public var debugDescription: String { description }
}

public enum GatewayCandidateVerifier {
    public static func verify(canonicalCandidate: Data, signature: Data, wireVersion: UInt64,
                              registrationToken: String, trust: GatewayCandidateTrust,
                              nowUnixMillis: UInt64, now: AuthorityMoment, maximumLifetimeMillis: UInt64,
                              payloadLimits: CBORLimits, signingLimits: CBORLimits) throws -> VerifiedGatewayCandidate {
        guard maximumLifetimeMillis > 0 else { throw GatewayCandidateVerificationError.invalidPolicy }
        let candidate = try GatewayTokenCandidate.decode(canonicalCandidate, limits: payloadLimits)
        guard trust.active else { throw GatewayCandidateVerificationError.unavailableGateway }
        let binding = candidate.binding
        guard binding.ownerID == trust.ownerID, binding.macID == trust.macID, binding.accountID == trust.accountID,
              binding.gatewayID == trust.gatewayID, binding.lifecycleEpoch == trust.lifecycleEpoch else {
            throw GatewayCandidateVerificationError.wrongGateway
        }
        let enrollment = trust.enrollment
        guard enrollment.active, binding.phoneID == enrollment.phoneID, binding.enrollmentEpoch == enrollment.epoch,
              binding.enrollmentTag == enrollment.tag else { throw GatewayCandidateVerificationError.unavailableEnrollment }
        guard candidate.revision > trust.appliedControlRevision else { throw GatewayCandidateVerificationError.staleRevision }
        guard try GatewayTokenCandidateSignature.verify(signature: signature, publicKey: trust.rootPublicKey,
            wireVersion: wireVersion, canonicalPayload: canonicalCandidate, payloadLimits: payloadLimits, inputLimits: signingLimits) else {
            throw GatewayCandidateVerificationError.invalidSignature
        }
        guard !registrationToken.isEmpty, registrationToken.utf8.count <= 16384,
              registrationToken.utf8.allSatisfy({ (33...126).contains($0) }) else { throw GatewayCandidateVerificationError.invalidToken }
        guard Data(SHA256.hash(data: Data(registrationToken.utf8))) == binding.tokenDigest else {
            throw GatewayCandidateVerificationError.wrongToken
        }
        guard candidate.issuedAtUnixMillis <= nowUnixMillis else { throw GatewayCandidateVerificationError.futureIssue }
        guard nowUnixMillis < candidate.expiresAtUnixMillis else { throw GatewayCandidateVerificationError.expired }
        guard candidate.expiresAtUnixMillis - candidate.issuedAtUnixMillis <= maximumLifetimeMillis else {
            throw GatewayCandidateVerificationError.excessiveLifetime
        }
        let (deadline, overflow) = now.milliseconds.addingReportingOverflow(candidate.expiresAtUnixMillis - nowUnixMillis)
        guard !overflow else { throw GatewayCandidateVerificationError.invalidClock }
        return VerifiedGatewayCandidate(candidate: candidate, payloadDigest: Data(SHA256.hash(data: canonicalCandidate)),
            trust: trust, admittedAt: now, deadlineMilliseconds: deadline, registrationToken: registrationToken)
    }
}
