import Foundation
import RemozioProtocol

/// A bounded provider message, not a dispatch permit. The coordinator must first commit an attempt and recheck current trust.
public struct FCMTokenProbe: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    let registrationToken: String
    public let payload: PushTokenChallenge
    public let ttlSeconds: UInt32
    public init(candidate: VerifiedGatewayCandidate, nowUnixMillis: UInt64, now: AuthorityMoment, maximumTTLSeconds: UInt32) throws {
        try self.init(candidate: candidate.candidate, registrationToken: candidate.registrationToken,
            admittedAt: candidate.admittedAt, deadlineMilliseconds: candidate.deadlineMilliseconds,
            nowUnixMillis: nowUnixMillis, now: now, maximumTTLSeconds: maximumTTLSeconds)
    }
    init(candidate: GatewayTokenCandidate, registrationToken: String, admittedAt: AuthorityMoment, deadlineMilliseconds: UInt64,
         nowUnixMillis: UInt64, now: AuthorityMoment, maximumTTLSeconds: UInt32) throws {
        guard maximumTTLSeconds <= 2_419_200 else { throw FCMError.invalidConfiguration }
        guard now.epoch == admittedAt.epoch, now.milliseconds >= admittedAt.milliseconds else {
            throw GatewayCandidateVerificationError.invalidClock
        }
        guard now.milliseconds < deadlineMilliseconds,
              nowUnixMillis >= candidate.issuedAtUnixMillis, nowUnixMillis < candidate.expiresAtUnixMillis else {
            throw GatewayCandidateVerificationError.expired
        }
        let remaining = min(deadlineMilliseconds - now.milliseconds, candidate.expiresAtUnixMillis - nowUnixMillis)
        // Round down; TTL zero asks the provider to deliver immediately or discard the probe.
        self.ttlSeconds = UInt32(min(UInt64(maximumTTLSeconds), remaining / 1000))
        let binding = candidate.binding
        self.payload = try PushTokenChallenge(candidateID: binding.candidateID, challenge: binding.challenge, enrollmentTag: binding.enrollmentTag)
        self.registrationToken = registrationToken
    }
    public var description: String { "FCMTokenProbe(redacted)" }
    public var debugDescription: String { description }
}
