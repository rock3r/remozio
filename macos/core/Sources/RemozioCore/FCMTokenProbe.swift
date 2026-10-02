import Foundation
import RemozioProtocol

/// A bounded provider message, not a dispatch permit. The coordinator must first commit an attempt and recheck current trust.
public struct FCMTokenProbe: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    let registrationToken: String
    public let payload: PushTokenChallenge
    public let ttlSeconds: UInt32
    public init(candidate: VerifiedGatewayCandidate, nowUnixMillis: UInt64, now: AuthorityMoment, maximumTTLSeconds: UInt32) throws {
        guard maximumTTLSeconds <= 2_419_200 else { throw FCMError.invalidConfiguration }
        guard now.epoch == candidate.admittedAt.epoch, now.milliseconds >= candidate.admittedAt.milliseconds else {
            throw GatewayCandidateVerificationError.invalidClock
        }
        guard now.milliseconds < candidate.deadlineMilliseconds,
              nowUnixMillis >= candidate.candidate.issuedAtUnixMillis, nowUnixMillis < candidate.candidate.expiresAtUnixMillis else {
            throw GatewayCandidateVerificationError.expired
        }
        let remaining = min(candidate.deadlineMilliseconds - now.milliseconds, candidate.candidate.expiresAtUnixMillis - nowUnixMillis)
        // Round down; TTL zero asks the provider to deliver immediately or discard the probe.
        self.ttlSeconds = UInt32(min(UInt64(maximumTTLSeconds), remaining / 1000))
        let binding = candidate.candidate.binding
        self.payload = try PushTokenChallenge(candidateID: binding.candidateID, challenge: binding.challenge, enrollmentTag: binding.enrollmentTag)
        self.registrationToken = candidate.registrationToken
    }
    public var description: String { "FCMTokenProbe(redacted)" }
    public var debugDescription: String { description }
}
