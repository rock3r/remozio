import Foundation

public enum PushDataError: Error, Equatable { case invalidFields, invalidBytes, invalidEncoding }

/// Provider data is an untrusted routing hint. It never authorizes an approval or enrollment change.
public struct PushWake: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let identifier: Data
    public let enrollmentTag: Data
    public init(identifier: Data, enrollmentTag: Data) throws {
        guard identifier.count == 32, enrollmentTag.count == 32 else { throw PushDataError.invalidBytes }
        self.identifier = identifier; self.enrollmentTag = enrollmentTag
    }
    public var description: String { "PushWake(redacted)" }
    public var debugDescription: String { description }
}

/// The challenge reaches the phone only through the provider. Match it with retained registration metadata over an authenticated channel.
public struct PushTokenChallenge: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let candidateID: Data
    public let challenge: Data
    public let enrollmentTag: Data
    public init(candidateID: Data, challenge: Data, enrollmentTag: Data) throws {
        guard candidateID.count == 16, challenge.count == 32, enrollmentTag.count == 32 else { throw PushDataError.invalidBytes }
        self.candidateID = candidateID; self.challenge = challenge; self.enrollmentTag = enrollmentTag
    }
    public var description: String { "PushTokenChallenge(redacted)" }
    public var debugDescription: String { description }
}

public enum PushData: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    case wake(PushWake)
    case tokenChallenge(PushTokenChallenge)
    public var description: String { "PushData(redacted)" }
    public var debugDescription: String { description }
    public func encode() -> [String: String] {
        switch self {
        case .wake(let v): return ["wake_v1": v.identifier.base64EncodedString(), "enrollment_v1": v.enrollmentTag.base64EncodedString()]
        case .tokenChallenge(let v): return ["candidate_v1": v.candidateID.base64EncodedString(),
            "token_challenge_v1": v.challenge.base64EncodedString(), "enrollment_v1": v.enrollmentTag.base64EncodedString()]
        }
    }
    public static func decode(_ data: [String: String]) throws -> PushData {
        guard (2...3).contains(data.count) else { throw PushDataError.invalidFields }
        let keys = Set(data.keys)
        if keys == ["wake_v1", "enrollment_v1"] {
            return try .wake(PushWake(identifier: bytes(data["wake_v1"]!, count: 32), enrollmentTag: bytes(data["enrollment_v1"]!, count: 32)))
        }
        if keys == ["candidate_v1", "token_challenge_v1", "enrollment_v1"] {
            return try .tokenChallenge(PushTokenChallenge(candidateID: bytes(data["candidate_v1"]!, count: 16),
                challenge: bytes(data["token_challenge_v1"]!, count: 32), enrollmentTag: bytes(data["enrollment_v1"]!, count: 32)))
        }
        throw PushDataError.invalidFields
    }
    private static func bytes(_ value: String, count: Int) throws -> Data {
        guard value.utf8.count == ((count + 2) / 3) * 4, let bytes = Data(base64Encoded: value), bytes.count == count,
              bytes.base64EncodedString() == value else { throw PushDataError.invalidEncoding }
        return bytes
    }
}
