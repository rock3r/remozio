import Foundation

public enum RequestStatusReason: UInt64, CaseIterable, Sendable {
    case none = 0, verifiedResult = 1, outcomeUnavailable = 2, declined = 3
    case userCancelled = 4, authorizationExpired = 5, targetTimedOut = 6
    case targetDisappeared = 7, authorityRestarted = 8, noDispatchProved = 9

    fileprivate func permits(_ phase: RequestPhase) -> Bool {
        switch self {
        case .none: !phase.isTerminal
        case .verifiedResult: phase == .succeeded || phase == .failed
        case .outcomeUnavailable: phase == .unknown
        case .declined: phase == .declined
        case .targetDisappeared: phase == .unknown || phase == .cancelled
        case .userCancelled, .noDispatchProved: phase == .cancelled
        case .authorizationExpired, .targetTimedOut: phase == .expired
        case .authorityRestarted: phase == .cancelled || phase == .unknown
        }
    }
}

public enum RequestStatusError: Error, Equatable {
    case invalidFields, unsupportedSchema, invalidBytes, invalidState, invalidTiming
}

/// A status claim. The receiver must check authentication, freshness, retained bindings, and transitions.
public struct RequestStatusPayload: Equatable, Sendable {
    public let macID: Data
    public let accountID: Data
    public let requestID: Data
    public let requestDigest: Data
    public let challenge: Data
    public let revision: UInt64
    public let phase: RequestPhase
    public let reason: RequestStatusReason
    public let observationID: Data
    public let observedAgeMs: UInt64
    public let authorizationRemainingMs: UInt64?
    public let estimatedLifetimeMs: UInt64?
    public let lateObservation: Bool
    public let terminalAgeMs: UInt64?
    public let decisionPhoneID: Data?

    public init(macID: Data, accountID: Data, requestID: Data, requestDigest: Data, challenge: Data,
                revision: UInt64, phase: RequestPhase, reason: RequestStatusReason, observationID: Data,
                observedAgeMs: UInt64, authorizationRemainingMs: UInt64?, estimatedLifetimeMs: UInt64?,
                lateObservation: Bool, terminalAgeMs: UInt64?, decisionPhoneID: Data?) throws {
        guard [macID, accountID, requestID, observationID].allSatisfy({ $0.count == 16 }),
              requestDigest.count == 32, challenge.count == 32,
              decisionPhoneID == nil || decisionPhoneID?.count == 16 else { throw RequestStatusError.invalidBytes }
        let pending = phase == .queued || phase == .presented
        guard revision > 0, reason.permits(phase), !pending || decisionPhoneID == nil,
              !(phase == .unknown && reason == .targetDisappeared) || decisionPhoneID == nil else {
            throw RequestStatusError.invalidState
        }
        guard pending == (authorizationRemainingMs != nil),
              estimatedLifetimeMs == nil || estimatedLifetimeMs! > 0,
              phase.isTerminal == (terminalAgeMs != nil),
              terminalAgeMs == nil || terminalAgeMs! <= observedAgeMs else { throw RequestStatusError.invalidTiming }
        self.macID = macID
        self.accountID = accountID
        self.requestID = requestID
        self.requestDigest = requestDigest
        self.challenge = challenge
        self.revision = revision
        self.phase = phase
        self.reason = reason
        self.observationID = observationID
        self.observedAgeMs = observedAgeMs
        self.authorizationRemainingMs = authorizationRemainingMs
        self.estimatedLifetimeMs = estimatedLifetimeMs
        self.lateObservation = lateObservation
        self.terminalAgeMs = terminalAgeMs
        self.decisionPhoneID = decisionPhoneID
    }

    public func encode(limits: CBORLimits) throws -> Data {
        try DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(macID), 2: .bytes(accountID), 3: .bytes(requestID),
            4: .bytes(requestDigest), 5: .bytes(challenge), 6: .unsigned(revision),
            7: .unsigned(Self.phaseTag(phase)), 8: .unsigned(reason.rawValue), 9: .bytes(observationID),
            10: .unsigned(observedAgeMs), 11: Self.number(authorizationRemainingMs),
            12: Self.number(estimatedLifetimeMs), 13: .boolean(lateObservation),
            14: Self.number(terminalAgeMs), 15: decisionPhoneID.map(CBORValue.bytes) ?? .null,
        ]), limits: limits)
    }

    public static func decode(_ bytes: Data, limits: CBORLimits) throws -> RequestStatusPayload {
        guard case let .map(fields) = try DeterministicCBOR.decode(bytes, limits: limits),
              Set(fields.keys) == Set(0...UInt64(15)) else { throw RequestStatusError.invalidFields }
        guard fields[0] == .unsigned(1) else { throw RequestStatusError.unsupportedSchema }
        func data(_ key: UInt64) throws -> Data {
            guard case let .bytes(value) = fields[key] else { throw RequestStatusError.invalidBytes }
            return value
        }
        func uint(_ key: UInt64) throws -> UInt64 {
            guard case let .unsigned(value) = fields[key] else { throw RequestStatusError.invalidFields }
            return value
        }
        func optional(_ key: UInt64) throws -> UInt64? { try fields[key] == .null ? nil : uint(key) }
        guard let reason = RequestStatusReason(rawValue: try uint(8)) else { throw RequestStatusError.invalidState }
        guard case let .boolean(late) = fields[13] else { throw RequestStatusError.invalidFields }
        return try RequestStatusPayload(macID: data(1), accountID: data(2), requestID: data(3),
            requestDigest: data(4), challenge: data(5), revision: uint(6), phase: phase(uint(7)),
            reason: reason, observationID: data(9), observedAgeMs: uint(10), authorizationRemainingMs: optional(11),
            estimatedLifetimeMs: optional(12), lateObservation: late, terminalAgeMs: optional(14),
            decisionPhoneID: fields[15] == .null ? nil : data(15))
    }

    private static func number(_ value: UInt64?) -> CBORValue { value.map(CBORValue.unsigned) ?? .null }
    private static func phaseTag(_ phase: RequestPhase) -> UInt64 {
        switch phase {
        case .queued: 0; case .presented: 1; case .authorized: 2; case .executing: 3
        case .succeeded: 4; case .failed: 5; case .unknown: 6; case .declined: 7; case .cancelled: 8; case .expired: 9
        }
    }
    private static func phase(_ tag: UInt64) throws -> RequestPhase {
        switch tag {
        case 0: .queued; case 1: .presented; case 2: .authorized; case 3: .executing
        case 4: .succeeded; case 5: .failed; case 6: .unknown; case 7: .declined; case 8: .cancelled; case 9: .expired
        default: throw RequestStatusError.invalidState
        }
    }
}
