import Foundation

public enum RoutingStatusError: Error { case invalidMessage }
public enum RoutingStatusMode: UInt64, Sendable { case automatic = 0, present = 1, away = 2 }
public enum RoutingStatusDestination: UInt64, Sendable { case localMac = 0, phones = 1 }
public enum RoutingStatusReason: UInt64, Sendable {
    case manualPresent = 0, manualAway = 1, remoteDesktop = 2, locked = 3, displaysOff = 4
    case displaysDark = 5, idle = 6, active = 7, detectorUnavailable = 8
}
public enum RoutingStatusOutcome: UInt64, Sendable { case status = 0, challenge = 1, applied = 2, conflict = 3 }

/// Coarse authority state. Connection loss and elapsed response age still determine whether it is current.
public struct RoutingStatusState: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let mode: RoutingStatusMode
    public let revision: UInt64
    public let destination: RoutingStatusDestination
    public let reason: RoutingStatusReason
    public let detectionLimited: Bool
    public init(mode: RoutingStatusMode, revision: UInt64, destination: RoutingStatusDestination,
                reason: RoutingStatusReason, detectionLimited: Bool) throws {
        let valid: Bool
        switch mode {
        case .present: valid = destination == .localMac && reason == .manualPresent && !detectionLimited
        case .away: valid = destination == .phones && reason == .manualAway && !detectionLimited
        case .automatic:
            switch reason {
            case .manualPresent, .manualAway: valid = false
            case .remoteDesktop: valid = destination == .localMac && !detectionLimited
            case .active: valid = destination == .localMac
            case .locked, .displaysOff, .displaysDark, .idle: valid = destination == .phones
            case .detectorUnavailable: valid = detectionLimited
            }
        }
        guard valid else { throw RoutingStatusError.invalidMessage }
        self.mode = mode; self.revision = revision; self.destination = destination
        self.reason = reason; self.detectionLimited = detectionLimited
    }
    public var description: String { "RoutingStatusState(redacted)" }
    public var debugDescription: String { description }
}

/// A parsed claim. Verify its authority signature, live scope, query nonce and elapsed deadline before use.
public struct RoutingStatusResponse: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let scope: ChannelScope
    public let queryNonce: Data
    public let outcome: RoutingStatusOutcome
    public let clockEpoch: Data
    public let sampledAtMilliseconds: UInt64
    public let state: RoutingStatusState
    public let canonicalChallenge: Data?
    public let controlDigest: Data?
    public let appliedRevision: UInt64?
    public static let maximumBytes = 3072
    public static var limits: CBORLimits { get throws { try .init(maxBytes: maximumBytes, maxDepth: 2, maxItems: 40) } }
    public init(scope: ChannelScope, queryNonce: Data, outcome: RoutingStatusOutcome, clockEpoch: Data,
                sampledAtMilliseconds: UInt64, state: RoutingStatusState, canonicalChallenge: Data? = nil,
                controlDigest: Data? = nil, appliedRevision: UInt64? = nil) throws {
        guard queryNonce.count == 32, clockEpoch.count == 16, controlDigest.map({ $0.count == 32 }) ?? true else {
            throw RoutingStatusError.invalidMessage
        }
        switch outcome {
        case .status:
            guard canonicalChallenge == nil, controlDigest == nil, appliedRevision == nil else { throw RoutingStatusError.invalidMessage }
        case .challenge:
            guard let canonicalChallenge, controlDigest == nil, appliedRevision == nil, state.revision < UInt64.max else {
                throw RoutingStatusError.invalidMessage
            }
            let control = try RoutingAwayControl.decode(canonicalChallenge, limits: Self.challengeLimits)
            guard control.macID == scope.macID, control.accountID == scope.accountID, control.phoneID == scope.phoneID,
                  control.enrollmentEpoch == scope.enrollmentEpoch, control.expectedRevision == state.revision else {
                throw RoutingStatusError.invalidMessage
            }
        case .applied:
            guard canonicalChallenge == nil, controlDigest != nil, let appliedRevision,
                  appliedRevision > 0, appliedRevision <= state.revision else { throw RoutingStatusError.invalidMessage }
        case .conflict:
            guard canonicalChallenge == nil, appliedRevision == nil else { throw RoutingStatusError.invalidMessage }
        }
        self.scope = scope; self.queryNonce = queryNonce; self.outcome = outcome; self.clockEpoch = clockEpoch
        self.sampledAtMilliseconds = sampledAtMilliseconds; self.state = state; self.canonicalChallenge = canonicalChallenge
        self.controlDigest = controlDigest; self.appliedRevision = appliedRevision
    }
    public var description: String { "RoutingStatusResponse(redacted)" }
    public var debugDescription: String { description }
    public func encode() throws -> Data {
        try DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(scope.macID), 2: .bytes(scope.accountID), 3: .bytes(scope.phoneID), 4: .bytes(scope.enrollmentEpoch),
            5: .bytes(queryNonce), 6: .unsigned(outcome.rawValue), 7: .bytes(clockEpoch), 8: .unsigned(sampledAtMilliseconds),
            9: .unsigned(state.mode.rawValue), 10: .unsigned(state.revision), 11: .unsigned(state.destination.rawValue),
            12: .unsigned(state.reason.rawValue), 13: .unsigned(state.detectionLimited ? 1 : 0),
            14: canonicalChallenge.map(CBORValue.bytes) ?? .null, 15: controlDigest.map(CBORValue.bytes) ?? .null,
            16: appliedRevision.map(CBORValue.unsigned) ?? .null,
        ]), limits: Self.limits)
    }
    public static func decode(_ bytes: Data) throws -> Self {
        guard case let .map(f) = try DeterministicCBOR.decode(bytes, limits: limits),
              Set(f.keys) == Set(UInt64(0)...16), f[0] == .unsigned(1) else { throw RoutingStatusError.invalidMessage }
        func data(_ n: UInt64) throws -> Data { guard case let .bytes(v) = f[n] else { throw RoutingStatusError.invalidMessage }; return v }
        func uint(_ n: UInt64) throws -> UInt64 { guard case let .unsigned(v) = f[n] else { throw RoutingStatusError.invalidMessage }; return v }
        guard let outcome = RoutingStatusOutcome(rawValue: try uint(6)), let mode = RoutingStatusMode(rawValue: try uint(9)),
              let destination = RoutingStatusDestination(rawValue: try uint(11)), let reason = RoutingStatusReason(rawValue: try uint(12)),
              try uint(13) <= 1 else { throw RoutingStatusError.invalidMessage }
        let state = try RoutingStatusState(mode: mode, revision: uint(10), destination: destination, reason: reason, detectionLimited: uint(13) == 1)
        let result = try Self(scope: .init(macID: data(1), accountID: data(2), phoneID: data(3), enrollmentEpoch: data(4)),
            queryNonce: data(5), outcome: outcome, clockEpoch: data(7), sampledAtMilliseconds: uint(8), state: state,
            canonicalChallenge: f[14] == .null ? nil : data(14), controlDigest: f[15] == .null ? nil : data(15),
            appliedRevision: f[16] == .null ? nil : uint(16))
        guard try result.encode() == bytes else { throw RoutingStatusError.invalidMessage }; return result
    }
    private static var challengeLimits: CBORLimits { get throws { try .init(maxBytes: 1024, maxDepth: 2, maxItems: 32) } }
}

/// Root responses use a distinct type and purpose from the existing phone Away signature.
public enum RoutingStatusSigningInput {
    public static func make(wireVersion: UInt64, canonicalPayload: Data, inputLimits: CBORLimits) throws -> Data {
        guard wireVersion == 1 else { throw SigningInputError.unsupportedVersion }
        _ = try RoutingStatusResponse.decode(canonicalPayload)
        return try DeterministicCBOR.encode(.map([0: .text("dev.remozio.routing"), 1: .unsigned(wireVersion),
            2: .unsigned(2), 3: .unsigned(2), 4: .bytes(canonicalPayload)]), limits: inputLimits)
    }
}

public enum RoutingStatusSignature {
    public static func verify(signature: Data, publicKey: Data, wireVersion: UInt64, canonicalPayload: Data,
                              inputLimits: CBORLimits) throws -> Bool {
        P256Verification.verify(signature: signature, publicKey: publicKey,
            input: try RoutingStatusSigningInput.make(wireVersion: wireVersion, canonicalPayload: canonicalPayload, inputLimits: inputLimits))
    }
}
