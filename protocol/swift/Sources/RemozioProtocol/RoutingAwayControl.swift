import Foundation

public enum RoutingControlError: String, Error, Equatable {
    case invalidFields, unsupportedSchema, invalidBytes, invalidControl, unsupportedMode
}

/// A phone claim to route requests Away. Current enrollment, challenge, expiry and revision need authority checks.
public struct RoutingAwayControl: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let macID: Data
    public let accountID: Data
    public let phoneID: Data
    public let enrollmentEpoch: Data
    public let operationID: Data
    public let challenge: Data
    public let keyID: Data
    public let expectedRevision: UInt64
    public let issuedAtUnixMillis: UInt64
    public let expiresAtUnixMillis: UInt64

    public init(macID: Data, accountID: Data, phoneID: Data, enrollmentEpoch: Data, operationID: Data,
                challenge: Data, keyID: Data, expectedRevision: UInt64, issuedAtUnixMillis: UInt64, expiresAtUnixMillis: UInt64) throws {
        guard [macID, accountID, phoneID, enrollmentEpoch, operationID, keyID].allSatisfy({ $0.count == 16 }),
              challenge.count == 32 else { throw RoutingControlError.invalidBytes }
        guard expiresAtUnixMillis > issuedAtUnixMillis else { throw RoutingControlError.invalidControl }
        self.macID = macID; self.accountID = accountID; self.phoneID = phoneID; self.enrollmentEpoch = enrollmentEpoch
        self.operationID = operationID; self.challenge = challenge; self.keyID = keyID; self.expectedRevision = expectedRevision
        self.issuedAtUnixMillis = issuedAtUnixMillis; self.expiresAtUnixMillis = expiresAtUnixMillis
    }
    public var description: String { "RoutingAwayControl(redacted)" }
    public var debugDescription: String { description }

    public func encode(limits: CBORLimits) throws -> Data {
        try DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(macID), 2: .bytes(accountID), 3: .bytes(phoneID), 4: .bytes(enrollmentEpoch),
            5: .bytes(operationID), 6: .bytes(challenge), 7: .bytes(keyID), 8: .unsigned(expectedRevision),
            9: .unsigned(issuedAtUnixMillis), 10: .unsigned(expiresAtUnixMillis), 11: .unsigned(2),
        ]), limits: limits)
    }
    public static func decode(_ payload: Data, limits: CBORLimits) throws -> RoutingAwayControl {
        guard case let .map(fields) = try DeterministicCBOR.decode(payload, limits: limits),
              Set(fields.keys) == Set(0...UInt64(11)) else { throw RoutingControlError.invalidFields }
        guard fields[0] == .unsigned(1) else { throw RoutingControlError.unsupportedSchema }
        guard fields[11] == .unsigned(2) else { throw RoutingControlError.unsupportedMode }
        func bytes(_ key: UInt64) throws -> Data {
            guard case let .bytes(value) = fields[key] else { throw RoutingControlError.invalidBytes }
            return value
        }
        func uint(_ key: UInt64) throws -> UInt64 {
            guard case let .unsigned(value) = fields[key] else { throw RoutingControlError.invalidControl }
            return value
        }
        return try RoutingAwayControl(macID: bytes(1), accountID: bytes(2), phoneID: bytes(3), enrollmentEpoch: bytes(4),
            operationID: bytes(5), challenge: bytes(6), keyID: bytes(7), expectedRevision: uint(8),
            issuedAtUnixMillis: uint(9), expiresAtUnixMillis: uint(10))
    }
}

public enum RoutingAwaySigningInput {
    public static func make(wireVersion: UInt64, canonicalPayload: Data, payloadLimits: CBORLimits, inputLimits: CBORLimits) throws -> Data {
        guard wireVersion == 1 else { throw SigningInputError.unsupportedVersion }
        _ = try RoutingAwayControl.decode(canonicalPayload, limits: payloadLimits)
        return try DeterministicCBOR.encode(.map([
            0: .text("dev.remozio.routing"), 1: .unsigned(wireVersion), 2: .unsigned(1), 3: .unsigned(1), 4: .bytes(canonicalPayload),
        ]), limits: inputLimits)
    }
}

/// Select only the current enrolled decision key. A valid signature alone cannot change routing or grant approval.
public enum RoutingAwaySignature {
    public static func verify(signature: Data, publicKey: Data, wireVersion: UInt64, canonicalPayload: Data,
                              payloadLimits: CBORLimits, inputLimits: CBORLimits) throws -> Bool {
        let input = try RoutingAwaySigningInput.make(wireVersion: wireVersion, canonicalPayload: canonicalPayload,
            payloadLimits: payloadLimits, inputLimits: inputLimits)
        return P256Verification.verify(signature: signature, publicKey: publicKey, input: input)
    }
}
