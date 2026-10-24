import Foundation

public enum UpdateSchedulingAction: UInt64, CaseIterable, Sendable {
    case installWhenCurrentWorkFinishes = 0, deferUpdate = 1, cancelDrain = 2
}

public enum UpdateSchedulingControlError: String, Error, Equatable {
    case invalidFields, unsupportedSchema, invalidBytes, invalidControl, unsupportedAction
}

/// A scheduling claim for one verified release. It cannot select artifacts, change floors, or authorize target actions.
public struct UpdateSchedulingControl: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let macID: Data
    public let accountID: Data
    public let phoneID: Data
    public let enrollmentEpoch: Data
    public let operationID: Data
    public let challenge: Data
    public let keyID: Data
    public let updateID: Data
    public let expectedGeneration: UInt64
    public let expectedRevision: UInt64
    public let issuedAtUnixMillis: UInt64
    public let expiresAtUnixMillis: UInt64
    public let action: UpdateSchedulingAction

    public init(macID: Data, accountID: Data, phoneID: Data, enrollmentEpoch: Data, operationID: Data,
                challenge: Data, keyID: Data, updateID: Data, expectedGeneration: UInt64, expectedRevision: UInt64,
                issuedAtUnixMillis: UInt64, expiresAtUnixMillis: UInt64, action: UpdateSchedulingAction) throws {
        guard [macID, accountID, phoneID, enrollmentEpoch, operationID, keyID].allSatisfy({ $0.count == 16 }),
              challenge.count == 32, updateID.count == 32 else { throw UpdateSchedulingControlError.invalidBytes }
        guard expectedGeneration > 0, expiresAtUnixMillis > issuedAtUnixMillis else {
            throw UpdateSchedulingControlError.invalidControl
        }
        self.macID = macID; self.accountID = accountID; self.phoneID = phoneID; self.enrollmentEpoch = enrollmentEpoch
        self.operationID = operationID; self.challenge = challenge; self.keyID = keyID; self.updateID = updateID
        self.expectedGeneration = expectedGeneration; self.expectedRevision = expectedRevision
        self.issuedAtUnixMillis = issuedAtUnixMillis; self.expiresAtUnixMillis = expiresAtUnixMillis; self.action = action
    }
    public var description: String { "UpdateSchedulingControl(redacted)" }
    public var debugDescription: String { description }

    public func encode(limits: CBORLimits) throws -> Data {
        try DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(macID), 2: .bytes(accountID), 3: .bytes(phoneID), 4: .bytes(enrollmentEpoch),
            5: .bytes(operationID), 6: .bytes(challenge), 7: .bytes(keyID), 8: .bytes(updateID),
            9: .unsigned(expectedGeneration), 10: .unsigned(expectedRevision), 11: .unsigned(issuedAtUnixMillis),
            12: .unsigned(expiresAtUnixMillis), 13: .unsigned(action.rawValue),
        ]), limits: limits)
    }
    public static func decode(_ payload: Data, limits: CBORLimits) throws -> UpdateSchedulingControl {
        guard case let .map(fields) = try DeterministicCBOR.decode(payload, limits: limits),
              Set(fields.keys) == Set(0...UInt64(13)) else { throw UpdateSchedulingControlError.invalidFields }
        guard fields[0] == .unsigned(1) else { throw UpdateSchedulingControlError.unsupportedSchema }
        func bytes(_ key: UInt64) throws -> Data {
            guard case let .bytes(value) = fields[key] else { throw UpdateSchedulingControlError.invalidBytes }
            return value
        }
        func uint(_ key: UInt64) throws -> UInt64 {
            guard case let .unsigned(value) = fields[key] else { throw UpdateSchedulingControlError.invalidControl }
            return value
        }
        guard case let .unsigned(tag) = fields[13], let action = UpdateSchedulingAction(rawValue: tag) else {
            throw UpdateSchedulingControlError.unsupportedAction
        }
        return try UpdateSchedulingControl(macID: bytes(1), accountID: bytes(2), phoneID: bytes(3), enrollmentEpoch: bytes(4),
            operationID: bytes(5), challenge: bytes(6), keyID: bytes(7), updateID: bytes(8), expectedGeneration: uint(9),
            expectedRevision: uint(10), issuedAtUnixMillis: uint(11), expiresAtUnixMillis: uint(12), action: action)
    }
}

public enum UpdateSchedulingSigningInput {
    public static func make(wireVersion: UInt64, canonicalPayload: Data, payloadLimits: CBORLimits, inputLimits: CBORLimits) throws -> Data {
        guard wireVersion == 1 else { throw SigningInputError.unsupportedVersion }
        _ = try UpdateSchedulingControl.decode(canonicalPayload, limits: payloadLimits)
        return try DeterministicCBOR.encode(.map([
            0: .text("dev.remozio.update-scheduling"), 1: .unsigned(wireVersion),
            2: .unsigned(1), 3: .unsigned(1), 4: .bytes(canonicalPayload),
        ]), limits: inputLimits)
    }
}

/// The authority must select the current enrolled decision key and consume the matching scheduling challenge once.
public enum UpdateSchedulingSignature {
    public static func verify(signature: Data, publicKey: Data, wireVersion: UInt64, canonicalPayload: Data,
                              payloadLimits: CBORLimits, inputLimits: CBORLimits) throws -> Bool {
        let input = try UpdateSchedulingSigningInput.make(wireVersion: wireVersion, canonicalPayload: canonicalPayload,
            payloadLimits: payloadLimits, inputLimits: inputLimits)
        return P256Verification.verify(signature: signature, publicKey: publicKey, input: input)
    }
}
