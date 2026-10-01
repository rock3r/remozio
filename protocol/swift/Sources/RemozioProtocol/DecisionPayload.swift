import Foundation

public enum DecisionPayloadError: Error, Equatable {
    case invalidFields, unsupportedSchema, invalidBytes, invalidAction
}

/// A parsed decision claim. Enrollment, signatures, retained request bindings, and consumption still require validation.
public struct DecisionPayload: Equatable, Sendable {
    public let macID: Data
    public let accountID: Data
    public let requestID: Data
    public let requestDigest: Data
    public let challenge: Data
    public let phoneID: Data
    public let keyID: Data
    public let action: CapturedAction

    public init(macID: Data, accountID: Data, requestID: Data, requestDigest: Data,
                challenge: Data, phoneID: Data, keyID: Data, action: CapturedAction) throws {
        guard [macID, accountID, requestID, phoneID, keyID].allSatisfy({ $0.count == 16 }),
              requestDigest.count == 32, challenge.count == 32 else { throw DecisionPayloadError.invalidBytes }
        if case .timed(seconds: 0) = action.scope { throw DecisionPayloadError.invalidAction }
        self.macID = macID
        self.accountID = accountID
        self.requestID = requestID
        self.requestDigest = requestDigest
        self.challenge = challenge
        self.phoneID = phoneID
        self.keyID = keyID
        self.action = action
    }

    public func encode(limits: CBORLimits) throws -> Data {
        try DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(macID), 2: .bytes(accountID), 3: .bytes(requestID),
            4: .bytes(requestDigest), 5: .bytes(challenge), 6: .bytes(phoneID), 7: .bytes(keyID),
            8: Self.encodeAction(action),
        ]), limits: limits)
    }

    public static func decode(_ bytes: Data, limits: CBORLimits) throws -> DecisionPayload {
        guard case let .map(fields) = try DeterministicCBOR.decode(bytes, limits: limits),
              Set(fields.keys) == Set(0...UInt64(8)) else { throw DecisionPayloadError.invalidFields }
        guard fields[0] == .unsigned(1) else { throw DecisionPayloadError.unsupportedSchema }
        func data(_ key: UInt64) throws -> Data {
            guard case let .bytes(value) = fields[key] else { throw DecisionPayloadError.invalidBytes }
            return value
        }
        return try DecisionPayload(macID: data(1), accountID: data(2), requestID: data(3),
            requestDigest: data(4), challenge: data(5), phoneID: data(6), keyID: data(7),
            action: decodeAction(fields[8]!))
    }

    private static let choices: [UInt64: ActionChoice] = [
        0: .decline, 1: .cancelTarget, 2: .execute, 3: .approveAccess, 4: .unlockVault,
        5: .allowOnce, 6: .denyOnce, 7: .allowRule, 8: .denyRule, 9: .removeRule,
    ]

    private static func encodeAction(_ action: CapturedAction) -> CBORValue {
        let choice = choices.first { $0.value == action.choice }!.key
        var fields: [UInt64: CBORValue] = [0: .unsigned(choice)]
        switch action.scope {
        case .currentRequest: fields[1] = .unsigned(0)
        case .session: fields[1] = .unsigned(1)
        case let .timed(seconds): fields[1] = .unsigned(2); fields[2] = .unsigned(seconds)
        case .forever: fields[1] = .unsigned(3)
        }
        return .map(fields)
    }

    private static func decodeAction(_ value: CBORValue) throws -> CapturedAction {
        guard case let .map(fields) = value,
              case let .unsigned(choiceTag) = fields[0], let choice = choices[choiceTag],
              case let .unsigned(scopeTag) = fields[1] else { throw DecisionPayloadError.invalidAction }
        let scope: ActionScope
        switch scopeTag {
        case 0: scope = .currentRequest
        case 1: scope = .session
        case 2:
            guard case let .unsigned(seconds) = fields[2], seconds > 0 else { throw DecisionPayloadError.invalidAction }
            scope = .timed(seconds: seconds)
        case 3: scope = .forever
        default: throw DecisionPayloadError.invalidAction
        }
        let expected: Set<UInt64> = scopeTag == 2 ? [0, 1, 2] : [0, 1]
        guard Set(fields.keys) == expected else { throw DecisionPayloadError.invalidAction }
        return CapturedAction(choice: choice, scope: scope)
    }
}
