import Foundation

enum ActionWireError: Error { case invalidAction }

enum ActionWire {
    private static let choices: [UInt64: ActionChoice] = [
        0: .decline, 1: .cancelTarget, 2: .execute, 3: .approveAccess, 4: .unlockVault,
        5: .allowOnce, 6: .denyOnce, 7: .allowRule, 8: .denyRule, 9: .removeRule,
    ]

    static func encode(_ action: CapturedAction) -> CBORValue {
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

    static func decode(_ value: CBORValue) throws -> CapturedAction {
        guard case let .map(fields) = value,
              case let .unsigned(choiceTag) = fields[0], let choice = choices[choiceTag],
              case let .unsigned(scopeTag) = fields[1] else { throw ActionWireError.invalidAction }
        let scope: ActionScope
        switch scopeTag {
        case 0: scope = .currentRequest
        case 1: scope = .session
        case 2:
            guard case let .unsigned(seconds) = fields[2], seconds > 0 else { throw ActionWireError.invalidAction }
            scope = .timed(seconds: seconds)
        case 3: scope = .forever
        default: throw ActionWireError.invalidAction
        }
        let expected: Set<UInt64> = scopeTag == 2 ? [0, 1, 2] : [0, 1]
        guard Set(fields.keys) == expected else { throw ActionWireError.invalidAction }
        return CapturedAction(choice: choice, scope: scope)
    }
}
