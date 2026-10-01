import Foundation

public enum RequestKind: String, CaseIterable, Sendable {
    case command, onePasswordAccess, onePasswordUnlock, littleSnitch
}

public enum ActionChoice: String, CaseIterable, Sendable {
    case decline, cancelTarget, execute, approveAccess, unlockVault
    case allowOnce, denyOnce, allowRule, denyRule, removeRule
}

public enum ActionScope: Hashable, Sendable {
    case currentRequest, session, timed(seconds: UInt64), forever
}

public struct CapturedAction: Hashable, Sendable {
    public let choice: ActionChoice
    public let scope: ActionScope

    public init(choice: ActionChoice, scope: ActionScope) {
        self.choice = choice
        self.scope = scope
    }
}

public enum ApprovalKeyClass: String, Sendable { case decision, biometric }
public enum ApprovalPurpose: String, Sendable { case cancellation, oneTimeUI, biometricAuthorization }
public enum ActionEffect: String, Sendable { case resolveRequest, dispatchTarget }

public struct ActionRequirement: Equatable, Sendable {
    public let keyClass: ApprovalKeyClass
    public let purpose: ApprovalPurpose
    public let effect: ActionEffect
}

public enum ActionPolicyError: String, Error, Equatable {
    case notPermitted, incompatibleAction, invalidScope
}

/// Evaluate against the trusted capture, never a permitted-action list supplied by a decision.
public enum ActionPolicy {
    public static func requirement(
        for action: CapturedAction,
        requestKind: RequestKind,
        retainedPermittedActions: Set<CapturedAction>
    ) throws -> ActionRequirement {
        guard retainedPermittedActions.contains(action) else { throw ActionPolicyError.notPermitted }
        switch action.choice {
        case .decline:
            try requireCurrentRequest(action.scope)
            return ActionRequirement(keyClass: .decision, purpose: .cancellation, effect: .resolveRequest)
        case .cancelTarget:
            guard requestKind != .command else { throw ActionPolicyError.incompatibleAction }
            try requireCurrentRequest(action.scope)
            return ActionRequirement(keyClass: .decision, purpose: .oneTimeUI, effect: .dispatchTarget)
        case .execute:
            guard requestKind == .command else { throw ActionPolicyError.incompatibleAction }
            try requireCurrentRequest(action.scope)
            return biometric
        case .approveAccess:
            guard requestKind == .onePasswordAccess else { throw ActionPolicyError.incompatibleAction }
            try requireCurrentRequest(action.scope)
            return biometric
        case .unlockVault:
            guard requestKind == .onePasswordUnlock else { throw ActionPolicyError.incompatibleAction }
            try requireCurrentRequest(action.scope)
            return biometric
        case .allowOnce, .denyOnce:
            guard requestKind == .littleSnitch else { throw ActionPolicyError.incompatibleAction }
            try requireCurrentRequest(action.scope)
            return ActionRequirement(keyClass: .decision, purpose: .oneTimeUI, effect: .dispatchTarget)
        case .allowRule, .denyRule, .removeRule:
            guard requestKind == .littleSnitch else { throw ActionPolicyError.incompatibleAction }
            switch action.scope {
            case .session, .forever: break
            case let .timed(seconds) where seconds > 0: break
            default: throw ActionPolicyError.invalidScope
            }
            return biometric
        }
    }

    private static var biometric: ActionRequirement {
        ActionRequirement(keyClass: .biometric, purpose: .biometricAuthorization, effect: .dispatchTarget)
    }

    private static func requireCurrentRequest(_ scope: ActionScope) throws {
        guard scope == .currentRequest else { throw ActionPolicyError.invalidScope }
    }
}
