import Foundation

public enum RequestPhase: String, CaseIterable, Sendable {
    case queued, presented, authorized, executing
    case succeeded, failed, unknown, declined, cancelled, expired

    public var isTerminal: Bool {
        switch self {
        case .queued, .presented, .authorized, .executing: false
        default: true
        }
    }
}

public enum RequestEvent: String, CaseIterable, Sendable {
    case present, authorize, decline, cancel, expire, beginDispatch
    case verifySuccess, verifyFailure, loseOutcome, restartAuthority, proveNoDispatch
}

public enum LifecycleError: String, Error, Equatable { case terminal, invalidTransition }

/// A transition rule, not a dispatch permit. The authority must serialize and durably commit changes.
public enum RequestLifecycle {
    public static func transition(from phase: RequestPhase, event: RequestEvent) throws -> RequestPhase {
        guard !phase.isTerminal else { throw LifecycleError.terminal }
        switch (phase, event) {
        case (.queued, .present): return .presented
        case (.queued, .authorize), (.presented, .authorize): return .authorized
        case (.queued, .decline), (.presented, .decline): return .declined
        case (.queued, .cancel), (.presented, .cancel): return .cancelled
        case (.queued, .expire), (.presented, .expire): return .expired
        case (.authorized, .beginDispatch): return .executing
        case (.authorized, .proveNoDispatch): return .cancelled
        case (.executing, .verifySuccess): return .succeeded
        case (.executing, .verifyFailure): return .failed
        case (.authorized, .loseOutcome), (.executing, .loseOutcome): return .unknown
        case (.queued, .restartAuthority), (.presented, .restartAuthority): return .cancelled
        case (.authorized, .restartAuthority), (.executing, .restartAuthority): return .unknown
        default: throw LifecycleError.invalidTransition
        }
    }
}
