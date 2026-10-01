import Foundation

public enum AuditEventKind: UInt64, CaseIterable, Sendable {
    case unknown = 0, requestCreated = 1, phoneDecision = 2, decisionAccepted = 3
    case decisionRejected = 4, consumed = 5, dispatched = 6, verifiedResult = 7
    case expired = 8, cancelled = 9, unknownOutcome = 10, enrollmentAdded = 11
    case enrollmentRevoked = 12, recovery = 13, updateScheduled = 14, updateActivated = 15
    case updateInterrupted = 16, bridgeStarted = 17, bridgeStopped = 18, dismissed = 19
    case biometricCancelled = 20, aggregatedRejections = 21
}

public enum AuditCategory: UInt64, CaseIterable, Sendable {
    case unknown = 0, command = 1, onePasswordAccess = 2, onePasswordUnlock = 3
    case littleSnitch = 4, enrollment = 5, authority = 6, update = 7
    case adbBridge = 8
}

public enum AuditActionKind: UInt64, CaseIterable, Sendable {
    case unknown = 0, decline = 1, cancelTarget = 2, execute = 3
    case approveAccess = 4, unlockVault = 5, allow = 6, deny = 7
    case removeRule = 8
}

public enum AuditLifetime: UInt64, CaseIterable, Sendable {
    case unknown = 0, currentRequest = 1, session = 2, timed = 3
    case forever = 4
}

public enum AuditTargetScope: UInt64, CaseIterable, Sendable {
    case unknown = 0, host = 1, domain = 2, any = 3
}

public enum AuditAuthentication: UInt64, CaseIterable, Sendable {
    case unknown = 0, unverified = 1, decisionKey = 2, biometricKey = 3
    case localAdministrator = 4, system = 5
}

public enum AuditOutcome: UInt64, CaseIterable, Sendable {
    case unknown = 0, pending = 1, accepted = 2, rejected = 3
    case noDispatch = 4, attempted = 5, verifiedSuccess = 6, verifiedFailure = 7
    case unresolved = 8, cancelled = 9, expired = 10
}

public enum AuditReason: UInt64, CaseIterable, Sendable {
    case unknown = 0, none = 1, userDeclined = 2, userCancelled = 3
    case authorizationExpired = 4, targetTimedOut = 5, targetDisappeared = 6, revoked = 7
    case bindingMismatch = 8, replay = 9, incompatible = 10, authorityRestarted = 11
    case storageUnavailable = 12, outcomeUnavailable = 13, updateInterrupted = 14, peerDisconnected = 15
    case manualStop = 16
}

/// Privacy projection only. It does not validate a decision or retain duration or target values.
public struct AuditActionMetadata: Equatable, Sendable {
    public let kind: AuditActionKind
    public let lifetime: AuditLifetime
    public let target: AuditTargetScope?
    public init(kind: AuditActionKind, lifetime: AuditLifetime, target: AuditTargetScope?) {
        self.kind = kind; self.lifetime = lifetime; self.target = target
    }
    public init(action: CapturedAction, target: AuditTargetScope? = nil) {
        switch action.choice {
        case .decline: kind = .decline
        case .cancelTarget: kind = .cancelTarget
        case .execute: kind = .execute
        case .approveAccess: kind = .approveAccess
        case .unlockVault: kind = .unlockVault
        case .allowOnce, .allowRule: kind = .allow
        case .denyOnce, .denyRule: kind = .deny
        case .removeRule: kind = .removeRule
        }
        switch action.scope {
        case .currentRequest: lifetime = .currentRequest
        case .session: lifetime = .session
        case .timed: lifetime = .timed
        case .forever: lifetime = .forever
        }
        self.target = target
    }
}

public enum AuditEventError: Error { case invalidMetadata }

/// Unauthenticated metadata. Journal ordering, integrity, retention and event truth are external obligations.
public struct AuditEventMetadata: Equatable, Sendable {
    public let eventID: Data
    public let macID: Data
    public let accountID: Data
    public let journalEpoch: Data
    public let sequence: UInt64
    public let requestID: Data?
    public let eventTimeMs: UInt64?
    public let authorityReceiptTimeMs: UInt64?
    public let kind: AuditEventKind
    public let category: AuditCategory
    public let action: AuditActionMetadata?
    public let decisionPhoneID: Data?
    public let authentication: AuditAuthentication
    public let outcome: AuditOutcome
    public let reason: AuditReason
    public let droppedEventCount: UInt64?
    public let peerDeviceID: Data?

    public init(eventID: Data, macID: Data, accountID: Data, journalEpoch: Data, sequence: UInt64,
                requestID: Data?, eventTimeMs: UInt64?, authorityReceiptTimeMs: UInt64?, kind: AuditEventKind,
                category: AuditCategory, action: AuditActionMetadata?, decisionPhoneID: Data?,
                authentication: AuditAuthentication, outcome: AuditOutcome, reason: AuditReason,
                droppedEventCount: UInt64?, peerDeviceID: Data?) throws {
        guard [eventID, macID, accountID, journalEpoch, requestID, decisionPhoneID, peerDeviceID]
            .compactMap({ $0 }).allSatisfy({ $0.count == 16 }), sequence > 0,
            (kind == .aggregatedRejections) == (droppedEventCount != nil), droppedEventCount != 0 else {
            throw AuditEventError.invalidMetadata
        }
        self.eventID = eventID; self.macID = macID; self.accountID = accountID; self.journalEpoch = journalEpoch
        self.sequence = sequence; self.requestID = requestID; self.eventTimeMs = eventTimeMs
        self.authorityReceiptTimeMs = authorityReceiptTimeMs; self.kind = kind; self.category = category
        self.action = action; self.decisionPhoneID = decisionPhoneID; self.authentication = authentication
        self.outcome = outcome; self.reason = reason; self.droppedEventCount = droppedEventCount; self.peerDeviceID = peerDeviceID
    }

    public func encode(limits: CBORLimits) throws -> Data {
        try DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(eventID), 2: .bytes(macID), 3: .bytes(accountID), 4: .bytes(journalEpoch),
            5: .unsigned(sequence), 6: requestID.map(CBORValue.bytes) ?? .null,
            7: Self.number(eventTimeMs), 8: Self.number(authorityReceiptTimeMs), 9: .unsigned(kind.rawValue),
            10: .unsigned(category.rawValue), 11: Self.number(action?.kind.rawValue), 12: Self.number(action?.lifetime.rawValue),
            13: Self.number(action?.target?.rawValue), 14: decisionPhoneID.map(CBORValue.bytes) ?? .null,
            15: .unsigned(authentication.rawValue), 16: .unsigned(outcome.rawValue), 17: .unsigned(reason.rawValue),
            18: Self.number(droppedEventCount), 19: peerDeviceID.map(CBORValue.bytes) ?? .null,
        ]), limits: limits)
    }
    private static func number(_ value: UInt64?) -> CBORValue { value.map(CBORValue.unsigned) ?? .null }

    public static func decode(_ bytes: Data, limits: CBORLimits) throws -> AuditEventMetadata {
        guard case let .map(fields) = try DeterministicCBOR.decode(bytes, limits: limits),
              Set(fields.keys) == Set(0...UInt64(19)), fields[0] == .unsigned(1) else { throw AuditEventError.invalidMetadata }
        func uint(_ key: UInt64) throws -> UInt64 {
            guard case let .unsigned(value) = fields[key] else { throw AuditEventError.invalidMetadata }
            return value
        }
        func optional(_ key: UInt64) throws -> UInt64? { try fields[key] == .null ? nil : uint(key) }
        func data(_ key: UInt64) throws -> Data {
            guard case let .bytes(value) = fields[key] else { throw AuditEventError.invalidMetadata }
            return value
        }
        func optionalData(_ key: UInt64) throws -> Data? { try fields[key] == .null ? nil : data(key) }
        func tag<T: RawRepresentable>(_ key: UInt64, _: T.Type) throws -> T where T.RawValue == UInt64 {
            guard let value = T(rawValue: try uint(key)) else { throw AuditEventError.invalidMetadata }
            return value
        }
        let action: AuditActionMetadata?
        if fields[11] == .null {
            guard fields[12] == .null, fields[13] == .null else { throw AuditEventError.invalidMetadata }
            action = nil
        } else {
            action = try AuditActionMetadata(kind: tag(11, AuditActionKind.self), lifetime: tag(12, AuditLifetime.self),
                target: fields[13] == .null ? nil : tag(13, AuditTargetScope.self))
        }
        return try AuditEventMetadata(eventID: data(1), macID: data(2), accountID: data(3), journalEpoch: data(4),
            sequence: uint(5), requestID: optionalData(6), eventTimeMs: optional(7), authorityReceiptTimeMs: optional(8),
            kind: tag(9, AuditEventKind.self), category: tag(10, AuditCategory.self), action: action,
            decisionPhoneID: optionalData(14), authentication: tag(15, AuditAuthentication.self),
            outcome: tag(16, AuditOutcome.self), reason: tag(17, AuditReason.self), droppedEventCount: optional(18),
            peerDeviceID: optionalData(19))
    }
}
