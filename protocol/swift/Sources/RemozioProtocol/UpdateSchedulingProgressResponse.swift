import Foundation

public enum UpdateSchedulingProgressPhase: UInt64, Sendable {
    case unknown = 0, ready = 1, draining = 2, activating = 3, checkingRestart = 4, finishing = 5, completed = 6, cancelled = 7
    public var irreversible: Bool { self == .activating || self == .checkingRestart || self == .finishing || self == .completed }
}
public enum UpdateSchedulingDesignation: UInt64, Sendable { case unknown = 0, unassigned = 1, thisAccount = 2, otherAccount = 3 }
public enum UpdateSchedulingSecurityStatus: UInt64, Sendable { case unknown = 0, notSecurity = 1, security = 2 }
public enum UpdateSchedulingAdmissionState: UInt64, Sendable { case unknown = 0, open = 1, closed = 2 }

public struct UpdateSchedulingAvailableActions: OptionSet, Equatable, Sendable {
    public let rawValue: UInt64
    public init(rawValue: UInt64) { self.rawValue = rawValue }
    public static let installWhenCurrentWorkFinishes = Self(rawValue: 1)
    public static let deferUpdate = Self(rawValue: 2)
    public static let cancelDrain = Self(rawValue: 4)
}

public struct UpdateSchedulingBlocker: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public enum Kind: UInt64, Sendable { case pendingRequests = 0, activeCommands = 1, liveGUIPermits = 2, otherAccounts = 3 }
    public let kind: Kind
    public let count: UInt64?
    public let oldestAgeMilliseconds: UInt64?
    public init(kind: Kind, count: UInt64?, oldestAgeMilliseconds: UInt64?) throws {
        if kind == .otherAccounts {
            guard count == nil, oldestAgeMilliseconds == nil else { throw UpdateSchedulingStatusError.invalidMessage }
        } else {
            guard let count, count > 0 else { throw UpdateSchedulingStatusError.invalidMessage }
        }
        self.kind = kind; self.count = count; self.oldestAgeMilliseconds = oldestAgeMilliseconds
    }
    public func oldestAgeMilliseconds(afterObservationAge elapsed: UInt64?) -> UInt64? {
        UpdateSchedulingProgressResponse.advanceAge(oldestAgeMilliseconds, by: elapsed)
    }
    public var description: String { "UpdateSchedulingBlocker(redacted)" }
    public var debugDescription: String { description }
}

/// A signed observation for product controls. Every action still requires its own current Root challenge and decision signature.
public struct UpdateSchedulingProgressResponse: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let status: UpdateSchedulingStatusResponse
    public let phase: UpdateSchedulingProgressPhase
    public let designation: UpdateSchedulingDesignation
    public let security: UpdateSchedulingSecurityStatus
    public let readyAgeMilliseconds: UInt64?
    public let availableActions: UpdateSchedulingAvailableActions
    public let blockers: [UpdateSchedulingBlocker]
    public let admission: UpdateSchedulingAdmissionState
    public static let maximumBytes = 4096
    public static var limits: CBORLimits { get throws { try .init(maxBytes: maximumBytes, maxDepth: 3, maxItems: 64) } }

    public init(status: UpdateSchedulingStatusResponse, phase: UpdateSchedulingProgressPhase,
                designation: UpdateSchedulingDesignation, security: UpdateSchedulingSecurityStatus,
                readyAgeMilliseconds: UInt64?, availableActions: UpdateSchedulingAvailableActions,
                blockers: [UpdateSchedulingBlocker], admission: UpdateSchedulingAdmissionState) throws {
        guard status.controlDigest == nil, availableActions.rawValue <= 7, blockers.count <= 4 else {
            throw UpdateSchedulingStatusError.invalidMessage
        }
        for (first, second) in zip(blockers, blockers.dropFirst()) {
            guard first.kind.rawValue < second.kind.rawValue else { throw UpdateSchedulingStatusError.invalidMessage }
        }
        if phase == .unknown || phase.irreversible || admission == .unknown {
            guard availableActions.isEmpty else { throw UpdateSchedulingStatusError.invalidMessage }
        }
        if availableActions.contains(.installWhenCurrentWorkFinishes) {
            guard (phase == .ready || phase == .cancelled), admission == .open else {
                throw UpdateSchedulingStatusError.invalidMessage
            }
        }
        if availableActions.contains(.deferUpdate) {
            guard designation == .thisAccount else { throw UpdateSchedulingStatusError.invalidMessage }
        }
        if availableActions.contains(.cancelDrain) {
            guard admission == .closed, status.requestedAction == .installWhenCurrentWorkFinishes else {
                throw UpdateSchedulingStatusError.invalidMessage
            }
        }
        self.status = status; self.phase = phase; self.designation = designation; self.security = security
        self.readyAgeMilliseconds = readyAgeMilliseconds; self.availableActions = availableActions
        self.blockers = blockers; self.admission = admission
    }

    public func readyAgeMilliseconds(afterObservationAge elapsed: UInt64?) -> UInt64? {
        Self.advanceAge(readyAgeMilliseconds, by: elapsed)
    }
    static func advanceAge(_ age: UInt64?, by elapsed: UInt64?) -> UInt64? {
        guard let age, let elapsed else { return nil }
        let result = age.addingReportingOverflow(elapsed)
        return result.overflow ? nil : result.partialValue
    }
    public var description: String { "UpdateSchedulingProgressResponse(redacted)" }
    public var debugDescription: String { description }

    public func encode() throws -> Data {
        try DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(status.encode()), 2: .unsigned(phase.rawValue),
            3: .unsigned(designation.rawValue), 4: .unsigned(security.rawValue),
            5: readyAgeMilliseconds.map(CBORValue.unsigned) ?? .null, 6: .unsigned(availableActions.rawValue),
            7: .array(blockers.map { .array([.unsigned($0.kind.rawValue),
                $0.count.map(CBORValue.unsigned) ?? .null, $0.oldestAgeMilliseconds.map(CBORValue.unsigned) ?? .null]) }),
            8: .unsigned(admission.rawValue),
        ]), limits: Self.limits)
    }
    public static func decode(_ bytes: Data) throws -> Self {
        guard case let .map(fields) = try DeterministicCBOR.decode(bytes, limits: limits),
              Set(fields.keys) == Set(UInt64(0)...8), fields[0] == .unsigned(1),
              case let .bytes(statusBytes) = fields[1], case let .array(entries) = fields[7] else {
            throw UpdateSchedulingStatusError.invalidMessage
        }
        func uint(_ value: CBORValue?) throws -> UInt64 {
            guard case let .unsigned(number) = value else { throw UpdateSchedulingStatusError.invalidMessage }; return number
        }
        func optional(_ value: CBORValue?) throws -> UInt64? { value == .null ? nil : try uint(value) }
        guard let phase = UpdateSchedulingProgressPhase(rawValue: try uint(fields[2])),
              let designation = UpdateSchedulingDesignation(rawValue: try uint(fields[3])),
              let security = UpdateSchedulingSecurityStatus(rawValue: try uint(fields[4])),
              let admission = UpdateSchedulingAdmissionState(rawValue: try uint(fields[8])) else {
            throw UpdateSchedulingStatusError.invalidMessage
        }
        let blockers: [UpdateSchedulingBlocker] = try entries.map {
            guard case let .array(parts) = $0, parts.count == 3,
                  let kind = UpdateSchedulingBlocker.Kind(rawValue: try uint(parts[0])) else {
                throw UpdateSchedulingStatusError.invalidMessage
            }
            return try .init(kind: kind, count: optional(parts[1]), oldestAgeMilliseconds: optional(parts[2]))
        }
        let value = try Self(status: UpdateSchedulingStatusResponse.decode(statusBytes), phase: phase,
            designation: designation, security: security, readyAgeMilliseconds: optional(fields[5]),
            availableActions: .init(rawValue: uint(fields[6])), blockers: blockers, admission: admission)
        guard try value.encode() == bytes else { throw UpdateSchedulingStatusError.invalidMessage }; return value
    }
}

public enum UpdateSchedulingProgressSigningInput {
    public static func make(wireVersion: UInt64, canonicalPayload: Data, inputLimits: CBORLimits) throws -> Data {
        guard wireVersion == 1 else { throw SigningInputError.unsupportedVersion }
        _ = try UpdateSchedulingProgressResponse.decode(canonicalPayload)
        return try DeterministicCBOR.encode(.map([
            0: .text("dev.remozio.update-scheduling-progress"), 1: .unsigned(1), 2: .unsigned(1),
            3: .unsigned(1), 4: .bytes(canonicalPayload),
        ]), limits: inputLimits)
    }
}
public enum UpdateSchedulingProgressSignature {
    public static func verify(signature: Data, authorityPublicKey: Data, wireVersion: UInt64,
                              canonicalPayload: Data, inputLimits: CBORLimits) throws -> Bool {
        let input = try UpdateSchedulingProgressSigningInput.make(wireVersion: wireVersion,
            canonicalPayload: canonicalPayload, inputLimits: inputLimits)
        return P256Verification.verify(signature: signature, publicKey: authorityPublicKey, input: input)
    }
}
