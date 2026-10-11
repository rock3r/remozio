import Foundation
import RemozioProtocol

public enum AuthorityPresenceIPCError: Error, Equatable {
    case invalidMessage, staleOperation, unavailable, policyMismatch
}

/// The account scope and both incarnations bind every mutation to one authenticated app connection.
public struct AuthorityPresenceBinding: Equatable, Sendable {
    public let macID: Data
    public let accountID: Data
    public let clockEpoch: UUID
    public let connectionID: UUID
    public init(macID: Data, accountID: Data, clockEpoch: UUID, connectionID: UUID) throws {
        guard macID.count == 16, accountID.count == 16 else { throw AuthorityPresenceIPCError.invalidMessage }
        self.macID = macID; self.accountID = accountID; self.clockEpoch = clockEpoch; self.connectionID = connectionID
    }
}

/// A current Root reply. The client must discard it when the connection is lost.
public struct AuthorityPresenceStatus: Sendable {
    public let binding: AuthorityPresenceBinding
    public let sampledAt: AuthorityMoment
    public let state: RoutingState
    public let routing: PresenceRouting
    public let conflict: Bool
}

struct AuthorityPresencePublication: Sendable {
    let binding: AuthorityPresenceBinding
    let sequence: UInt64
    let sampledAt: AuthorityMoment
    let snapshot: PresenceSnapshot
}
struct AuthorityPresenceModeChange: Sendable {
    let binding: AuthorityPresenceBinding
    let sequence: UInt64
    let mode: RoutingMode
    let expectedRevision: UInt64
}

/// Version one local IPC. Messages contain coarse signals, never keystrokes, windows or remote session identifiers.
public enum AuthorityPresenceCodec {
    public static let maximumBytes = 4096
    public static func encodeStatus(_ value: AuthorityPresenceStatus) throws -> Data {
        guard value.sampledAt.epoch == value.binding.clockEpoch else { throw invalid }
        var fields = prefix(value.binding)
        fields[5] = .unsigned(value.sampledAt.milliseconds)
        fields[6] = .text(value.state.mode.rawValue); fields[7] = .unsigned(value.state.revision)
        fields[8] = .text(value.routing.destination.rawValue); fields[9] = .text(value.routing.reason.rawValue)
        fields[10] = .unsigned(value.routing.detectionLimited ? 1 : 0); fields[11] = .unsigned(value.conflict ? 1 : 0)
        return try encode(fields)
    }
    public static func decodeStatus(_ bytes: Data, expectedMacID: Data, expectedAccountID: Data) throws -> AuthorityPresenceStatus {
        let fields = try decode(bytes, count: 12), binding = try binding(fields)
        guard binding.macID == expectedMacID, binding.accountID == expectedAccountID,
              case .text(let modeString) = fields[6], let mode = RoutingMode(rawValue: modeString),
              case .text(let destinationString) = fields[8], let destination = RequestDestination(rawValue: destinationString),
              case .text(let reasonString) = fields[9], let reason = PresenceReason(rawValue: reasonString) else { throw invalid }
        let result = AuthorityPresenceStatus(binding: binding, sampledAt: .init(epoch: binding.clockEpoch, milliseconds: try number(fields[5])),
            state: .init(mode: mode, revision: try number(fields[7])),
            routing: .init(destination: destination, reason: reason, detectionLimited: try boolean(fields[10])), conflict: try boolean(fields[11]))
        guard try encodeStatus(result) == bytes else { throw invalid }
        return result
    }
    public static func encodePublication(binding: AuthorityPresenceBinding, sequence: UInt64,
                                         sampledAt: AuthorityMoment, snapshot: PresenceSnapshot) throws -> Data {
        guard sequence > 0, sampledAt.epoch == binding.clockEpoch else { throw invalid }
        let at = PresenceMoment(epoch: sampledAt.epoch, milliseconds: sampledAt.milliseconds)
        guard matches(snapshot.remoteWorkspace, at), matches(snapshot.locked, at), matches(snapshot.displays, at),
              matches(snapshot.lastQualifyingInputMilliseconds, at),
              (snapshot.displays?.value.count ?? 0) <= 32,
              snapshot.lastQualifyingInputMilliseconds.map({ $0.value <= at.milliseconds }) ?? true else { throw invalid }
        var fields = prefix(binding)
        fields[5] = .unsigned(sequence); fields[6] = .unsigned(sampledAt.milliseconds)
        fields[7] = snapshot.remoteWorkspace.map { .unsigned(remote($0.value)) } ?? .null
        fields[8] = snapshot.locked.map { .unsigned($0.value ? 1 : 0) } ?? .null
        fields[9] = snapshot.displays.map { .array($0.value.map { .unsigned(display($0)) }) } ?? .null
        fields[10] = snapshot.lastQualifyingInputMilliseconds.map { .unsigned($0.value) } ?? .null
        return try encode(fields)
    }
    static func decodePublication(_ bytes: Data) throws -> AuthorityPresencePublication {
        let fields = try decode(bytes, count: 11), binding = try binding(fields)
        let sequence = try number(fields[5]), milliseconds = try number(fields[6])
        guard sequence > 0 else { throw invalid }
        let at = PresenceMoment(epoch: binding.clockEpoch, milliseconds: milliseconds)
        let remoteValue: PresenceObservation<RemoteWorkspace>?
        if fields[7] == .null { remoteValue = nil }
        else {
            let value: RemoteWorkspace
            switch try number(fields[7]) { case 0: value = .notUsable; case 1: value = .usable; case 2: value = .unsupported; default: throw invalid }
            remoteValue = .init(value, observedAt: at)
        }
        let locked = fields[8] == .null ? nil : PresenceObservation(try boolean(fields[8]), observedAt: at)
        let displays: PresenceObservation<[DisplayPresence]>?
        if fields[9] == .null { displays = nil }
        else {
            guard case .array(let values) = fields[9], values.count <= 32 else { throw invalid }
            displays = try .init(values.map { value in
                switch try number(value) {
                case 0: return .asleep; case 1: return .awake(.readable); case 2: return .awake(.dark)
                case 3: return .awake(.unknown); case 4: return .unknown; default: throw invalid
                }
            }, observedAt: at)
        }
        let input = fields[10] == .null ? nil : PresenceObservation(try number(fields[10]), observedAt: at)
        let result = AuthorityPresencePublication(binding: binding, sequence: sequence,
            sampledAt: .init(epoch: binding.clockEpoch, milliseconds: milliseconds),
            snapshot: .init(remoteWorkspace: remoteValue, locked: locked, displays: displays, lastQualifyingInputMilliseconds: input))
        guard try encodePublication(binding: binding, sequence: sequence, sampledAt: result.sampledAt, snapshot: result.snapshot) == bytes else { throw invalid }
        return result
    }
    public static func encodeModeChange(binding: AuthorityPresenceBinding, sequence: UInt64,
                                        mode: RoutingMode, expectedRevision: UInt64) throws -> Data {
        guard sequence > 0 else { throw invalid }
        var fields = prefix(binding)
        fields[5] = .unsigned(sequence); fields[6] = .text(mode.rawValue); fields[7] = .unsigned(expectedRevision)
        return try encode(fields)
    }
    static func decodeModeChange(_ bytes: Data) throws -> AuthorityPresenceModeChange {
        let fields = try decode(bytes, count: 8), binding = try binding(fields), sequence = try number(fields[5])
        guard sequence > 0, case .text(let modeString) = fields[6], let mode = RoutingMode(rawValue: modeString) else { throw invalid }
        let result = AuthorityPresenceModeChange(binding: binding, sequence: sequence, mode: mode, expectedRevision: try number(fields[7]))
        guard try encodeModeChange(binding: binding, sequence: sequence, mode: mode, expectedRevision: result.expectedRevision) == bytes else { throw invalid }
        return result
    }
    private static var invalid: AuthorityPresenceIPCError { .invalidMessage }
    private static var limits: CBORLimits { get throws { try .init(maxBytes: maximumBytes, maxDepth: 2, maxItems: 128) } }
    private static func prefix(_ binding: AuthorityPresenceBinding) -> [UInt64: CBORValue] {
        [0: .unsigned(1), 1: .bytes(binding.macID), 2: .bytes(binding.accountID),
         3: .bytes(uuidBytes(binding.clockEpoch)), 4: .bytes(uuidBytes(binding.connectionID))]
    }
    private static func binding(_ fields: [UInt64: CBORValue]) throws -> AuthorityPresenceBinding {
        guard fields[0] == .unsigned(1), case .bytes(let mac) = fields[1], case .bytes(let account) = fields[2],
              case .bytes(let epoch) = fields[3], case .bytes(let connection) = fields[4] else { throw invalid }
        return try .init(macID: mac, accountID: account, clockEpoch: uuid(epoch), connectionID: uuid(connection))
    }
    private static func uuidBytes(_ value: UUID) -> Data { withUnsafeBytes(of: value.uuid) { Data($0) } }
    private static func uuid(_ bytes: Data) throws -> UUID {
        guard bytes.count == 16 else { throw invalid }
        return bytes.withUnsafeBytes { UUID(uuid: $0.loadUnaligned(as: uuid_t.self)) }
    }
    private static func number(_ value: CBORValue?) throws -> UInt64 { guard case .unsigned(let n) = value else { throw invalid }; return n }
    private static func boolean(_ value: CBORValue?) throws -> Bool { let n = try number(value); guard n <= 1 else { throw invalid }; return n == 1 }
    private static func encode(_ fields: [UInt64: CBORValue]) throws -> Data { try DeterministicCBOR.encode(.map(fields), limits: limits) }
    private static func decode(_ bytes: Data, count: UInt64) throws -> [UInt64: CBORValue] {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits), Set(fields.keys) == Set(0..<count) else { throw invalid }
        return fields
    }
    private static func remote(_ value: RemoteWorkspace) -> UInt64 {
        switch value { case .notUsable: 0; case .usable: 1; case .unsupported: 2 }
    }
    private static func display(_ value: DisplayPresence) -> UInt64 {
        switch value { case .asleep: 0; case .awake(.readable): 1; case .awake(.dark): 2; case .awake(.unknown): 3; case .unknown: 4 }
    }
    private static func matches<T: Sendable>(_ value: PresenceObservation<T>?, _ moment: PresenceMoment) -> Bool {
        value.map { $0.observedAt == moment } ?? true
    }
}
