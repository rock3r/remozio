import Foundation

public enum AuditEpochCause: UInt64, Sendable { case initial = 0, restart = 1, replacement = 2, recovery = 3, restoration = 4, unknown = 5 }
public enum AuditHistoryDisposition: UInt64, Sendable { case discovery = 0, available = 1, unavailable = 2, cursorAhead = 3 }
public enum AuditHistoryError: Error { case invalidStatus }

private struct AuditFields {
    let fields: [UInt64: CBORValue]
    init(_ bytes: Data, limits: CBORLimits, lastKey: UInt64) throws {
        guard case let .map(fields) = try DeterministicCBOR.decode(bytes, limits: limits),
              Set(fields.keys) == Set(0...lastKey), fields[0] == .unsigned(1) else { throw AuditHistoryError.invalidStatus }
        self.fields = fields
    }
    func uint(_ key: UInt64) throws -> UInt64 {
        guard case let .unsigned(value) = fields[key] else { throw AuditHistoryError.invalidStatus }
        return value
    }
    func optionalUInt(_ key: UInt64) throws -> UInt64? { try fields[key] == .null ? nil : uint(key) }
    func bytes(_ key: UInt64) throws -> Data {
        guard case let .bytes(value) = fields[key] else { throw AuditHistoryError.invalidStatus }
        return value
    }
    func id(_ key: UInt64, _ size: Int) throws -> Data {
        let value = try bytes(key)
        guard value.count == size else { throw AuditHistoryError.invalidStatus }
        return value
    }
    func optionalID(_ key: UInt64, _ size: Int) throws -> Data? { try fields[key] == .null ? nil : id(key, size) }
}

/// Immutable epoch metadata. A prior boundary does not prove that no later records ever existed.
public struct AuditEpochDescriptor: Sendable {
    private let fields: [UInt64: CBORValue]
    public let macID: Data
    public let accountID: Data
    public let epoch: Data
    public let generation: UInt64
    public let cause: AuditEpochCause
    public let previousEpoch: Data?
    public let previousSequence: UInt64?
    public let previousEventDigest: Data?
    public func encode(limits: CBORLimits) throws -> Data { try DeterministicCBOR.encode(.map(fields), limits: limits) }

    public static func decode(_ bytes: Data, limits: CBORLimits) throws -> AuditEpochDescriptor {
        let f = try AuditFields(bytes, limits: limits, lastKey: 8)
        let mac = try f.id(1, 16), account = try f.id(2, 16), epoch = try f.id(3, 16), generation = try f.uint(4)
        guard let cause = AuditEpochCause(rawValue: try f.uint(5)) else { throw AuditHistoryError.invalidStatus }
        let previous = try f.optionalID(6, 16), sequence = try f.optionalUInt(7), digest = try f.optionalID(8, 32)
        guard (previous == nil) == (sequence == nil), previous != epoch,
              (digest != nil) == (sequence.map { $0 > 0 } ?? false),
              cause != .initial || previous == nil else { throw AuditHistoryError.invalidStatus }
        return AuditEpochDescriptor(fields: f.fields, macID: mac, accountID: account, epoch: epoch,
            generation: generation, cause: cause, previousEpoch: previous, previousSequence: sequence, previousEventDigest: digest)
    }
}

/// Query-bound discovery or reconciliation data. Signature, freshness and cached evidence checks are separate.
public struct AuditHistoryStatus: Sendable {
    private let fields: [UInt64: CBORValue]
    public let macID: Data
    public let accountID: Data
    public let queryNonce: Data
    public let requestedEpoch: Data?
    public let requestedAfter: UInt64?
    public let disposition: AuditHistoryDisposition
    public let current: AuditEpochDescriptor
    public let currentRetainedAfter: UInt64
    public let currentHead: UInt64
    public let queried: AuditEpochDescriptor?
    public let queriedRetainedAfter: UInt64?
    public let queriedHead: UInt64?
    public func encode(limits: CBORLimits) throws -> Data { try DeterministicCBOR.encode(.map(fields), limits: limits) }

    public static func decode(_ bytes: Data, limits: CBORLimits, descriptorLimits: CBORLimits) throws -> AuditHistoryStatus {
        let f = try AuditFields(bytes, limits: limits, lastKey: 12)
        let mac = try f.id(1, 16), account = try f.id(2, 16), nonce = try f.id(3, 32)
        let requested = try f.optionalID(4, 16), after = try f.optionalUInt(5)
        guard let disposition = AuditHistoryDisposition(rawValue: try f.uint(6)) else { throw AuditHistoryError.invalidStatus }
        func descriptor(_ key: UInt64) throws -> AuditEpochDescriptor {
            let result = try AuditEpochDescriptor.decode(f.bytes(key), limits: descriptorLimits)
            guard result.macID == mac, result.accountID == account else { throw AuditHistoryError.invalidStatus }
            return result
        }
        let current = try descriptor(7), retained = try f.uint(8), head = try f.uint(9)
        let queried = try f.fields[10] == .null ? nil : descriptor(10)
        let queriedRetained = try f.optionalUInt(11), queriedHead = try f.optionalUInt(12)
        guard retained <= head, (requested == nil) == (after == nil),
              (queried == nil) == (queriedRetained == nil), (queried == nil) == (queriedHead == nil) else {
            throw AuditHistoryError.invalidStatus
        }
        switch disposition {
        case .discovery:
            guard requested == nil, queried == nil else { throw AuditHistoryError.invalidStatus }
        case .unavailable:
            guard let requested, queried == nil, requested != current.epoch else { throw AuditHistoryError.invalidStatus }
        case .available, .cursorAhead:
            guard let requested, let after, let queried, let queriedRetained, let queriedHead,
                  requested == queried.epoch, queriedRetained <= queriedHead,
                  (disposition == .cursorAhead) == (after > queriedHead) else { throw AuditHistoryError.invalidStatus }
        }
        if let queried, queried.epoch == current.epoch {
            guard f.fields[7] == f.fields[10], retained == queriedRetained, head == queriedHead else { throw AuditHistoryError.invalidStatus }
        }
        return AuditHistoryStatus(fields: f.fields, macID: mac, accountID: account, queryNonce: nonce,
            requestedEpoch: requested, requestedAfter: after, disposition: disposition, current: current,
            currentRetainedAfter: retained, currentHead: head, queried: queried, queriedRetainedAfter: queriedRetained, queriedHead: queriedHead)
    }
}
