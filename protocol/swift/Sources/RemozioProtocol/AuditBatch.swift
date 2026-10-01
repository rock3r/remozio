import Foundation

public enum AuditBatchError: Error { case invalidBatch }

/// One epoch's contiguous page. This value does not establish authenticity, freshness or trust continuity.
public struct AuditBatch: Sendable {
    private let fields: [UInt64: CBORValue]
    public let macID: Data
    public let accountID: Data
    public let journalEpoch: Data
    public let queryNonce: Data
    public let epochCreationGeneration: UInt64
    public let requestedAfter: UInt64
    public let retainedAfter: UInt64
    public let head: UInt64
    public let records: [AuditEventMetadata]
    public var pageAfter: UInt64 { max(requestedAfter, retainedAfter) }
    public var nextAfter: UInt64 { pageAfter + UInt64(records.count) }
    public var hasMore: Bool { nextAfter < head }
    public var retentionGap: Bool { requestedAfter < retainedAfter }
    public func encode(limits: CBORLimits) throws -> Data { try DeterministicCBOR.encode(.map(fields), limits: limits) }

    public static func decode(_ bytes: Data, batchLimits: CBORLimits,
                              recordLimits: CBORLimits, maximumRecords: Int) throws -> AuditBatch {
        guard maximumRecords > 0,
              case let .map(fields) = try DeterministicCBOR.decode(bytes, limits: batchLimits),
              Set(fields.keys) == Set(0...UInt64(9)), fields[0] == .unsigned(1) else { throw AuditBatchError.invalidBatch }
        func uint(_ key: UInt64) throws -> UInt64 {
            guard case let .unsigned(value) = fields[key] else { throw AuditBatchError.invalidBatch }
            return value
        }
        func id(_ key: UInt64, _ size: Int) throws -> Data {
            guard case let .bytes(value) = fields[key], value.count == size else { throw AuditBatchError.invalidBatch }
            return value
        }
        let mac = try id(1, 16), account = try id(2, 16), epoch = try id(3, 16), nonce = try id(8, 32)
        let generation = try uint(4), after = try uint(5), retained = try uint(6), head = try uint(7)
        let start = max(after, retained)
        guard case let .array(rows) = fields[9], after <= head, retained <= head,
              rows.count <= maximumRecords, UInt64(rows.count) <= head - start,
              !rows.isEmpty || start == head else { throw AuditBatchError.invalidBatch }
        var seen = Set<Data>()
        let records = try rows.enumerated().map { index, row -> AuditEventMetadata in
            guard case let .bytes(raw) = row else { throw AuditBatchError.invalidBatch }
            let record = try AuditEventMetadata.decode(raw, limits: recordLimits)
            guard record.macID == mac, record.accountID == account, record.journalEpoch == epoch,
                  record.sequence == start + UInt64(index) + 1, seen.insert(record.eventID).inserted else {
                throw AuditBatchError.invalidBatch
            }
            return record
        }
        return AuditBatch(fields: fields, macID: mac, accountID: account, journalEpoch: epoch, queryNonce: nonce,
            epochCreationGeneration: generation, requestedAfter: after, retainedAfter: retained, head: head, records: records)
    }
}
