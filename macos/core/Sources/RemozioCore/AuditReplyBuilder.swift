import CryptoKit
import Foundation
import RemozioProtocol

public enum AuditReplyError: Error, Equatable {
    case invalidScope, invalidQuery, invalidBounds, invalidAuthorityKey
    case scopeMismatch, epochMismatch, reconciliationRequired, invalidSignature
}

/// A coherent read from one account's journal. The caller obtains all reads for a reply in one transaction.
public struct AuditEpochRead: Sendable {
    public let descriptor: AuditEpochDescriptor
    public let retainedAfter: UInt64
    public let head: UInt64
    public init(descriptor: AuditEpochDescriptor, retainedAfter: UInt64, head: UInt64) throws {
        guard retainedAfter <= head else { throw AuditReplyError.invalidBounds }
        self.descriptor = descriptor; self.retainedAfter = retainedAfter; self.head = head
    }
}

public struct AuditHistoryRequest: Sendable {
    public let nonce: Data
    public let epoch: Data?
    public let after: UInt64?
    public init(nonce: Data, epoch: Data?, after: UInt64?) throws {
        guard nonce.count == 32, (epoch == nil) == (after == nil), epoch == nil || epoch?.count == 16 else {
            throw AuditReplyError.invalidQuery
        }
        self.nonce = nonce; self.epoch = epoch; self.after = after
    }
}

public struct AuditPageRequest: Sendable {
    public let nonce: Data
    public let epoch: Data
    public let generation: UInt64
    public let after: UInt64
    public init(nonce: Data, epoch: Data, generation: UInt64, after: UInt64) throws {
        guard nonce.count == 32, epoch.count == 16 else { throw AuditReplyError.invalidQuery }
        self.nonce = nonce; self.epoch = epoch; self.generation = generation; self.after = after
    }
}

public struct AuditReplyLimits: Sendable {
    public let batch: CBORLimits
    public let record: CBORLimits
    public let history: CBORLimits
    public let descriptor: CBORLimits
    public let signing: CBORLimits
    public let maximumRecords: Int
    public init(batch: CBORLimits, record: CBORLimits, history: CBORLimits, descriptor: CBORLimits,
                signing: CBORLimits, maximumRecords: Int) throws {
        guard maximumRecords > 0 else { throw AuditReplyError.invalidBounds }
        self.batch = batch; self.record = record; self.history = history; self.descriptor = descriptor
        self.signing = signing; self.maximumRecords = maximumRecords
    }
}

public enum AuditReplyKind: Equatable, Sendable { case page, history }
public struct SignedAuditReply: Sendable {
    public let kind: AuditReplyKind
    public let wireVersion: UInt64
    public let canonicalBody: Data
    public let signature: Data
}

/// Builds bounded, audit-only replies after the service authorizes the enrolled phone and account.
/// It does not establish channel authorization, read a journal, select current trust or write history.
public struct AuditReplyBuilder {
    private let macID: Data
    private let accountID: Data
    private let authorityPublicKey: Data
    private let limits: AuditReplyLimits
    private let signer: (Data) throws -> Data

    /// The signer signs these bytes with P-256/SHA-256 once and returns raw 64-byte R||S.
    /// Production supplies the non-exportable authority key. The expected public key comes from local trust.
    public init(macID: Data, accountID: Data, authorityPublicKey: Data, limits: AuditReplyLimits,
                signer: @escaping (Data) throws -> Data) throws {
        guard macID.count == 16, accountID.count == 16 else { throw AuditReplyError.invalidScope }
        guard authorityPublicKey.count == 65, authorityPublicKey.first == 4,
              (try? P256.Signing.PublicKey(x963Representation: authorityPublicKey)) != nil else {
            throw AuditReplyError.invalidAuthorityKey
        }
        self.macID = macID; self.accountID = accountID; self.authorityPublicKey = authorityPublicKey
        self.limits = limits; self.signer = signer
    }

    /// Records are one bounded contiguous page, never an entire journal loaded for pagination.
    public func page(_ query: AuditPageRequest, epoch: AuditEpochRead, canonicalRecords: [Data]) throws -> SignedAuditReply {
        try checkScope(epoch)
        guard query.epoch == epoch.descriptor.epoch, query.generation == epoch.descriptor.generation else {
            throw AuditReplyError.epochMismatch
        }
        guard query.after <= epoch.head else { throw AuditReplyError.reconciliationRequired }
        guard canonicalRecords.count <= limits.maximumRecords else { throw AuditReplyError.invalidBounds }
        var recordBytes = 0
        for record in canonicalRecords {
            guard record.count <= limits.record.maxBytes, record.count <= limits.batch.maxBytes - recordBytes else {
                throw AuditReplyError.invalidBounds
            }
            recordBytes += record.count
        }
        let body = try DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(macID), 2: .bytes(accountID), 3: .bytes(query.epoch),
            4: .unsigned(query.generation), 5: .unsigned(query.after), 6: .unsigned(epoch.retainedAfter),
            7: .unsigned(epoch.head), 8: .bytes(query.nonce), 9: .array(canonicalRecords.map(CBORValue.bytes)),
        ]), limits: limits.batch)
        _ = try AuditBatch.decode(body, batchLimits: limits.batch, recordLimits: limits.record, maximumRecords: limits.maximumRecords)
        return try sign(body, kind: .page)
    }

    /// A nil queried read means an old epoch is unavailable. The current epoch always uses its current read.
    public func history(_ query: AuditHistoryRequest, current: AuditEpochRead, queried supplied: AuditEpochRead? = nil) throws -> SignedAuditReply {
        try checkScope(current)
        if let supplied { try checkScope(supplied) }
        let queried: AuditEpochRead?
        let disposition: AuditHistoryDisposition
        if let requested = query.epoch {
            if requested == current.descriptor.epoch {
                if let supplied {
                    guard try supplied.descriptor.encode(limits: limits.descriptor) == current.descriptor.encode(limits: limits.descriptor),
                          supplied.retainedAfter == current.retainedAfter, supplied.head == current.head else {
                        throw AuditReplyError.epochMismatch
                    }
                }
                queried = current
            } else {
                guard supplied == nil || supplied?.descriptor.epoch == requested else { throw AuditReplyError.epochMismatch }
                queried = supplied
            }
            if let queried { disposition = query.after! > queried.head ? .cursorAhead : .available }
            else { disposition = .unavailable }
        } else {
            guard supplied == nil else { throw AuditReplyError.invalidQuery }
            queried = nil; disposition = .discovery
        }
        let body = try DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(macID), 2: .bytes(accountID), 3: .bytes(query.nonce),
            4: query.epoch.map(CBORValue.bytes) ?? .null, 5: query.after.map(CBORValue.unsigned) ?? .null,
            6: .unsigned(disposition.rawValue), 7: .bytes(try current.descriptor.encode(limits: limits.descriptor)),
            8: .unsigned(current.retainedAfter), 9: .unsigned(current.head),
            10: try queried.map { .bytes(try $0.descriptor.encode(limits: limits.descriptor)) } ?? .null,
            11: queried.map { .unsigned($0.retainedAfter) } ?? .null, 12: queried.map { .unsigned($0.head) } ?? .null,
        ]), limits: limits.history)
        _ = try AuditHistoryStatus.decode(body, limits: limits.history, descriptorLimits: limits.descriptor)
        return try sign(body, kind: .history)
    }

    private func checkScope(_ epoch: AuditEpochRead) throws {
        guard epoch.descriptor.macID == macID, epoch.descriptor.accountID == accountID else { throw AuditReplyError.scopeMismatch }
    }

    private func sign(_ body: Data, kind: AuditReplyKind) throws -> SignedAuditReply {
        let input: Data
        switch kind {
        case .page: input = try AuditBatchSigningInput.make(wireVersion: 1, canonicalPayload: body,
            payloadLimits: limits.batch, inputLimits: limits.signing)
        case .history: input = try AuditHistoryStatusSigningInput.make(wireVersion: 1, canonicalPayload: body,
            payloadLimits: limits.history, inputLimits: limits.signing)
        }
        let signature = try signer(input)
        let valid: Bool
        switch kind {
        case .page: valid = try AuditBatchSignature.verify(signature: signature, publicKey: authorityPublicKey, wireVersion: 1,
            canonicalPayload: body, payloadLimits: limits.batch, inputLimits: limits.signing)
        case .history: valid = try AuditHistoryStatusSignature.verify(signature: signature, publicKey: authorityPublicKey, wireVersion: 1,
            canonicalPayload: body, payloadLimits: limits.history, inputLimits: limits.signing)
        }
        guard valid else { throw AuditReplyError.invalidSignature }
        return SignedAuditReply(kind: kind, wireVersion: 1, canonicalBody: body, signature: signature)
    }
}
