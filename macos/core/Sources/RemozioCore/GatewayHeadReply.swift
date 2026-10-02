import CryptoKit
import Foundation
import RemozioProtocol

public enum GatewayHeadReplyError: Error, Equatable {
    case invalidConfiguration, invalidMessage, unsupportedVersion, wrongScope, invalidSignature, invalidReceipt
    case unknownQuery, expired, capacityExceeded, invalidClock, stopped
}

/// Transport bytes only. Construction does not authenticate either signature or establish freshness.
public struct GatewayHeadReply: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let canonicalPayload: Data
    public let signature: Data
    public init(canonicalPayload: Data, signature: Data) {
        self.canonicalPayload = canonicalPayload; self.signature = signature
    }
    public var description: String { "GatewayHeadReply(redacted)" }
    public var debugDescription: String { description }
}

/// A gateway assertion received for one live query. Local trust-history reconciliation is still required.
public struct VerifiedGatewayHead: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let evidence: GatewayHeadEvidence
    public let receivedAt: AuthorityMoment
    fileprivate init(evidence: GatewayHeadEvidence, receivedAt: AuthorityMoment) {
        self.evidence = evidence; self.receivedAt = receivedAt
    }
    public var description: String { "VerifiedGatewayHead(redacted)" }
    public var debugDescription: String { description }
}

/// Root-side query owner. Serialize all calls with local trust changes; discard it when either pin changes.
/// Neither the transport nor a reply may supply its registration identity or gateway key.
public final class GatewayHeadQueryOwner {
    private let registration: GatewayRegistrationIdentity
    private let gatewayKey: P256.Signing.PublicKey
    private let clockEpoch: UUID
    private let lifetimeMillis: UInt64
    private let maximumQueries: Int
    private var pending: [Data: UInt64] = [:]
    private var lastMoment: UInt64?
    private var stopped = false

    public init(registration: GatewayRegistrationIdentity, gatewayPublicKey: Data, clockEpoch: UUID,
                lifetimeMillis: UInt64 = 30_000, maximumQueries: Int = 8) throws {
        guard (1...60_000).contains(lifetimeMillis), (1...64).contains(maximumQueries),
              gatewayPublicKey.count == 65, gatewayPublicKey.first == 4,
              let key = try? P256.Signing.PublicKey(x963Representation: gatewayPublicKey) else {
            throw GatewayHeadReplyError.invalidConfiguration
        }
        self.registration = registration; gatewayKey = key; self.clockEpoch = clockEpoch
        self.lifetimeMillis = lifetimeMillis; self.maximumQueries = maximumQueries
    }

    public func makeQuery(now: AuthorityMoment) throws -> Data {
        try clock(now)
        pending = pending.filter { now.milliseconds < $0.value }
        guard pending.count < maximumQueries else { throw GatewayHeadReplyError.capacityExceeded }
        let (deadline, overflow) = now.milliseconds.addingReportingOverflow(lifetimeMillis)
        guard !overflow else { throw GatewayHeadReplyError.invalidClock }
        let nonce = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
        guard pending[nonce] == nil else { throw GatewayHeadReplyError.capacityExceeded }
        let query = try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .unsigned(0),
            2: .bytes(registration.encode()), 3: .bytes(nonce)]), limits: GatewayHeadWire.queryLimits)
        pending[nonce] = deadline
        return query
    }

    public func accept(_ reply: GatewayHeadReply, now: AuthorityMoment) throws -> VerifiedGatewayHead {
        try clock(now)
        guard reply.signature.count == 64, reply.canonicalPayload.count <= GatewayHeadWire.replyLimits.maxBytes,
              let signature = try? P256.Signing.ECDSASignature(rawRepresentation: reply.signature),
              gatewayKey.isValidSignature(signature, for: GatewayHeadWire.signingInput(reply.canonicalPayload)) else {
            throw GatewayHeadReplyError.invalidSignature
        }
        let fields = try GatewayHeadWire.fields(reply.canonicalPayload, kind: 1, lastKey: 7, limits: GatewayHeadWire.replyLimits)
        guard try GatewayHeadWire.bytes(fields, 2) == registration.encode() else { throw GatewayHeadReplyError.wrongScope }
        let nonce = try GatewayHeadWire.bytes(fields, 3)
        guard nonce.count == 32, let deadline = pending[nonce] else { throw GatewayHeadReplyError.unknownQuery }
        guard now.milliseconds < deadline else {
            pending.removeValue(forKey: nonce)
            throw GatewayHeadReplyError.expired
        }
        guard case let .unsigned(revision) = fields[4], case let .unsigned(kind) = fields[5] else {
            throw GatewayHeadReplyError.invalidMessage
        }
        let payload = try GatewayHeadWire.bytes(fields, 6), rootSignature = try GatewayHeadWire.bytes(fields, 7)
        let receipt = try GatewayHeadWire.receipt(kind: kind, payload: payload, signature: rootSignature,
            revision: revision, registration: registration)
        pending.removeValue(forKey: nonce)
        return VerifiedGatewayHead(evidence: GatewayHeadEvidence(registration: registration, revision: revision, receipt: receipt), receivedAt: now)
    }

    /// Trust changes, service shutdown, or key replacement invalidate every in-flight query.
    public func invalidate() { stopped = true; pending.removeAll() }

    private func clock(_ now: AuthorityMoment) throws {
        guard !stopped else { throw GatewayHeadReplyError.stopped }
        guard now.epoch == clockEpoch, lastMoment.map({ now.milliseconds >= $0 }) ?? true else {
            invalidate(); throw GatewayHeadReplyError.invalidClock
        }
        lastMoment = now.milliseconds
    }
}

extension GatewayDatabase {
    /// Call only after authenticating the registered caller. The signer is the gateway's separately pinned key.
    /// The service serializes this read with control application. No private token is included in the reply.
    public func headReply(canonicalQuery: Data, sign: (Data) throws -> Data) throws -> GatewayHeadReply {
        let fields = try GatewayHeadWire.fields(canonicalQuery, kind: 0, lastKey: 3, limits: GatewayHeadWire.queryLimits)
        let nonce = try GatewayHeadWire.bytes(fields, 3)
        guard nonce.count == 32 else { throw GatewayHeadReplyError.invalidMessage }
        let evidence = try headEvidence()
        guard try GatewayHeadWire.bytes(fields, 2) == evidence.registration.encode() else { throw GatewayHeadReplyError.wrongScope }
        let kind: UInt64
        switch evidence.receipt {
        case .candidate: kind = 1
        case .recipient(let value): kind = value.kind.rawValue
        case nil: kind = 0
        }
        let payload = try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .unsigned(1),
            2: .bytes(evidence.registration.encode()), 3: .bytes(nonce), 4: .unsigned(evidence.revision),
            5: .unsigned(kind), 6: .bytes(evidence.receipt?.canonicalPayload ?? Data()),
            7: .bytes(evidence.receipt?.signature ?? Data())]), limits: GatewayHeadWire.replyLimits)
        let signature = try sign(GatewayHeadWire.signingInput(payload))
        guard signature.count == 64 else { throw GatewayHeadReplyError.invalidSignature }
        return GatewayHeadReply(canonicalPayload: payload, signature: signature)
    }
}

private enum GatewayHeadWire {
    static let queryLimits = try! CBORLimits(maxBytes: 1024, maxDepth: 4, maxItems: 32)
    static let replyLimits = try! CBORLimits(maxBytes: 70_000, maxDepth: 4, maxItems: 32)
    static let receiptLimits = try! CBORLimits(maxBytes: 65_536, maxDepth: 8, maxItems: 128)
    static let signingLimits = try! CBORLimits(maxBytes: 131_072, maxDepth: 8, maxItems: 128)

    static func signingInput(_ payload: Data) -> Data {
        Data("Remozio/GatewayHeadReply/v1\u{0}".utf8) + payload
    }
    static func fields(_ payload: Data, kind: UInt64, lastKey: UInt64, limits: CBORLimits) throws -> [UInt64: CBORValue] {
        guard case let .map(fields) = try DeterministicCBOR.decode(payload, limits: limits), Set(fields.keys) == Set(0...lastKey) else {
            throw GatewayHeadReplyError.invalidMessage
        }
        guard fields[0] == .unsigned(1) else { throw GatewayHeadReplyError.unsupportedVersion }
        guard fields[1] == .unsigned(kind) else { throw GatewayHeadReplyError.invalidMessage }
        return fields
    }
    static func bytes(_ fields: [UInt64: CBORValue], _ key: UInt64) throws -> Data {
        guard case let .bytes(value) = fields[key] else { throw GatewayHeadReplyError.invalidMessage }
        return value
    }
    static func receipt(kind: UInt64, payload: Data, signature: Data, revision: UInt64,
                        registration: GatewayRegistrationIdentity) throws -> GatewayControlReceipt? {
        if revision == 0 {
            guard kind == 0, payload.isEmpty, signature.isEmpty else { throw GatewayHeadReplyError.invalidReceipt }
            return nil
        }
        guard signature.count == 64 else { throw GatewayHeadReplyError.invalidReceipt }
        do {
            if kind == 1 {
                let candidate = try GatewayTokenCandidate.decode(payload, limits: receiptLimits)
                guard candidate.revision == revision, registration.matches(candidate.binding),
                      try GatewayTokenCandidateSignature.verify(signature: signature, publicKey: registration.rootPublicKey,
                        wireVersion: 1, canonicalPayload: payload, payloadLimits: receiptLimits, inputLimits: signingLimits) else {
                    throw GatewayHeadReplyError.invalidReceipt
                }
                return .candidate(GatewayCandidateReceipt(candidate: candidate, canonicalPayload: payload, signature: signature))
            }
            guard let kind = GatewayRecipientKind(rawValue: kind) else { throw GatewayHeadReplyError.invalidReceipt }
            let control = try GatewayStoredRecipient.decode(payload, kind: kind, limits: receiptLimits)
            guard control.revision == revision, control.matches(registration),
                  try GatewayRecipientSignature.verify(signature: signature, publicKey: registration.rootPublicKey,
                    wireVersion: 1, kind: kind, canonicalPayload: payload, payloadLimits: receiptLimits, inputLimits: signingLimits) else {
                throw GatewayHeadReplyError.invalidReceipt
            }
            return .recipient(GatewayRecipientReceipt(control: control, canonicalPayload: payload, signature: signature))
        } catch { throw GatewayHeadReplyError.invalidReceipt }
    }
}
