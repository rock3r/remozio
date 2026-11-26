import Foundation

/// Authority evidence that one authenticated decision did not reach consumption.
public struct DecisionRefusalFrame: Sendable, CustomStringConvertible {
    public enum Reason: UInt64, Sendable { case requestChanged = 1, actionUnavailable = 2 }

    public struct Attempt: Equatable, Sendable {
        public let sessionID: Data
        public let sequence: UInt64

        public init(sessionID: Data, sequence: UInt64) throws {
            guard sessionID.count == 32 else { throw ChannelNegotiationError.rejected }
            self.sessionID = sessionID
            self.sequence = sequence
        }
    }

    public struct Payload: Sendable {
        public let scope: ChannelScope
        public let attempt: Attempt
        public let requestID: Data
        public let requestDigest: Data
        public let decisionFrameDigest: Data
        public let reason: Reason

        public init(scope: ChannelScope, attempt: Attempt, requestID: Data, requestDigest: Data,
                    decisionFrameDigest: Data, reason: Reason) throws {
            guard requestID.count == 16, requestDigest.count == 32, decisionFrameDigest.count == 32 else {
                throw ChannelNegotiationError.rejected
            }
            self.scope = scope; self.attempt = attempt; self.requestID = requestID; self.requestDigest = requestDigest
            self.decisionFrameDigest = decisionFrameDigest; self.reason = reason
        }

        fileprivate func encode() throws -> Data {
            try DeterministicCBOR.encode(.map([0: .unsigned(1),
                1: .array([scope.macID, scope.accountID, scope.phoneID, scope.enrollmentEpoch].map(CBORValue.bytes)),
                2: .bytes(attempt.sessionID), 3: .unsigned(attempt.sequence), 4: .bytes(requestID), 5: .bytes(requestDigest),
                6: .bytes(decisionFrameDigest), 7: .unsigned(reason.rawValue)]), limits: Self.limits)
        }

        fileprivate static func decode(_ bytes: Data) throws -> Self {
            guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits),
                  Set(fields.keys) == Set(UInt64(0)...7), fields[0] == .unsigned(1),
                  case .array(let scope) = fields[1], scope.count == 4,
                  case .bytes(let mac) = scope[0], case .bytes(let account) = scope[1],
                  case .bytes(let phone) = scope[2], case .bytes(let epoch) = scope[3],
                  case .bytes(let session) = fields[2], case .unsigned(let sequence) = fields[3],
                  case .bytes(let requestID) = fields[4], case .bytes(let digest) = fields[5],
                  case .bytes(let decision) = fields[6], case .unsigned(let tag) = fields[7],
                  let reason = Reason(rawValue: tag) else { throw ChannelNegotiationError.rejected }
            return try Self(scope: .init(macID: mac, accountID: account, phoneID: phone, enrollmentEpoch: epoch),
                attempt: .init(sessionID: session, sequence: sequence), requestID: requestID, requestDigest: digest,
                decisionFrameDigest: decision, reason: reason)
        }

        public func signingInput() throws -> Data {
            try DeterministicCBOR.encode(.map([0: .text("dev.remozio.decision-refusal"), 1: .unsigned(1),
                2: .bytes(encode())]), limits: DecisionRefusalFrame.limits)
        }

        private static let limits = try! CBORLimits(maxBytes: 256, maxDepth: 2, maxItems: 21)
    }

    /// Advertised only by a live approval channel capable of handling an authority-signed refusal.
    public static let capability: UInt64 = 129
    public static let maximumBytes = 384
    public let payload: Payload
    public let signature: Data

    public init(payload: Payload, signature: Data) throws {
        guard signature.count == 64 else { throw ChannelNegotiationError.rejected }
        self.payload = payload; self.signature = signature
    }

    public var description: String { "DecisionRefusalFrame(redacted)" }

    public func verify(authorityPublicKey: Data) throws -> Bool {
        P256Verification.verify(signature: signature, publicKey: authorityPublicKey, input: try payload.signingInput())
    }

    public func encode() throws -> Data {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("decision-refusal"),
            2: .bytes(payload.encode()), 3: .bytes(signature)]), limits: Self.limits)
    }

    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits),
              Set(fields.keys) == Set(UInt64(0)...3), fields[0] == .unsigned(1), fields[1] == .text("decision-refusal"),
              case .bytes(let payload) = fields[2], case .bytes(let signature) = fields[3] else {
            throw ChannelNegotiationError.rejected
        }
        let result = try Self(payload: .decode(payload), signature: signature)
        guard try result.encode() == bytes else { throw ChannelNegotiationError.rejected }
        return result
    }

    private static let limits = try! CBORLimits(maxBytes: maximumBytes, maxDepth: 1, maxItems: 9)
}
