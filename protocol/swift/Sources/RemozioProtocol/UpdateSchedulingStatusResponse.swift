import Foundation

public enum UpdateSchedulingStatusError: Error { case invalidMessage }

/// A signed scheduling observation. It grants no admission, dispatch or activation authority.
public struct UpdateSchedulingStatusResponse: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let scope: ChannelScope
    public let queryNonce: Data
    public let updateID: Data
    public let generation: UInt64
    public let revision: UInt64
    public let requestedAction: UpdateSchedulingAction?
    public let controlDigest: Data?
    public static let maximumBytes = 2048
    public static var limits: CBORLimits { get throws { try .init(maxBytes: maximumBytes, maxDepth: 2, maxItems: 32) } }
    public init(scope: ChannelScope, queryNonce: Data, updateID: Data, generation: UInt64, revision: UInt64,
                requestedAction: UpdateSchedulingAction?, controlDigest: Data? = nil) throws {
        guard queryNonce.count == 32, updateID.count == 32, generation > 0, (revision == 0) == (requestedAction == nil),
              controlDigest.map({ $0.count == 32 && requestedAction != nil && revision > 0 }) ?? true else {
            throw UpdateSchedulingStatusError.invalidMessage
        }
        self.scope = scope; self.queryNonce = queryNonce; self.updateID = updateID
        self.generation = generation; self.revision = revision; self.requestedAction = requestedAction; self.controlDigest = controlDigest
    }
    public var description: String { "UpdateSchedulingStatusResponse(redacted)" }
    public var debugDescription: String { description }
    public func encode() throws -> Data {
        try DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(scope.macID), 2: .bytes(scope.accountID), 3: .bytes(scope.phoneID),
            4: .bytes(scope.enrollmentEpoch), 5: .bytes(queryNonce), 6: .bytes(updateID),
            7: .unsigned(generation), 8: .unsigned(revision),
            9: requestedAction.map { .unsigned($0.rawValue) } ?? .null, 10: controlDigest.map(CBORValue.bytes) ?? .null,
        ]), limits: Self.limits)
    }
    public static func decode(_ bytes: Data) throws -> Self {
        guard case let .map(f) = try DeterministicCBOR.decode(bytes, limits: limits),
              Set(f.keys) == Set(UInt64(0)...10), f[0] == .unsigned(1) else { throw UpdateSchedulingStatusError.invalidMessage }
        func data(_ n: UInt64) throws -> Data {
            guard case let .bytes(v) = f[n] else { throw UpdateSchedulingStatusError.invalidMessage }; return v
        }
        func uint(_ n: UInt64) throws -> UInt64 {
            guard case let .unsigned(v) = f[n] else { throw UpdateSchedulingStatusError.invalidMessage }; return v
        }
        let action: UpdateSchedulingAction?
        if f[9] == .null { action = nil }
        else { guard let value = UpdateSchedulingAction(rawValue: try uint(9)) else { throw UpdateSchedulingStatusError.invalidMessage }; action = value }
        let result = try Self(scope: ChannelScope(macID: data(1), accountID: data(2), phoneID: data(3), enrollmentEpoch: data(4)),
            queryNonce: data(5), updateID: data(6), generation: uint(7), revision: uint(8), requestedAction: action,
            controlDigest: f[10] == .null ? nil : data(10))
        guard try result.encode() == bytes else { throw UpdateSchedulingStatusError.invalidMessage }; return result
    }
}

public enum UpdateSchedulingStatusSigningInput {
    public static func make(wireVersion: UInt64, canonicalPayload: Data, inputLimits: CBORLimits) throws -> Data {
        guard wireVersion == 1 else { throw SigningInputError.unsupportedVersion }
        _ = try UpdateSchedulingStatusResponse.decode(canonicalPayload)
        return try DeterministicCBOR.encode(.map([
            0: .text("dev.remozio.update-scheduling-status"), 1: .unsigned(1), 2: .unsigned(1),
            3: .unsigned(1), 4: .bytes(canonicalPayload),
        ]), limits: inputLimits)
    }
}

public enum UpdateSchedulingStatusSignature {
    public static func verify(signature: Data, authorityPublicKey: Data, wireVersion: UInt64,
                              canonicalPayload: Data, inputLimits: CBORLimits) throws -> Bool {
        let input = try UpdateSchedulingStatusSigningInput.make(wireVersion: wireVersion,
            canonicalPayload: canonicalPayload, inputLimits: inputLimits)
        return P256Verification.verify(signature: signature, publicKey: authorityPublicKey, input: input)
    }
}
