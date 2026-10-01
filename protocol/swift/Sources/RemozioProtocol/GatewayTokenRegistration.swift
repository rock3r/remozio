import Foundation

public enum GatewayTokenError: Error, Equatable { case invalidFields, unsupportedSchema, invalidBytes, invalidControl }

/// A candidate binding, not enrollment authority. Its challenge must reach the phone through the provider only.
public struct GatewayTokenBinding: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    private let values: [Data]
    public var ownerID: Data { values[0] }
    public var macID: Data { values[1] }
    public var accountID: Data { values[2] }
    public var gatewayID: Data { values[3] }
    public var lifecycleEpoch: Data { values[4] }
    public var phoneID: Data { values[5] }
    public var enrollmentEpoch: Data { values[6] }
    public var candidateID: Data { values[7] }
    public var tokenDigest: Data { values[8] }
    public var challenge: Data { values[9] }
    public var enrollmentTag: Data { values[10] }

    public init(ownerID: Data, macID: Data, accountID: Data, gatewayID: Data, lifecycleEpoch: Data,
                phoneID: Data, enrollmentEpoch: Data, candidateID: Data, tokenDigest: Data, challenge: Data, enrollmentTag: Data) throws {
        let values = [ownerID, macID, accountID, gatewayID, lifecycleEpoch, phoneID, enrollmentEpoch, candidateID,
                      tokenDigest, challenge, enrollmentTag]
        guard values.enumerated().allSatisfy({ $0.element.count == ($0.offset < 8 ? 16 : 32) }) else {
            throw GatewayTokenError.invalidBytes
        }
        self.values = values
    }
    public var description: String { "GatewayTokenBinding(redacted)" }
    public var debugDescription: String { description }
    var value: CBORValue { .map(Dictionary(uniqueKeysWithValues: values.enumerated().map { (UInt64($0.offset), .bytes($0.element)) })) }
    static func decode(_ value: CBORValue) throws -> GatewayTokenBinding {
        guard case let .map(fields) = value, Set(fields.keys) == Set(0...UInt64(10)) else { throw GatewayTokenError.invalidFields }
        func bytes(_ key: UInt64) throws -> Data {
            guard case let .bytes(value) = fields[key] else { throw GatewayTokenError.invalidBytes }
            return value
        }
        return try GatewayTokenBinding(ownerID: bytes(0), macID: bytes(1), accountID: bytes(2), gatewayID: bytes(3),
            lifecycleEpoch: bytes(4), phoneID: bytes(5), enrollmentEpoch: bytes(6), candidateID: bytes(7),
            tokenDigest: bytes(8), challenge: bytes(9), enrollmentTag: bytes(10))
    }
}

/// A root-to-gateway candidate claim. Verification, freshness, replay checks and current trust remain separate.
public struct GatewayTokenCandidate: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let binding: GatewayTokenBinding
    public let revision: UInt64
    public let operationID: Data
    public let issuedAtUnixMillis: UInt64
    public let expiresAtUnixMillis: UInt64
    public init(binding: GatewayTokenBinding, revision: UInt64, operationID: Data,
                issuedAtUnixMillis: UInt64, expiresAtUnixMillis: UInt64) throws {
        guard revision > 0, operationID.count == 16, expiresAtUnixMillis > issuedAtUnixMillis else { throw GatewayTokenError.invalidControl }
        self.binding = binding; self.revision = revision; self.operationID = operationID
        self.issuedAtUnixMillis = issuedAtUnixMillis; self.expiresAtUnixMillis = expiresAtUnixMillis
    }
    public var description: String { "GatewayTokenCandidate(redacted)" }
    public var debugDescription: String { description }
    public func encode(limits: CBORLimits) throws -> Data {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: binding.value, 2: .unsigned(revision), 3: .bytes(operationID),
            4: .unsigned(issuedAtUnixMillis), 5: .unsigned(expiresAtUnixMillis)]), limits: limits)
    }
    public static func decode(_ bytes: Data, limits: CBORLimits) throws -> GatewayTokenCandidate {
        let fields = try gatewayFields(bytes, last: 5, limits: limits)
        guard case let .unsigned(revision) = fields[2], case let .bytes(operationID) = fields[3],
              case let .unsigned(issued) = fields[4], case let .unsigned(expires) = fields[5] else { throw GatewayTokenError.invalidControl }
        return try GatewayTokenCandidate(binding: GatewayTokenBinding.decode(fields[1]!), revision: revision, operationID: operationID,
            issuedAtUnixMillis: issued, expiresAtUnixMillis: expires)
    }
}

/// Receipt of an opaque provider challenge. Authenticate the phone channel and consume the retained candidate separately.
public struct GatewayTokenProof: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let binding: GatewayTokenBinding
    public init(binding: GatewayTokenBinding) { self.binding = binding }
    public var description: String { "GatewayTokenProof(redacted)" }
    public var debugDescription: String { description }
    public func encode(limits: CBORLimits) throws -> Data {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: binding.value]), limits: limits)
    }
    public static func decode(_ bytes: Data, limits: CBORLimits) throws -> GatewayTokenProof {
        let fields = try gatewayFields(bytes, last: 1, limits: limits)
        return try GatewayTokenProof(binding: GatewayTokenBinding.decode(fields[1]!))
    }
}

private func gatewayFields(_ bytes: Data, last: UInt64, limits: CBORLimits) throws -> [UInt64: CBORValue] {
    guard case let .map(fields) = try DeterministicCBOR.decode(bytes, limits: limits),
          Set(fields.keys) == Set(0...last) else { throw GatewayTokenError.invalidFields }
    guard fields[0] == .unsigned(1) else { throw GatewayTokenError.unsupportedSchema }
    return fields
}
