import Foundation

public enum GatewayRecipientKind: UInt64, Sendable { case activation = 2, phoneRevocation = 3 }

/// Identifies one enrolled phone epoch within one registered gateway lifecycle.
public struct GatewayPhoneEpochBinding: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    private let values: [Data]
    public var ownerID: Data { values[0] }
    public var macID: Data { values[1] }
    public var accountID: Data { values[2] }
    public var gatewayID: Data { values[3] }
    public var lifecycleEpoch: Data { values[4] }
    public var phoneID: Data { values[5] }
    public var enrollmentEpoch: Data { values[6] }
    public init(ownerID: Data, macID: Data, accountID: Data, gatewayID: Data, lifecycleEpoch: Data, phoneID: Data, enrollmentEpoch: Data) throws {
        let values = [ownerID, macID, accountID, gatewayID, lifecycleEpoch, phoneID, enrollmentEpoch]
        guard values.allSatisfy({ $0.count == 16 }) else { throw GatewayTokenError.invalidBytes }
        self.values = values
    }
    public var description: String { "GatewayPhoneEpochBinding(redacted)" }
    public var debugDescription: String { description }
    fileprivate var value: CBORValue { .map(Dictionary(uniqueKeysWithValues: values.enumerated().map { (UInt64($0.offset), .bytes($0.element)) })) }
    fileprivate static func decode(_ value: CBORValue) throws -> GatewayPhoneEpochBinding {
        guard case let .map(fields) = value, Set(fields.keys) == Set(0...UInt64(6)) else { throw GatewayTokenError.invalidFields }
        func bytes(_ key: UInt64) throws -> Data {
            guard case let .bytes(value) = fields[key] else { throw GatewayTokenError.invalidBytes }
            return value
        }
        return try GatewayPhoneEpochBinding(ownerID: bytes(0), macID: bytes(1), accountID: bytes(2), gatewayID: bytes(3),
            lifecycleEpoch: bytes(4), phoneID: bytes(5), enrollmentEpoch: bytes(6))
    }
}

/// A root claim for a previously verified candidate. Current trust, candidate expiry and one-time consumption remain separate checks.
public struct GatewayMappingActivation: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let binding: GatewayTokenBinding
    public let revision: UInt64
    public let operationID: Data
    public let issuedAtUnixMillis: UInt64
    public let expiresAtUnixMillis: UInt64
    public init(binding: GatewayTokenBinding, revision: UInt64, operationID: Data, issuedAtUnixMillis: UInt64, expiresAtUnixMillis: UInt64) throws {
        try validateRecipientMetadata(revision, operationID, issuedAtUnixMillis, expiresAtUnixMillis)
        self.binding = binding; self.revision = revision; self.operationID = operationID
        self.issuedAtUnixMillis = issuedAtUnixMillis; self.expiresAtUnixMillis = expiresAtUnixMillis
    }
    public var description: String { "GatewayMappingActivation(redacted)" }
    public var debugDescription: String { description }
    public func encode(limits: CBORLimits) throws -> Data {
        try encodeRecipient(binding.value, revision, operationID, issuedAtUnixMillis, expiresAtUnixMillis, .activation, limits)
    }
    public static func decode(_ bytes: Data, limits: CBORLimits) throws -> GatewayMappingActivation {
        let fields = try recipientFields(bytes, .activation, limits)
        let metadata = try recipientMetadata(fields)
        return try GatewayMappingActivation(binding: GatewayTokenBinding.decode(fields[1]!), revision: metadata.0, operationID: metadata.1,
            issuedAtUnixMillis: metadata.2, expiresAtUnixMillis: metadata.3)
    }
}

/// A root revocation claim for one phone epoch. Applying it requires durable tombstones and current registration verification.
public struct GatewayPhoneRevocation: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let binding: GatewayPhoneEpochBinding
    public let revision: UInt64
    public let operationID: Data
    public let issuedAtUnixMillis: UInt64
    public let expiresAtUnixMillis: UInt64
    public init(binding: GatewayPhoneEpochBinding, revision: UInt64, operationID: Data, issuedAtUnixMillis: UInt64, expiresAtUnixMillis: UInt64) throws {
        try validateRecipientMetadata(revision, operationID, issuedAtUnixMillis, expiresAtUnixMillis)
        self.binding = binding; self.revision = revision; self.operationID = operationID
        self.issuedAtUnixMillis = issuedAtUnixMillis; self.expiresAtUnixMillis = expiresAtUnixMillis
    }
    public var description: String { "GatewayPhoneRevocation(redacted)" }
    public var debugDescription: String { description }
    public func encode(limits: CBORLimits) throws -> Data {
        try encodeRecipient(binding.value, revision, operationID, issuedAtUnixMillis, expiresAtUnixMillis, .phoneRevocation, limits)
    }
    public static func decode(_ bytes: Data, limits: CBORLimits) throws -> GatewayPhoneRevocation {
        let fields = try recipientFields(bytes, .phoneRevocation, limits)
        let metadata = try recipientMetadata(fields)
        return try GatewayPhoneRevocation(binding: GatewayPhoneEpochBinding.decode(fields[1]!), revision: metadata.0, operationID: metadata.1,
            issuedAtUnixMillis: metadata.2, expiresAtUnixMillis: metadata.3)
    }
}

private func validateRecipientMetadata(_ revision: UInt64, _ operation: Data, _ issued: UInt64, _ expires: UInt64) throws {
    guard revision > 0, operation.count == 16, expires > issued else { throw GatewayTokenError.invalidControl }
}
private func encodeRecipient(_ binding: CBORValue, _ revision: UInt64, _ operation: Data, _ issued: UInt64,
                             _ expires: UInt64, _ kind: GatewayRecipientKind, _ limits: CBORLimits) throws -> Data {
    try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: binding, 2: .unsigned(revision), 3: .bytes(operation),
        4: .unsigned(issued), 5: .unsigned(expires), 6: .unsigned(kind.rawValue)]), limits: limits)
}
private func recipientFields(_ bytes: Data, _ kind: GatewayRecipientKind, _ limits: CBORLimits) throws -> [UInt64: CBORValue] {
    guard case let .map(fields) = try DeterministicCBOR.decode(bytes, limits: limits), Set(fields.keys) == Set(0...UInt64(6)) else {
        throw GatewayTokenError.invalidFields
    }
    guard fields[0] == .unsigned(1) else { throw GatewayTokenError.unsupportedSchema }
    guard fields[6] == .unsigned(kind.rawValue) else { throw GatewayTokenError.invalidControl }
    return fields
}
private func recipientMetadata(_ fields: [UInt64: CBORValue]) throws -> (UInt64, Data, UInt64, UInt64) {
    guard case let .unsigned(revision) = fields[2], case let .bytes(operation) = fields[3],
          case let .unsigned(issued) = fields[4], case let .unsigned(expires) = fields[5] else { throw GatewayTokenError.invalidControl }
    return (revision, operation, issued, expires)
}
