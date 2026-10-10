import Foundation

public enum GatewaySubmissionKind: UInt64, Sendable { case rotation = 4, revocation = 5 }

/// Identifies one protected gateway registration. Incoming fields cannot establish that registration.
public struct GatewaySubmissionBinding: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    private let bytes: [Data]
    public var ownerID: Data { bytes[0] }
    public var macID: Data { bytes[1] }
    public var accountID: Data { bytes[2] }
    public var gatewayID: Data { bytes[3] }
    public var lifecycleEpoch: Data { bytes[4] }
    public init(ownerID: Data, macID: Data, accountID: Data, gatewayID: Data, lifecycleEpoch: Data) throws {
        let values = [ownerID, macID, accountID, gatewayID, lifecycleEpoch]
        guard values.allSatisfy({ $0.count == 16 }) else { throw GatewayTokenError.invalidBytes }
        bytes = values
    }
    public var description: String { "GatewaySubmissionBinding(redacted)" }
    public var debugDescription: String { description }
    fileprivate var value: CBORValue {
        .map(Dictionary(uniqueKeysWithValues: bytes.enumerated().map { (UInt64($0.offset), .bytes($0.element)) }))
    }
    fileprivate static func decode(_ value: CBORValue) throws -> Self {
        guard case .map(let fields) = value, Set(fields.keys) == Set(UInt64(0)...4) else { throw GatewayTokenError.invalidFields }
        func blob(_ key: UInt64) throws -> Data {
            guard case .bytes(let value) = fields[key] else { throw GatewayTokenError.invalidBytes }; return value
        }
        return try Self(ownerID: blob(0), macID: blob(1), accountID: blob(2), gatewayID: blob(3), lifecycleEpoch: blob(4))
    }
}

/// A Root claim to replace or revoke a wake-only credential. Durable application and current trust remain separate checks.
public struct GatewaySubmissionControl: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let kind: GatewaySubmissionKind
    public let binding: GatewaySubmissionBinding
    public let revision: UInt64
    public let operationID: Data
    public let issuedAtUnixMillis: UInt64
    public let expiresAtUnixMillis: UInt64
    public let credentialID: Data
    public let publicKey: Data?
    public init(kind: GatewaySubmissionKind, binding: GatewaySubmissionBinding, revision: UInt64, operationID: Data,
                issuedAtUnixMillis: UInt64, expiresAtUnixMillis: UInt64, credentialID: Data, publicKey: Data?) throws {
        guard revision > 0, operationID.count == 16, credentialID.count == 16, expiresAtUnixMillis > issuedAtUnixMillis else {
            throw GatewayTokenError.invalidControl
        }
        switch kind {
        case .rotation:
            guard let publicKey, publicKey.count == 65, publicKey.first == 4 else { throw GatewayTokenError.invalidBytes }
        case .revocation:
            guard publicKey == nil else { throw GatewayTokenError.invalidControl }
        }
        self.kind = kind; self.binding = binding; self.revision = revision; self.operationID = operationID
        self.issuedAtUnixMillis = issuedAtUnixMillis; self.expiresAtUnixMillis = expiresAtUnixMillis
        self.credentialID = credentialID; self.publicKey = publicKey
    }
    public var description: String { "GatewaySubmissionControl(redacted)" }
    public var debugDescription: String { description }
    public func encode(limits: CBORLimits) throws -> Data {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: binding.value, 2: .unsigned(revision), 3: .bytes(operationID),
            4: .unsigned(issuedAtUnixMillis), 5: .unsigned(expiresAtUnixMillis), 6: .unsigned(kind.rawValue),
            7: .bytes(credentialID), 8: publicKey.map { .bytes($0) } ?? .null]), limits: limits)
    }
    public static func decode(_ bytes: Data, limits: CBORLimits) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits), Set(fields.keys) == Set(UInt64(0)...8) else {
            throw GatewayTokenError.invalidFields
        }
        guard fields[0] == .unsigned(1) else { throw GatewayTokenError.unsupportedSchema }
        func uint(_ key: UInt64) throws -> UInt64 {
            guard case .unsigned(let value) = fields[key] else { throw GatewayTokenError.invalidControl }; return value
        }
        func blob(_ key: UInt64) throws -> Data {
            guard case .bytes(let value) = fields[key] else { throw GatewayTokenError.invalidBytes }; return value
        }
        guard let kind = GatewaySubmissionKind(rawValue: try uint(6)) else { throw GatewayTokenError.invalidControl }
        let publicKey: Data?
        switch fields[8] {
        case .null: publicKey = nil
        case .bytes(let value): publicKey = value
        default: throw GatewayTokenError.invalidBytes
        }
        return try Self(kind: kind, binding: GatewaySubmissionBinding.decode(fields[1]!), revision: uint(2), operationID: blob(3),
            issuedAtUnixMillis: uint(4), expiresAtUnixMillis: uint(5), credentialID: blob(7), publicKey: publicKey)
    }
}
