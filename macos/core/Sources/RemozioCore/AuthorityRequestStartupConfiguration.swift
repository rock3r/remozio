import CryptoKit
import Darwin
import Foundation
import RemozioProtocol

/// Protected request-service inputs. Provisioning supplies the key pin; runtime never discovers or replaces it.
public struct AuthorityRequestStartupConfiguration: Sendable, CustomStringConvertible {
    public let service: AuthorityServiceConfiguration
    public let keyRecordPath: String
    public let authorityPublicKey: Data
    public let maintenanceIntervalMilliseconds: Int
    public let canonicalBytes: Data
    public var description: String { "AuthorityRequestStartupConfiguration(redacted)" }

    public init(service: AuthorityServiceConfiguration, keyRecordPath: String, authorityPublicKey: Data,
                maintenanceIntervalMilliseconds: Int = 1000) throws {
        let parts = keyRecordPath.dropFirst().split(separator: "/", omittingEmptySubsequences: false)
        guard service.continuityDirectory != nil, service.maximumPayloadBytes > ApprovalMessage.overheadBytes,
              keyRecordPath.hasPrefix("/"), keyRecordPath.utf8.count < Int(PATH_MAX), !parts.isEmpty,
              parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." && !$0.utf8.contains(0) && $0.utf8.count <= 255 }),
              authorityPublicKey.count == 65, authorityPublicKey.first == 4,
              (try? P256.Signing.PublicKey(x963Representation: authorityPublicKey)) != nil,
              (100...60_000).contains(maintenanceIntervalMilliseconds) else {
            throw AuthorityServiceConfigurationError.invalidConfiguration
        }
        self.service = service; self.keyRecordPath = keyRecordPath; self.authorityPublicKey = authorityPublicKey
        self.maintenanceIntervalMilliseconds = maintenanceIntervalMilliseconds
        canonicalBytes = try DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(service.canonicalBytes), 2: .text(keyRecordPath),
            3: .bytes(authorityPublicKey), 4: .unsigned(UInt64(maintenanceIntervalMilliseconds)),
        ]), limits: Self.limits())
    }

    /// Requires a root-private file and protected local ancestors. Parsing alone does not establish provenance.
    public static func load(path: String) throws -> AuthorityRequestStartupConfiguration {
        try decode(ProtectedServiceConfiguration.read(path: path))
    }

    public static func decode(_ bytes: Data) throws -> AuthorityRequestStartupConfiguration {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits()),
              Set(fields.keys) == Set(UInt64(0)...4), fields[0] == .unsigned(1),
              case .bytes(let serviceBytes) = fields[1], case .text(let path) = fields[2],
              case .bytes(let publicKey) = fields[3], case .unsigned(let interval) = fields[4],
              let milliseconds = Int(exactly: interval) else {
            throw AuthorityServiceConfigurationError.invalidConfiguration
        }
        let result = try AuthorityRequestStartupConfiguration(service: AuthorityServiceConfiguration.decode(serviceBytes),
            keyRecordPath: path, authorityPublicKey: publicKey, maintenanceIntervalMilliseconds: milliseconds)
        guard result.canonicalBytes == bytes else { throw AuthorityServiceConfigurationError.invalidConfiguration }
        return result
    }
    private static func limits() throws -> CBORLimits {
        try CBORLimits(maxBytes: ProtectedServiceConfiguration.maximumBytes, maxDepth: 1, maxItems: 11)
    }
}
