import Foundation
import Security

public enum SignedExecutableValidationError: Error, Equatable {
    case invalidPolicy, missingMetadata, unsafeRuntime, invalidGeneration, rollback
    case security(OSStatus)
}

/// Evidence for one protected executable. It is not a durable activation record or an execution permit.
public struct SignedExecutableEvidence: Sendable {
    public let identifier: String
    public let codeDirectoryHash: Data
    public let generation: UInt64
}

public enum SignedExecutableValidation {
    /// Policy and generations must come from the trusted installation boundary, never from the candidate.
    public static func validate(_ path: ProtectedExecutablePath, policy: XPCPeerPolicy,
                                committedFloor: UInt64, installedGeneration: UInt64) throws -> SignedExecutableEvidence {
        try validate(path, requirement: policy.requirement, committedFloor: committedFloor, installedGeneration: installedGeneration)
    }

    /// Internal ad-hoc fixture entry point. Production callers must supply XPCPeerPolicy.
    static func validate(_ path: ProtectedExecutablePath, requirement expression: String,
                         committedFloor: UInt64, installedGeneration: UInt64) throws -> SignedExecutableEvidence {
        guard committedFloor > 0 else { throw SignedExecutableValidationError.invalidPolicy }
        try path.validate()
        do {
            var requirement: SecRequirement?
            try checked(SecRequirementCreateWithString(expression as CFString, [], &requirement))
            guard let requirement else { throw SignedExecutableValidationError.invalidPolicy }
            var candidate: SecStaticCode?
            try checked(SecStaticCodeCreateWithPath(URL(fileURLWithPath: path.path) as CFURL, [], &candidate))
            guard let candidate else { throw SignedExecutableValidationError.missingMetadata }
            let flags = SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures)
            try checked(SecStaticCodeCheckValidity(candidate, flags, requirement))
            var information: CFDictionary?
            try checked(SecCodeCopySigningInformation(candidate, SecCSFlags(rawValue: kSecCSSigningInformation), &information))
            guard let values = information as? [String: Any],
                  let identifier = values[kSecCodeInfoIdentifier as String] as? String,
                  let hash = values[kSecCodeInfoUnique as String] as? Data, hash.count == 20,
                  let flags = values[kSecCodeInfoFlags as String] as? NSNumber,
                  let plist = values[kSecCodeInfoPList as String] as? [String: Any] else {
                throw SignedExecutableValidationError.missingMetadata
            }
            // CSCommon.h defines kSecCodeSignatureRuntime as 0x10000; Swift does not import the constant.
            guard flags.uint32Value & 0x10000 != 0 else {
                throw SignedExecutableValidationError.unsafeRuntime
            }
            let generation = try validatedGeneration(plist["RemozioSecurityGeneration"],
                committedFloor: committedFloor, installedGeneration: installedGeneration)
            try path.validate()
            return SignedExecutableEvidence(identifier: identifier, codeDirectoryHash: hash, generation: generation)
        } catch {
            path.close()
            throw error
        }
    }

    static func validatedGeneration(_ value: Any?, committedFloor: UInt64, installedGeneration: UInt64) throws -> UInt64 {
        guard committedFloor > 0 else { throw SignedExecutableValidationError.invalidPolicy }
        guard let text = value as? String, !text.isEmpty, text.utf8.count <= 20,
              text.utf8.allSatisfy({ (48...57).contains($0) }), text.first != "0",
              let generation = UInt64(text), generation > 0 else { throw SignedExecutableValidationError.invalidGeneration }
        guard generation >= committedFloor, generation >= installedGeneration else { throw SignedExecutableValidationError.rollback }
        return generation
    }
    private static func checked(_ status: OSStatus) throws {
        guard status == errSecSuccess else { throw SignedExecutableValidationError.security(status) }
    }
}
