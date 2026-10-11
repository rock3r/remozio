import Foundation
import Security

/// Signature evidence for a candidate bundle. Revalidate protected copies before installation or execution.
public struct SignedReleaseEvidence: Sendable {
    public let manifest: ReleaseManifest
    public let codeDirectoryHashes: [AuthorityCodeRole: Data]
}

public enum SignedReleaseInspection {
    /// The expected identity must come from trusted setup or update policy, never from the candidate manifest.
    /// This check does not establish notarization, installed placement, generation floors, or quiescent activation.
    public static func inspect(_ bundle: URL, teamID: String, appIdentifier: String) throws -> SignedReleaseEvidence {
        guard teamID.utf8.count == 10, teamID.utf8.allSatisfy({ (65...90).contains($0) || (48...57).contains($0) }),
              ReleaseManifest.validToken(appIdentifier) else { throw ReleaseManifestError.invalidDeclaration }
        return try inspect(bundle, expectedAppIdentifier: appIdentifier, expectedTeamID: teamID) { identifier, hash in
            try XPCPeerPolicy(teamID: teamID, componentIdentifier: identifier,
                approvedCodeDirectoryHashes: [hash], expectedUserID: 0).requirement
        }
    }

    /// Internal fixture seam. Production has no caller-supplied signature requirement.
    static func inspect(_ bundle: URL, expectedAppIdentifier: String, expectedTeamID: String?,
                        requirement: (String, Data) throws -> String) throws -> SignedReleaseEvidence {
        let root = bundle.standardizedFileURL
        try noSymlink(root)
        let app = try signedMetadata(root, identifier: expectedAppIdentifier, requirement: requirement)
        guard let declaration = app.plist[ReleaseManifest.infoKey] as? Data,
              declaration.count <= ReleaseManifest.maximumBytes else { throw ReleaseManifestError.missingMetadata }
        let manifest = try ReleaseManifest.decode(declaration)
        guard let appComponent = manifest.components.first(where: { $0.role == .app }),
              let executable = app.plist["CFBundleExecutable"] as? String,
              appComponent.identifier == expectedAppIdentifier, appComponent.relativePath == "Contents/MacOS/" + executable,
              app.plist["CFBundleVersion"] as? String == manifest.build,
              app.plist["CFBundleShortVersionString"] as? String == manifest.release,
              app.plist["LSMinimumSystemVersion"] as? String == "26.0" else { throw ReleaseManifestError.identityMismatch }
        var hashes: [AuthorityCodeRole: Data] = [:]
        for component in manifest.components {
            var path = root
            for segment in component.relativePath.split(separator: "/") {
                path.appendPathComponent(String(segment)); try noSymlink(path)
            }
            try thinArm64(path)
            let metadata = component.role == .app ? app : try signedMetadata(path, identifier: component.identifier, requirement: requirement)
            guard metadata.identifier == component.identifier, metadata.teamID == expectedTeamID,
                  component.teamID == metadata.teamID, metadata.plist["CFBundleVersion"] as? String == component.build,
                  metadata.plist["CFBundleIdentifier"] as? String == component.identifier,
                  metadata.plist["RemozioSecurityGeneration"] as? String == String(component.generation),
                  component.role == .app ? component.build == manifest.build : component.codeDirectoryHash == metadata.hash else {
                throw ReleaseManifestError.identityMismatch
            }
            hashes[component.role] = metadata.hash
        }
        // Check the enclosing seal again after inspecting all nested code. This remains a candidate snapshot.
        let final = try signedMetadata(root, identifier: expectedAppIdentifier, requirement: requirement)
        guard final.hash == app.hash, final.plist[ReleaseManifest.infoKey] as? Data == declaration else {
            throw ReleaseManifestError.identityMismatch
        }
        return SignedReleaseEvidence(manifest: manifest, codeDirectoryHashes: hashes)
    }

    private struct Metadata {
        let identifier: String
        let hash: Data
        let teamID: String?
        let plist: [String: Any]
    }
    private static func signedMetadata(_ url: URL, identifier: String,
                                       requirement: (String, Data) throws -> String) throws -> Metadata {
        var code: SecStaticCode?
        try checked(SecStaticCodeCreateWithPath(url as CFURL, [], &code))
        guard let code else { throw ReleaseManifestError.missingMetadata }
        func information() throws -> [String: Any] {
            var information: CFDictionary?
            try checked(SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &information))
            guard let values = information as? [String: Any] else { throw ReleaseManifestError.missingMetadata }; return values
        }
        // The initial hash only selects a requirement. No metadata is trusted before strict validation.
        guard let candidateHash = try information()[kSecCodeInfoUnique as String] as? Data, candidateHash.count == 20 else {
            throw ReleaseManifestError.missingMetadata
        }
        var compiled: SecRequirement?
        try checked(SecRequirementCreateWithString(try requirement(identifier, candidateHash) as CFString, [], &compiled))
        guard let compiled else { throw ReleaseManifestError.missingMetadata }
        let flags = SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures | kSecCSCheckNestedCode)
        try checked(SecStaticCodeCheckValidity(code, flags, compiled))
        let values = try information()
        guard let actualIdentifier = values[kSecCodeInfoIdentifier as String] as? String, actualIdentifier == identifier,
              let hash = values[kSecCodeInfoUnique as String] as? Data, hash == candidateHash,
              let codeFlags = values[kSecCodeInfoFlags as String] as? NSNumber, codeFlags.uint32Value & 0x10000 != 0,
              let plist = values[kSecCodeInfoPList as String] as? [String: Any] else {
            throw ReleaseManifestError.identityMismatch
        }
        let entitlements = values[kSecCodeInfoEntitlementsDict as String] as? [String: Any] ?? [:]
        guard entitlements.isEmpty || (entitlements.count == 1 && entitlements["com.apple.application-identifier"] as? String == identifier) else {
            throw ReleaseManifestError.identityMismatch
        }
        return Metadata(identifier: actualIdentifier, hash: hash, teamID: values[kSecCodeInfoTeamIdentifier as String] as? String, plist: plist)
    }
    private static func thinArm64(_ url: URL) throws {
        let file = try FileHandle(forReadingFrom: url)
        defer { try? file.close() }
        guard try file.read(upToCount: 8) == Data([0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0, 0, 1]) else {
            throw ReleaseManifestError.identityMismatch
        }
    }
    private static func noSymlink(_ url: URL) throws {
        guard try url.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink == false else { throw ReleaseManifestError.unsafePath }
    }
    private static func checked(_ status: OSStatus) throws {
        guard status == errSecSuccess else { throw ReleaseManifestError.security(status) }
    }
}
