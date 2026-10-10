import Foundation
import Darwin
import LocalAuthentication
import Security

/// Loads one provisioned identity without authentication UI for the lookup. It never creates or discovers another key.
public enum ApprovalTransportIdentity {
    public static func load(configuration: ApprovalTransportConfiguration) throws -> SecIdentity {
        try configuration.requireProcess(realUID: getuid(), effectiveUID: geteuid())
        return try load(configuration: configuration, lookup: { query in
            var result: CFTypeRef?
            let status = SecItemCopyMatching(query, &result)
            return (status, result)
        })
    }

    static func load(configuration: ApprovalTransportConfiguration,
                     lookup: (CFDictionary) -> (OSStatus, CFTypeRef?)) throws -> SecIdentity {
        let context = LAContext()
        context.interactionNotAllowed = true
        let query: [CFString: Any] = [kSecClass: kSecClassIdentity,
            kSecMatchItemList: [configuration.identityReference], kSecReturnRef: true,
            kSecMatchLimit: kSecMatchLimitOne, kSecUseAuthenticationContext: context]
        let (status, result) = lookup(query as CFDictionary)
        guard status == errSecSuccess, let result else { throw ApprovalTransportStartupError.identityUnavailable }
        guard CFGetTypeID(result) == SecIdentityGetTypeID() else { throw ApprovalTransportStartupError.invalidIdentity }
        let identity = result as! SecIdentity
        var key: SecKey?, certificate: SecCertificate?
        guard SecIdentityCopyPrivateKey(identity, &key) == errSecSuccess, let key,
              SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess, let certificate,
              let attributes = SecKeyCopyAttributes(key) as? [String: Any],
              attributes[kSecAttrTokenID as String] as? String == kSecAttrTokenIDSecureEnclave as String,
              attributes[kSecAttrKeyType as String] as? String == kSecAttrKeyTypeECSECPrimeRandom as String,
              attributes[kSecAttrKeySizeInBits as String] as? Int == 256,
              let publicKey = SecKeyCopyPublicKey(key),
              let certificateKey = SecCertificateCopyKey(certificate),
              let publicBytes = SecKeyCopyExternalRepresentation(publicKey, nil) as Data?,
              let certificateBytes = SecKeyCopyExternalRepresentation(certificateKey, nil) as Data?,
              publicBytes == certificateBytes,
              try PinnedTLSPeer(subjectPublicKeyInfo: configuration.identityPublicKeyInfo)
                .accepts(certificate: SecCertificateCopyData(certificate) as Data) else {
            throw ApprovalTransportStartupError.invalidIdentity
        }
        return identity
    }
}
