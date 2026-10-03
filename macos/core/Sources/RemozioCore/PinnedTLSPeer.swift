import CryptoKit
import Foundation
import Security

public enum TLSPeerPinError: Error { case invalidPin }

/// Checks an enrolled P-256 key and the leaf validity interval during a TLS handshake.
/// The TLS implementation must separately prove key possession and enforce the channel profile.
public struct PinnedTLSPeer: Sendable {
    private let publicKey: Data

    /// Accepts only canonical DER SubjectPublicKeyInfo for a P-256 public key.
    public init(subjectPublicKeyInfo: Data) throws {
        guard subjectPublicKeyInfo.count == 91,
              let key = try? P256.Signing.PublicKey(derRepresentation: subjectPublicKeyInfo),
              key.derRepresentation == subjectPublicKeyInfo else { throw TLSPeerPinError.invalidPin }
        publicKey = key.x963Representation
    }

    /// Uses the presented leaf without invoking system CA trust or network certificate discovery.
    public func accepts(_ trust: SecTrust, at date: Date = Date()) -> Bool {
        guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
              let leaf = chain.first else { return false }
        return accepts(certificate: SecCertificateCopyData(leaf) as Data, at: date)
    }

    public func accepts(certificate encoded: Data, at date: Date = Date()) -> Bool {
        guard date.timeIntervalSinceReferenceDate.isFinite,
              !encoded.isEmpty, encoded.count <= 8_192,
              let certificate = SecCertificateCreateWithData(nil, encoded as CFData),
              let before = SecCertificateCopyNotValidBeforeDate(certificate),
              let after = SecCertificateCopyNotValidAfterDate(certificate),
              CFDateGetAbsoluteTime(before) <= date.timeIntervalSinceReferenceDate,
              date.timeIntervalSinceReferenceDate <= CFDateGetAbsoluteTime(after),
              let key = SecCertificateCopyKey(certificate),
              let attributes = SecKeyCopyAttributes(key) as? [String: Any],
              attributes[kSecAttrKeyType as String] as? String == kSecAttrKeyTypeECSECPrimeRandom as String,
              attributes[kSecAttrKeySizeInBits as String] as? Int == 256,
              let representation = SecKeyCopyExternalRepresentation(key, nil) as Data? else { return false }
        return representation == publicKey
    }
}
