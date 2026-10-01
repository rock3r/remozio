import Foundation
import Security
import Synchronization

/// Provider credentials belong to the dedicated push service, separate from approval identity keys.
/// Import does not persist a key or contact a provider. The setup controller supplies the JSON explicitly.
public struct FCMServiceAccount: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    private let email: String
    private let keyID: String
    private let key: Signer
    static let tokenEndpoint = "https://oauth2.googleapis.com/token"
    static let scope = "https://www.googleapis.com/auth/firebase.messaging"

    public init(json: Data) throws {
        guard !json.isEmpty, json.count <= 65536,
              let fields = try? JSONDecoder().decode(Fields.self, from: json),
              fields.type == "service_account", fields.token_uri == Self.tokenEndpoint,
              Self.printable(fields.client_email, maximum: 254), fields.client_email.contains("@"),
              Self.printable(fields.private_key_id, maximum: 256) else { throw FCMError.invalidCredentials }
        self.key = Signer(try Self.importKey(fields.private_key))
        self.email = fields.client_email; self.keyID = fields.private_key_id
    }

    public var description: String { "FCMServiceAccount(redacted)" }
    public var debugDescription: String { description }

    func assertion(at date: Date, lifetimeSeconds: UInt32) throws -> String {
        let seconds = date.timeIntervalSince1970
        guard seconds.isFinite, seconds >= 0, seconds <= 253_402_297_199,
              (1...3600).contains(lifetimeSeconds) else { throw FCMError.invalidTime }
        let issued = Int64(seconds.rounded(.down))
        let header = try JSONSerialization.data(withJSONObject: ["alg": "RS256", "typ": "JWT", "kid": keyID], options: [.sortedKeys])
        let claims = try JSONSerialization.data(withJSONObject: ["iss": email, "scope": Self.scope, "aud": Self.tokenEndpoint,
            "iat": issued, "exp": issued + Int64(lifetimeSeconds)], options: [.sortedKeys])
        let input = Self.base64url(header) + "." + Self.base64url(claims)
        return input + "." + Self.base64url(try key.sign(Data(input.utf8)))
    }

    /// SecKey has no Sendable conformance. Its handle stays inside this lock and never escapes.
    private final class Signer: Sendable {
        private let key: Mutex<SecKey>
        init(_ key: sending SecKey) { self.key = Mutex(key) }
        func sign(_ input: Data) throws -> Data {
            try key.withLock { key in
                var error: Unmanaged<CFError>?
                let signature = SecKeyCreateSignature(key, .rsaSignatureMessagePKCS1v15SHA256, input as CFData, &error)
                _ = error?.takeRetainedValue()
                guard let signature else { throw FCMError.signingFailed }
                return signature as Data
            }
        }
    }

    private static func importKey(_ pem: String) throws -> SecKey {
        guard pem.utf8.count <= 16384 else { throw FCMError.invalidCredentials }
        let text = pem.trimmingCharacters(in: .whitespacesAndNewlines)
        let begin = "-----BEGIN PRIVATE KEY-----", end = "-----END PRIVATE KEY-----"
        guard text.hasPrefix(begin), text.hasSuffix(end) else { throw FCMError.invalidCredentials }
        let payload = text.dropFirst(begin.count).dropLast(end.count)
        let base64 = payload.filter { !$0.isWhitespace }
        guard !base64.isEmpty, base64.utf8.allSatisfy({
            (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 43 || $0 == 47 || $0 == 61
        }), Data(base64Encoded: base64) != nil else { throw FCMError.invalidCredentials }
        // No destination keychain and no prompt flags: import only into this process.
        var format = SecExternalFormat.formatUnknown
        var type = SecExternalItemType.itemTypePrivateKey
        var items: CFArray?
        let status = SecItemImport(Data(text.utf8) as CFData, nil, &format, &type, [], nil, nil, &items)
        guard status == errSecSuccess, let imported = items as? [AnyObject], imported.count == 1,
              CFGetTypeID(imported[0]) == SecKeyGetTypeID() else { throw FCMError.invalidCredentials }
        let key = imported[0] as! SecKey
        guard let attributes = SecKeyCopyAttributes(key) as? [String: Any],
              attributes[kSecAttrKeyType as String] as? String == kSecAttrKeyTypeRSA as String,
              attributes[kSecAttrKeyClass as String] as? String == kSecAttrKeyClassPrivate as String,
              let bits = attributes[kSecAttrKeySizeInBits as String] as? Int, (2048...4096).contains(bits),
              SecKeyIsAlgorithmSupported(key, .sign, .rsaSignatureMessagePKCS1v15SHA256) else { throw FCMError.invalidCredentials }
        return key
    }

    private static func printable(_ text: String, maximum: Int) -> Bool {
        !text.isEmpty && text.utf8.count <= maximum && text.utf8.allSatisfy { (33...126).contains($0) }
    }
    private static func base64url(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
    private struct Fields: Decodable {
        let type: String
        let token_uri: String
        let client_email: String
        let private_key_id: String
        let private_key: String
    }
}
