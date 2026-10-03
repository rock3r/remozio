import Foundation
import JOSESwift

public enum SetupFileError: Error { case invalidInput, rejected }

/// A versioned encrypted container. Call away from the UI thread; password derivation is synchronous.
/// The protected setup host must validate the decrypted configuration before preview or import.
public enum SetupFileEncryption {
    public static let maximumPayloadBytes = 1_048_576
    public static let maximumFileBytes = 1_400_000
    public static let iterations = 220_000
    private static let type = "remozio-setup-v1+jwe"
    private static let algorithm = "PBES2-HS512+A256KW"

    /// Returns encrypted bytes only. This component does not create files or retain the password.
    public static func seal(_ payload: Data, password: String) throws -> Data {
        guard (1...maximumPayloadBytes).contains(payload.count), validPassword(password) else {
            throw SetupFileError.invalidInput
        }
        do {
            var header = JWEHeader(keyManagementAlgorithm: .PBES2_HS512_A256KW, contentEncryptionAlgorithm: .A256GCM)
            header.typ = type
            header.p2c = iterations
            guard let encrypter = Encrypter(keyManagementAlgorithm: .PBES2_HS512_A256KW,
                                           contentEncryptionAlgorithm: .A256GCM, encryptionKey: password,
                                           pbes2SaltInputLength: 32) else { throw SetupFileError.rejected }
            let encrypted = try JWE(header: header, payload: Payload(payload), encrypter: encrypter)
            return Data(encrypted.compactSerializedString.utf8)
        } catch { throw SetupFileError.rejected }
    }

    /// Authenticates the container before returning plaintext. Failure never returns partial plaintext.
    public static func open(_ file: Data, password: String) throws -> Data {
        guard validPassword(password) else { throw SetupFileError.invalidInput }
        do {
            let compact = try validate(file)
            let encrypted = try JWE(compactSerialization: compact)
            guard let decrypter = Decrypter(keyManagementAlgorithm: .PBES2_HS512_A256KW,
                                           contentEncryptionAlgorithm: .A256GCM, decryptionKey: password) else {
                throw SetupFileError.rejected
            }
            let plaintext = try encrypted.decrypt(using: decrypter).data()
            guard (1...maximumPayloadBytes).contains(plaintext.count) else { throw SetupFileError.rejected }
            return plaintext
        } catch { throw SetupFileError.rejected }
    }

    // Validate all untrusted lengths and the work factor before calling the cryptographic library.
    static func validate(_ file: Data) throws -> String {
        guard (1...maximumFileBytes).contains(file.count), let compact = String(data: file, encoding: .utf8) else {
            throw SetupFileError.rejected
        }
        let parts = compact.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 5, parts[0].utf8.count <= 1_024 else { throw SetupFileError.rejected }
        let header = try decode(parts[0])
        guard let fields = try JSONSerialization.jsonObject(with: header) as? [String: Any],
              Set(fields.keys) == Set(["alg", "enc", "typ", "p2s", "p2c"]),
              fields["alg"] as? String == algorithm, fields["enc"] as? String == "A256GCM",
              fields["typ"] as? String == type,
              let rounds = fields["p2c"] as? Int, (iterations...1_000_000).contains(rounds),
              let salt = fields["p2s"] as? String, try decode(Substring(salt)).count == 32,
              try JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys]) == header else {
            throw SetupFileError.rejected
        }
        guard try decode(parts[1]).count == 40, try decode(parts[2]).count == 12,
              (1...maximumPayloadBytes).contains(try decode(parts[3]).count),
              try decode(parts[4]).count == 16 else { throw SetupFileError.rejected }
        return compact
    }

    private static func validPassword(_ password: String) -> Bool { (1...1_024).contains(password.utf8.count) }

    private static func decode(_ value: Substring) throws -> Data {
        guard !value.isEmpty, value.utf8.allSatisfy({ (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 45 || $0 == 95 }) else {
            throw SetupFileError.rejected
        }
        var encoded = String(value).replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        encoded += String(repeating: "=", count: (4 - encoded.utf8.count % 4) % 4)
        guard let decoded = Data(base64Encoded: encoded),
              decoded.base64EncodedString().replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "") == value else {
            throw SetupFileError.rejected
        }
        return decoded
    }
}
