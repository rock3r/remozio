import CryptoKit
import Darwin
import Foundation

// Private synthetic controller only. No socket, enrollment, hardware keys, or production transport.
enum HarnessError: Error { case invalidInput }
struct Input: Decodable {
    let command: String
    let peer: String
    let info: String
    let aad: String
    let payload: String
    let encapsulation: String?
}
func bytes(_ value: String) throws -> Data {
    guard value.utf8.count <= 131_104, let result = Data(base64Encoded: value), result.count <= 65_552 else {
        throw HarnessError.invalidInput
    }
    return result
}
func readInput() throws -> Input? {
    var line = Data()
    while true {
        let next = getchar()
        if next == EOF {
            guard line.isEmpty else { throw HarnessError.invalidInput }
            return nil
        }
        if next == 10 { break }
        guard line.count < 300_000 else { throw HarnessError.invalidInput }
        line.append(UInt8(next))
    }
    return try JSONDecoder().decode(Input.self, from: line)
}
func emit(_ fields: [String: String]) throws {
    let data = try JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys])
    FileHandle.standardOutput.write(data + Data([10]))
}

#if !DEBUG
fatalError("The HPKE experiment is available only in debug builds.")
#else
guard getuid() != 0 else { fatalError("Run this synthetic experiment as an ordinary user.") }
let key = P256.KeyAgreement.PrivateKey()
let suite = HPKE.Ciphersuite.P256_SHA256_AES_GCM_256
try emit(["publicKey": key.publicKey.x963Representation.base64EncodedString()])
while let input = try readInput() {
    do {
        let peer = try P256.KeyAgreement.PublicKey(x963Representation: bytes(input.peer))
        let info = try bytes(input.info)
        let aad = try bytes(input.aad)
        let payload = try bytes(input.payload)
        switch input.command {
        case "seal":
            guard payload.count <= 65_536 else { throw HarnessError.invalidInput }
            var sender = try HPKE.Sender(recipientKey: peer, ciphersuite: suite, info: info, authenticatedBy: key)
            let ciphertext = try sender.seal(payload, authenticating: aad)
            try emit(["ciphertext": ciphertext.base64EncodedString(),
                      "encapsulation": sender.encapsulatedKey.base64EncodedString()])
        case "open":
            guard let encapsulation = input.encapsulation else { throw HarnessError.invalidInput }
            var recipient = try HPKE.Recipient(privateKey: key, ciphersuite: suite, info: info,
                encapsulatedKey: bytes(encapsulation), authenticatedBy: peer)
            let plaintext = try recipient.open(payload, authenticating: aad)
            try emit(["plaintext": plaintext.base64EncodedString()])
        default:
            throw HarnessError.invalidInput
        }
    } catch {
        // Do not echo inputs or key material in errors.
        try emit(["rejected": "true"])
    }
}
#endif
