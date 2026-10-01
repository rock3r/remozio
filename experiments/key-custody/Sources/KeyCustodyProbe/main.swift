import CryptoKit
import Foundation
import LocalAuthentication
import Security

struct Failure: Encodable {
    let domain: String
    let code: Int

    init(_ error: Error) {
        let error = error as NSError
        domain = error.domain
        code = error.code
    }
}

struct Report: Encodable {
    let schemaVersion = 1
    let experiment = "secure-enclave-signing"
    let osVersion = ProcessInfo.processInfo.operatingSystemVersionString
    let authenticationUIAllowed = false
    let accessibility = "after-first-unlock-this-device-only"
    var secureEnclaveAvailable = SecureEnclave.isAvailable
    var originalSignatureValid: Bool?
    var restoredKeyMatches: Bool?
    var restoredSignatureValid: Bool?
    var tamperedRepresentationRejected: Bool?
    var stage = "availability"
    var status = "blocked"
    var failure: Failure?
}

enum ProbeError: Int, Error {
    case accessControlCreation = 1
    case signatureInvalid
    case restoredKeyMismatch
    case tamperingAccepted
}

func run() -> Report {
    var report = Report()
    guard report.secureEnclaveAvailable else { return report }
    let context = LAContext()
    context.interactionNotAllowed = true
    defer { context.invalidate() }
    do {
        report.stage = "create"
        var accessError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, .privateKeyUsage, &accessError
        ) else {
            if let error = accessError?.takeRetainedValue() { throw error }
            throw ProbeError.accessControlCreation
        }
        let original = try SecureEnclave.P256.Signing.PrivateKey(
            accessControl: access, authenticationContext: context
        )
        let message = Data("Remozio disposable key-custody experiment v1".utf8)
        report.stage = "sign"
        let signature = try original.signature(for: message)
        report.originalSignatureValid = original.publicKey.isValidSignature(signature, for: message)
        guard report.originalSignatureValid == true else { throw ProbeError.signatureInvalid }

        report.stage = "restore"
        let representation = original.dataRepresentation
        let restored = try SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: representation, authenticationContext: context
        )
        report.restoredKeyMatches = restored.publicKey.rawRepresentation == original.publicKey.rawRepresentation
        guard report.restoredKeyMatches == true else { throw ProbeError.restoredKeyMismatch }
        let restoredSignature = try restored.signature(for: message)
        report.restoredSignatureValid = original.publicKey.isValidSignature(restoredSignature, for: message)
        guard report.restoredSignatureValid == true else { throw ProbeError.signatureInvalid }

        report.stage = "tamper"
        var damaged = representation
        damaged[damaged.startIndex + damaged.count / 2] ^= 1
        do {
            let tampered = try SecureEnclave.P256.Signing.PrivateKey(
                dataRepresentation: damaged, authenticationContext: context
            )
            let tamperedSignature = try tampered.signature(for: message)
            report.tamperedRepresentationRejected = !original.publicKey.isValidSignature(tamperedSignature, for: message)
        } catch {
            report.tamperedRepresentationRejected = true
        }
        guard report.tamperedRepresentationRejected == true else { throw ProbeError.tamperingAccepted }
        report.stage = "complete"
        report.status = "passed"
    } catch {
        report.failure = Failure(error)
    }
    return report
}

// The probe never writes key representations, signatures, or error descriptions.
let report = run()
let encoder = JSONEncoder()
encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
do {
    let data = try encoder.encode(report)
    FileHandle.standardOutput.write(data)
    FileHandle.standardOutput.write(Data([10]))
} catch {
    exit(70)
}
exit(report.status == "passed" ? 0 : 77)
