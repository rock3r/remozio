import CryptoKit
import Darwin
import Foundation
import LocalAuthentication
import Network
import RemozioCore
import Security

// Disposable, memory-only identities and a loopback exchange. Never package this probe in the app.
enum ProbeError: Error { case key, certificate, identity, payload, listener, wrongPinAccepted }

struct Report: Encodable {
    let experiment = "secure-enclave-tls"
    let schemaVersion = 1
    let osVersion = ProcessInfo.processInfo.operatingSystemVersionString
    let authenticationUIAllowed = false
    let persistentKeyRequested = false
    var secureEnclaveAvailable = SecureEnclave.isAvailable
    var enclaveTokenVerified = false
    var privateKeyExportRejected = false
    var identityCreated = false
    var mutualTLS13Exchange = false
    var wrongServerPinRejected = false
    var wrongPinPolicyRejectionObserved = false
    var wrongPinChannelOutcome: String?
    var stage = "availability"
    var status = "blocked"
    var errorDomain: String?
    var errorCode: Int?
}

// Minimal DER for synthetic self-signed certificates only. Production issuance is separate.
func der(_ tag: UInt8, _ bytes: Data) -> Data {
    let count = bytes.count
    let length: [UInt8] = count < 128 ? [UInt8(count)] : count < 256 ? [0x81, UInt8(count)] : [0x82, UInt8(count >> 8), UInt8(count & 255)]
    return Data([tag] + length) + bytes
}
func sequence(_ bytes: Data) -> Data { der(0x30, bytes) }
let signatureAlgorithm = sequence(Data([0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]))

func publicKey(_ key: SecKey) throws -> P256.Signing.PublicKey {
    guard let publicKey = SecKeyCopyPublicKey(key),
          let encoded = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else { throw ProbeError.key }
    return try P256.Signing.PublicKey(x963Representation: encoded)
}

func identity(_ key: SecKey, name: String) throws -> SecIdentity {
    let subject = sequence(der(0x31, sequence(Data([0x06, 0x03, 0x55, 0x04, 0x03]) + der(0x0c, Data(name.utf8)))))
    let formatter = DateFormatter()
    formatter.locale = Locale(identifier: "en_US_POSIX")
    formatter.timeZone = TimeZone(secondsFromGMT: 0)
    formatter.dateFormat = "yyMMddHHmmss'Z'"
    let now = Date()
    let validity = sequence(der(0x17, Data(formatter.string(from: now.addingTimeInterval(-60)).utf8))
        + der(0x17, Data(formatter.string(from: now.addingTimeInterval(300)).utf8)))
    let tbs = sequence(Data([0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01])
        + signatureAlgorithm + subject + validity + subject + (try publicKey(key)).derRepresentation)
    var error: Unmanaged<CFError>?
    guard let signature = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256, tbs as CFData, &error) as Data? else {
        if let error { throw error.takeRetainedValue() }
        throw ProbeError.certificate
    }
    let encoded = sequence(tbs + signatureAlgorithm + der(0x03, Data([0]) + signature))
    guard let certificate = SecCertificateCreateWithData(nil, encoded as CFData),
          let identity = SecIdentityCreate(nil, certificate, key) else { throw ProbeError.identity }
    return identity
}

func key(enclave: Bool, context: LAContext) throws -> SecKey {
    var error: Unmanaged<CFError>?
    var attributes: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits: 256, kSecUseAuthenticationContext: context,
        kSecPrivateKeyAttrs: [kSecAttrIsPermanent: false]]
    if enclave {
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                                                         .privateKeyUsage, &error) else {
            if let error { throw error.takeRetainedValue() }
            throw ProbeError.key
        }
        attributes[kSecAttrTokenID] = kSecAttrTokenIDSecureEnclave
        attributes[kSecPrivateKeyAttrs] = [kSecAttrIsPermanent: false, kSecAttrAccessControl: access]
    }
    guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
        if let error { throw error.takeRetainedValue() }
        throw ProbeError.key
    }
    return key
}

final class RejectionEvidence: @unchecked Sendable {
    private let lock = NSLock()
    private var rejected = false
    func record() { lock.withLock { rejected = true } }
    var observed: Bool { lock.withLock { rejected } }
}

func parameters(identity: SecIdentity, peer: Data, rejection: RejectionEvidence? = nil) throws -> NWParameters {
    let policy = try PinnedTLSPeer(subjectPublicKeyInfo: peer)
    let tls = NWProtocolTLS.Options()
    let options = tls.securityProtocolOptions
    guard let local = sec_identity_create(identity) else { throw ProbeError.identity }
    sec_protocol_options_set_local_identity(options, local)
    sec_protocol_options_set_min_tls_protocol_version(options, .TLSv13)
    sec_protocol_options_set_max_tls_protocol_version(options, .TLSv13)
    sec_protocol_options_set_peer_authentication_required(options, true)
    sec_protocol_options_set_tls_resumption_enabled(options, false)
    sec_protocol_options_set_tls_tickets_enabled(options, false)
    sec_protocol_options_add_tls_application_protocol(options, "remozio-enclave-probe/1")
    sec_protocol_options_set_verify_block(options, { metadata, _, complete in
        var leaf: SecCertificate?
        let accessible = sec_protocol_metadata_access_peer_certificate_chain(metadata) { certificate in
            if leaf == nil { leaf = sec_certificate_copy_ref(certificate).takeRetainedValue() }
        }
        guard accessible, let leaf else { complete(false); return }
        let accepted = policy.accepts(certificate: SecCertificateCopyData(leaf) as Data)
        if !accepted { rejection?.record() }
        complete(accepted)
    }, DispatchQueue(label: "dev.remozio.experiment.enclave-tls.verify"))
    return NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
}

func admitted(_ connection: NWConnection) -> Bool {
    guard let tls = connection.metadata(definition: NWProtocolTLS.definition) as? NWProtocolTLS.Metadata,
          let name = sec_protocol_metadata_copy_negotiated_protocol(tls.securityProtocolMetadata) else { return false }
    defer { free(UnsafeMutableRawPointer(mutating: name)) }
    return sec_protocol_metadata_get_negotiated_tls_protocol_version(tls.securityProtocolMetadata) == .TLSv13
        && String(cString: name) == "remozio-enclave-probe/1"
        && !sec_protocol_metadata_get_early_data_accepted(tls.securityProtocolMetadata)
}

@MainActor final class Probe {
    var report = Report()
    var listener: NWListener?
    var channels: [NetworkByteChannel] = []
    var serverTask: Task<Void, Error>?
    var generation = UUID()
    let payload = Data("Remozio disposable Secure Enclave TLS probe".utf8)

    func exchange(server: SecIdentity, client: SecIdentity, serverPin: Data, clientPin: Data, wrongPinControl: Bool = false, rejection: RejectionEvidence? = nil) async throws {
        let generation = UUID()
        self.generation = generation
        let options = try parameters(identity: server, peer: clientPin)
        options.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: .any)
        let listener = try NWListener(using: options)
        self.listener = listener
        listener.newConnectionHandler = { [weak self] connection in
            Task { @MainActor in
                guard let self, self.generation == generation, self.serverTask == nil else { connection.cancel(); return }
                let channel = NetworkByteChannel(connection: connection, admission: admitted)
                self.channels.append(channel)
                self.serverTask = Task {
                    try await channel.start(timeoutMilliseconds: 5_000)
                    let data = try await self.readPayload(channel)
                    guard data == self.payload else { throw ProbeError.payload }
                    try await channel.send(data)
                }
            }
        }
        let port: NWEndpoint.Port = try await withCheckedThrowingContinuation { continuation in
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    listener.stateUpdateHandler = nil
                    if let port = listener.port { continuation.resume(returning: port) }
                    else { continuation.resume(throwing: ProbeError.listener) }
                case .failed:
                    listener.stateUpdateHandler = nil
                    continuation.resume(throwing: ProbeError.listener)
                default: break
                }
            }
            listener.start(queue: DispatchQueue(label: "dev.remozio.experiment.enclave-tls.listener"))
        }
        let connection = NWConnection(host: .ipv4(.loopback), port: port, using: try parameters(identity: client, peer: serverPin, rejection: rejection))
        let channel = NetworkByteChannel(connection: connection, admission: admitted)
        channels.append(channel)
        try await channel.start(timeoutMilliseconds: 5_000)
        if wrongPinControl { throw ProbeError.wrongPinAccepted }
        try await channel.send(payload)
        guard try await readPayload(channel) == payload else { throw ProbeError.payload }
        guard let serverTask else { throw ProbeError.listener }
        try await serverTask.value
    }

    func readPayload(_ channel: NetworkByteChannel) async throws -> Data {
        var data = Data()
        while data.count < payload.count {
            guard let chunk = try await channel.receive() else { throw ProbeError.payload }
            data.append(chunk)
        }
        guard data.count == payload.count else { throw ProbeError.payload }
        return data
    }

    func run() async {
        guard report.secureEnclaveAvailable else { finish(); return }
        let context = LAContext()
        context.interactionNotAllowed = true
        defer { context.invalidate() }
        var assertionsPassed = false
        do {
            report.stage = "create-enclave-key"
            let serverKey = try key(enclave: true, context: context)
            let attributes = SecKeyCopyAttributes(serverKey) as? [String: Any]
            report.enclaveTokenVerified = attributes?[kSecAttrTokenID as String] as? String == kSecAttrTokenIDSecureEnclave as String
            guard report.enclaveTokenVerified else { throw ProbeError.key }
            report.privateKeyExportRejected = SecKeyCopyExternalRepresentation(serverKey, nil) == nil
            guard report.privateKeyExportRejected else { throw ProbeError.key }
            report.stage = "create-identity"
            let server = try identity(serverKey, name: "synthetic-remozio-enclave")
            report.identityCreated = true
            let clientKey = try key(enclave: false, context: context)
            let client = try identity(clientKey, name: "synthetic-remozio-client")
            report.stage = "mutual-tls"
            try await exchange(server: server, client: client, serverPin: publicKey(serverKey).derRepresentation,
                               clientPin: publicKey(clientKey).derRepresentation)
            report.mutualTLS13Exchange = true
            await cleanup()
            report.stage = "wrong-pin-control"
            let rejection = RejectionEvidence()
            do {
                try await exchange(server: server, client: client, serverPin: publicKey(clientKey).derRepresentation,
                                   clientPin: publicKey(clientKey).derRepresentation, wrongPinControl: true, rejection: rejection)
                throw ProbeError.wrongPinAccepted
            } catch let error as NetworkChannelError {
                report.wrongPinPolicyRejectionObserved = rejection.observed
                guard rejection.observed else { throw error }
                switch error {
                case .failed: report.wrongPinChannelOutcome = "failed"
                case .timedOut: report.wrongPinChannelOutcome = "timedOut"
                case .closed: report.wrongPinChannelOutcome = "closed"
                default: throw error
                }
                report.wrongServerPinRejected = true
            }
            assertionsPassed = true
            report.stage = "cleanup"
        } catch {
            let failure = error as NSError
            report.errorDomain = failure.domain
            report.errorCode = failure.code
        }
        await cleanup()
        if assertionsPassed {
            report.stage = "complete"
            report.status = "passed"
        }
        finish()
    }

    func timedOut() {
        report.stage = "timeout"
        report.status = "blocked"
        finish()
    }

    func cleanup() async {
        generation = UUID()
        listener?.cancel()
        let pending = serverTask
        pending?.cancel()
        for channel in channels { await channel.close() }
        if let pending { _ = try? await pending.value }
        channels.removeAll()
        serverTask = nil
        listener = nil
    }

    func finish() {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? encoder.encode(report) else { exit(70) }
        FileHandle.standardOutput.write(data + Data([10]))
        exit(report.status == "passed" ? 0 : 77)
    }
}

#if !DEBUG
fatalError("The enclave TLS probe is available only in debug builds.")
#else
guard getuid() != 0 else { fatalError("Run the disposable probe as an ordinary user.") }
let probe = Probe()
if CommandLine.arguments.dropFirst() == ["--timeout-control"] {
    probe.report.stage = "complete"
    probe.report.status = "passed"
    probe.timedOut()
}
guard CommandLine.arguments.count == 1 else { exit(64) }
DispatchQueue.main.asyncAfter(deadline: .now() + 15) { probe.timedOut() }
await probe.run()
#endif
