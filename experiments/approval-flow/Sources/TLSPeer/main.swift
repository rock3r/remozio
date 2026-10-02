import Darwin
import Foundation
import Network
import Security

// Synthetic loopback echo only. Never package this executable with the app.
enum ProbeError: Error { case invalidInput, identityImport(OSStatus) }
struct Setup: Decodable { let peerCertificate: String }

func emit(_ fields: [String: Int]) {
    guard let data = try? JSONSerialization.data(withJSONObject: fields) else { exit(1) }
    FileHandle.standardOutput.write(data + Data([10]))
}

final class Probe: @unchecked Sendable {
    let queue = DispatchQueue(label: "dev.remozio.experiment.tls")
    let listener: NWListener
    var connections: [UUID: NWConnection] = [:]

    init(identity: SecIdentity, peerCertificate: Data) throws {
        let tls = NWProtocolTLS.Options()
        let options = tls.securityProtocolOptions
        guard let local = sec_identity_create(identity) else { throw ProbeError.invalidInput }
        sec_protocol_options_set_local_identity(options, local)
        sec_protocol_options_set_min_tls_protocol_version(options, .TLSv13)
        sec_protocol_options_set_max_tls_protocol_version(options, .TLSv13)
        sec_protocol_options_set_peer_authentication_required(options, true)
        sec_protocol_options_set_tls_resumption_enabled(options, false)
        sec_protocol_options_set_tls_tickets_enabled(options, false)
        sec_protocol_options_add_tls_application_protocol(options, "remozio-experiment/1")
        sec_protocol_options_set_verify_block(options, { _, trust, complete in
            let reference = sec_trust_copy_ref(trust).takeRetainedValue()
            guard let chain = SecTrustCopyCertificateChain(reference) as? [SecCertificate], let leaf = chain.first else {
                complete(false); return
            }
            // The private controller supplies the exact disposable leaf pin. This is not a production PKI policy.
            complete((SecCertificateCopyData(leaf) as Data) == peerCertificate)
        }, queue)
        let parameters = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
        parameters.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: .any)
        listener = try NWListener(using: parameters)
    }

    func start() {
        listener.stateUpdateHandler = { [self] state in
            switch state {
            case .ready:
                guard let port = listener.port else { exit(1) }
                emit(["port": Int(port.rawValue)])
            case .failed: exit(1)
            default: break
            }
        }
        listener.newConnectionHandler = { [self] connection in
            guard connections.count < 8 else { connection.cancel(); return }
            let id = UUID()
            connections[id] = connection
            connection.stateUpdateHandler = { [self, weak connection] state in
                guard let connection else { return }
                switch state {
                case .ready:
                    guard let tls = connection.metadata(definition: NWProtocolTLS.definition) as? NWProtocolTLS.Metadata,
                          let name = sec_protocol_metadata_copy_negotiated_protocol(tls.securityProtocolMetadata) else { connection.cancel(); return }
                    defer { free(UnsafeMutableRawPointer(mutating: name)) }
                    guard String(cString: name) == "remozio-experiment/1",
                          !sec_protocol_metadata_get_early_data_accepted(tls.securityProtocolMetadata) else { connection.cancel(); return }
                    readFrame(connection)
                case .failed, .cancelled: connections.removeValue(forKey: id)
                default: break
                }
            }
            connection.start(queue: queue)
            queue.asyncAfter(deadline: .now() + 10) { [weak connection] in connection?.cancel() }
        }
        listener.start(queue: queue)
    }

    func readExactly(_ connection: NWConnection, count: Int, buffer: Data = Data(), complete: @escaping @Sendable (Data) -> Void) {
        guard count > buffer.count else { complete(buffer); return }
        connection.receive(minimumIncompleteLength: 1, maximumLength: count - buffer.count) { [self] data, _, ended, error in
            guard error == nil, let data, !data.isEmpty else { connection.cancel(); return }
            let accumulated = buffer + data
            if accumulated.count == count { complete(accumulated) }
            else if ended { connection.cancel() }
            else { readExactly(connection, count: count, buffer: accumulated, complete: complete) }
        }
    }

    func readFrame(_ connection: NWConnection) {
        readExactly(connection, count: 4) { [self] header in
            let length = header.reduce(0) { ($0 << 8) | Int($1) }
            guard length <= 65_536 else { connection.cancel(); return }
            readExactly(connection, count: length) { payload in
                connection.send(content: header + payload, completion: .contentProcessed { _ in connection.cancel() })
            }
        }
    }
}

#if !DEBUG
fatalError("The TLS experiment is available only in debug builds.")
#else
guard getuid() != 0, CommandLine.arguments.count == 2 else { fatalError("Run the synthetic TLS peer as an ordinary user.") }
var encodedSetup = Data()
while true {
    let byte = getchar()
    guard byte != EOF else { throw ProbeError.invalidInput }
    if byte == 10 { break }
    guard encodedSetup.count < 16_384 else { throw ProbeError.invalidInput }
    encodedSetup.append(UInt8(byte))
}
let setup = try JSONDecoder().decode(Setup.self, from: encodedSetup)
guard let peer = Data(base64Encoded: setup.peerCertificate), !peer.isEmpty, peer.count <= 8_192 else { throw ProbeError.invalidInput }
let identityData = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))
guard identityData.count <= 65_536 else { throw ProbeError.invalidInput }
var imported: CFArray?
let result = SecPKCS12Import(identityData as CFData, [kSecImportExportPassphrase: "synthetic-only", kSecImportToMemoryOnly: true] as CFDictionary, &imported)
guard result == errSecSuccess else { throw ProbeError.identityImport(result) }
guard let items = imported as? [[String: Any]], let value = items.first?[kSecImportItemIdentity as String] else { throw ProbeError.invalidInput }
let identity = value as! SecIdentity
let probe = try Probe(identity: identity, peerCertificate: peer)
probe.start()
DispatchQueue.global().async {
    // The controller keeps this pipe open. EOF also handles controller crashes. No further commands are accepted.
    exit(getchar() == EOF ? 0 : 1)
}
dispatchMain()
#endif
