import Darwin
import Foundation
import Network
import Security
import RemozioCore
import RemozioProtocol

// Synthetic loopback echo only. Never package this executable with the app.
enum ProbeError: Error { case invalidInput, identityImport(OSStatus) }
struct Setup: Decodable { let peerPublicKey: String; let negotiate: Bool?; let commandMessages: Bool? }

func emit(_ fields: [String: Int]) {
    guard let data = try? JSONSerialization.data(withJSONObject: fields) else { exit(1) }
    FileHandle.standardOutput.write(data + Data([10]))
}

final class Probe: @unchecked Sendable {
    let queue = DispatchQueue(label: "dev.remozio.experiment.tls")
    let listener: NWListener
    let negotiate: Bool
    let commandMessages: Bool
    var connections: [UUID: NetworkByteChannel] = [:]

    init(identity: SecIdentity, peerPublicKey: Data, negotiate: Bool, commandMessages: Bool) throws {
        self.negotiate = negotiate
        self.commandMessages = commandMessages
        let peer = try PinnedTLSPeer(subjectPublicKeyInfo: peerPublicKey)
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
        sec_protocol_options_set_verify_block(options, { metadata, _, complete in
            var leaf: SecCertificate?
            let accessible = sec_protocol_metadata_access_peer_certificate_chain(metadata) { certificate in
                if leaf == nil { leaf = sec_certificate_copy_ref(certificate).takeRetainedValue() }
            }
            guard accessible, let leaf else { complete(false); return }
            complete(peer.accepts(certificate: SecCertificateCopyData(leaf) as Data))
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
            let channel = NetworkByteChannel(connection: connection) { connection in
                guard let tls = connection.metadata(definition: NWProtocolTLS.definition) as? NWProtocolTLS.Metadata,
                      let name = sec_protocol_metadata_copy_negotiated_protocol(tls.securityProtocolMetadata) else { return false }
                defer { free(UnsafeMutableRawPointer(mutating: name)) }
                return String(cString: name) == "remozio-experiment/1"
                    && sec_protocol_metadata_get_negotiated_tls_protocol_version(tls.securityProtocolMetadata) == .TLSv13
                    && !sec_protocol_metadata_get_early_data_accepted(tls.securityProtocolMetadata)
            }
            connections[id] = channel
            Task {
                do {
                    if negotiate {
                        let scope = try ChannelScope(macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16),
                            phoneID: Data(repeating: 3, count: 16), enrollmentEpoch: Data(repeating: 4, count: 16))
                        let framed = try await NegotiatedNetworkChannel.accept(channel: channel, scope: scope,
                            requests: commandMessages ? [try ChannelRequestCapability(kind: 0, wireVersion: 1, schemaVersion: 1, features: [])] : [],
                            auditVersions: [], maximumPayloadBytes: 65_536, timeoutMilliseconds: 4_000)
                        do { while let payload = try await framed.receive() { try await framed.send(payload) } }
                        catch { await framed.closeAndWait(); throw error }
                        await framed.closeAndWait()
                    } else {
                        try await channel.start(timeoutMilliseconds: 10_000)
                        try await echoFrame(channel)
                    }
                } catch { }
                await channel.close()
                queue.async { self.connections.removeValue(forKey: id) }
            }
            queue.asyncAfter(deadline: .now() + 10) { Task { await channel.close() } }

        }
        listener.start(queue: queue)
    }

    func echoFrame(_ channel: NetworkByteChannel) async throws {
        var frame = Data()
        while frame.count < 4 {
            guard let chunk = try await channel.receive() else { throw ProbeError.invalidInput }
            frame.append(chunk)
        }
        let length = frame.prefix(4).reduce(0) { ($0 << 8) | Int($1) }
        guard length <= 65_536 else { throw ProbeError.invalidInput }
        while frame.count < length + 4 {
            guard let chunk = try await channel.receive() else { throw ProbeError.invalidInput }
            frame.append(chunk)
        }
        guard frame.count == length + 4 else { throw ProbeError.invalidInput }
        var offset = 0
        while offset < frame.count {
            let end = min(frame.count, offset + NetworkByteChannel.maximumChunkBytes)
            try await channel.send(Data(frame[offset..<end]))
            offset = end
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
guard let peer = Data(base64Encoded: setup.peerPublicKey), !peer.isEmpty, peer.count <= 8_192 else { throw ProbeError.invalidInput }
let identityData = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))
guard identityData.count <= 65_536 else { throw ProbeError.invalidInput }
var imported: CFArray?
let result = SecPKCS12Import(identityData as CFData, [kSecImportExportPassphrase: "synthetic-only", kSecImportToMemoryOnly: true] as CFDictionary, &imported)
guard result == errSecSuccess else { throw ProbeError.identityImport(result) }
guard let items = imported as? [[String: Any]], let value = items.first?[kSecImportItemIdentity as String] else { throw ProbeError.invalidInput }
let identity = value as! SecIdentity
let probe = try Probe(identity: identity, peerPublicKey: peer, negotiate: setup.negotiate == true, commandMessages: setup.commandMessages == true)
probe.start()
DispatchQueue.global().async {
    // The controller keeps this pipe open. EOF also handles controller crashes. No further commands are accepted.
    exit(getchar() == EOF ? 0 : 1)
}
dispatchMain()
#endif
