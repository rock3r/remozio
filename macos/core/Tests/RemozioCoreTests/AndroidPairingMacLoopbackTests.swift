import CryptoKit
import Darwin
import Foundation
import Network
import RemozioProtocol
import Security
import Synchronization
import XCTest
@testable import RemozioCore

/// The local runner sets a directory to use the API 37 Android client. CI uses the native test client.
final class AndroidPairingMacLoopbackTests: XCTestCase, @unchecked Sendable {
    private enum FixtureError: Error { case timeout, listenerFailed, unexpectedFrame }

    private enum Scenario {
        case defaultPairing, lanFilter, rejectsUnprovedClient
    }

    private struct Ready: Encodable {
        let port: UInt16
        let publicInvitation: String
        let windowID: String
    }

    private struct State: Sendable {
        var port: UInt16?
        var failed = false
        var channels = 0
        var onLinkArrivals = 0
        var verificationAttempts = 0
        var handlers = 0
        var retirements = 0
        var reservations = 0
        var receipts = 0
    }

    private final class Observation: Sendable {
        let value = Mutex(State())
    }

    // The Android test uses the same synthetic secret. Only the test fixture uses it.
    private static let invitationSecret = Data(repeating: 0x63, count: 32)
    private static let lifetimeMilliseconds: UInt64 = 120_000

    func testInvitationProofAndReceiptOnTheNativeListener() async throws {
        try await assertNativePairing()
    }

    func testLANFilterCancelsBeforeAllocatingChannelsOrSpendingIngressCredit() async throws {
        try await assertNativePairing(.lanFilter)
    }

    func testListenerRejectsUnprovedClientAndAcceptsValidInvitation() async throws {
        try await assertNativePairing(.rejectsUnprovedClient)
    }

    private final class AdmissionDriver: ByteConnectionDriver, Sendable {
        struct Calls: Sendable, Equatable {
            var starts = 0
            var cancellations = 0
        }

        private let calls = Mutex(Calls())

        var observed: Calls { calls.withLock { $0 } }

        func start(_ event: @escaping @Sendable (ByteConnectionEvent) -> Void) {
            calls.withLock { $0.starts += 1 }
        }

        func cancel() { calls.withLock { $0.cancellations += 1 } }

        func receive(_ result: @escaping @Sendable (Data?, Bool, Bool) -> Void) {
            XCTFail("The accept fixture attempted to read bytes")
            result(nil, false, true)
        }

        func send(_ data: Data, result: @escaping @Sendable (Bool) -> Void) {
            XCTFail("The accept fixture attempted to write bytes")
            result(true)
        }
    }

    func testV2ListenerCancelsOverflowWithoutStartingItAndAdmitsAfterRelease() throws {
        let transport = P256.Signing.PrivateKey()
        let invitation = try PairingInvitation(macID: Data(repeating: 1, count: 16),
            accountID: Data(repeating: 2, count: 16), label: "Pairing Test Mac",
            authorityPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
            transportPublicKey: transport.publicKey.x963Representation, minimumEnvelopeVersion: 1)
        let epoch = UUID()
        let clock = Mutex<UInt64>(0)
        let allocations = Mutex(0)
        let interval = (1_000 + PairingRegistrationBudget.registrationsPerSecond - 1)
            / PairingRegistrationBudget.registrationsPerSecond
        let fixture = PairingSetupListener.IngressFixture(peerSubnet: try fixtureSubnet(), now: {
            clock.withLock { milliseconds in
                milliseconds += interval
                return .init(epoch: epoch, milliseconds: milliseconds)
            }
        }, channelAllocated: { allocations.withLock { $0 += 1 } })
        let listener = try PairingSetupListener(identity: AuthorityJournalSchema19MigrationTests.fixtureIdentity(transport),
            invitation: invitation, binding: .loopback, maximumConnections: 4, handshakeTimeoutMilliseconds: 5_000,
            setupTimeoutMilliseconds: 30_000,
            v2: .init(windowID: Data(repeating: 3, count: 16), lifetimeMilliseconds: Self.lifetimeMilliseconds,
                reserve: { _ in XCTFail("The accept fixture started proof verification") }, disconnect: { _ in }),
            ingressFixture: fixture, event: { _ in }, handler: { _ in XCTFail("The accept fixture started a native session") })
        try listener.start()
        defer { listener.close() }

        let accepted = ContinuousClock.now
        func arrive(_ driver: AdmissionDriver, source: Int) throws -> UUID? {
            let address = try XCTUnwrap(IPv4Address("192.0.2.\(source)"))
            return listener.acceptFixtureConnection(driver, endpoint: .hostPort(host: .ipv4(address), port: 1), at: accepted)
        }

        let capacity = PairingSetupV2Admissions.maximumPending
        XCTAssertEqual(capacity, 16)
        let held = (0..<capacity).map { _ in AdmissionDriver() }
        let slots = try held.enumerated().map { try XCTUnwrap(arrive($0.element, source: $0.offset + 2)) }
        XCTAssertEqual(Set(slots).count, capacity)
        XCTAssertEqual(allocations.withLock { $0 }, capacity)
        XCTAssertTrue(held.allSatisfy { $0.observed == .init(starts: 1, cancellations: 0) })

        let overflow = AdmissionDriver()
        XCTAssertNil(try arrive(overflow, source: capacity + 2))
        XCTAssertEqual(overflow.observed, .init(starts: 0, cancellations: 1))
        XCTAssertEqual(allocations.withLock { $0 }, capacity)

        listener.releaseFixtureConnection(try XCTUnwrap(slots.first))
        let replacement = AdmissionDriver()
        XCTAssertNotNil(try arrive(replacement, source: capacity + 3))
        XCTAssertEqual(replacement.observed, .init(starts: 1, cancellations: 0))
        XCTAssertEqual(allocations.withLock { $0 }, capacity + 1)

        let stillFull = AdmissionDriver()
        XCTAssertNil(try arrive(stillFull, source: capacity + 4))
        XCTAssertEqual(stillFull.observed, .init(starts: 0, cancellations: 1))
        XCTAssertEqual(allocations.withLock { $0 }, capacity + 1)
        XCTAssertTrue(held.dropFirst().allSatisfy { $0.observed == .init(starts: 1, cancellations: 0) })
    }

    private func fixtureSubnet() throws -> PairingLANSubnet {
        let address = PairingLANRoute.Address.ipv4(try XCTUnwrap(IPv4Address("192.0.2.1")))
        let offset = try XCTUnwrap(MemoryLayout<sockaddr_in>.offset(of: \.sin_addr))
        let mask = [UInt8(offset + 3), UInt8(AF_INET)] + Array(repeating: 0, count: offset - 2) + [255, 255, 255]
        return try XCTUnwrap(PairingLANSubnet(bound: address, netmask: mask))
    }

    private func assertNativePairing(_ scenario: Scenario = .defaultPairing) async throws {
        let useDistinctSources = scenario == .rejectsUnprovedClient
        let subnet = try scenario == .lanFilter || useDistinctSources ? fixtureSubnet() : nil
        let authority = P256.Signing.PrivateKey()
        let transport = P256.Signing.PrivateKey()
        let publicInvitation = try PairingInvitation(macID: AuthorityPairingSetupAccess.secureRandom(16),
            accountID: AuthorityPairingSetupAccess.secureRandom(16), label: "Pairing Test Mac",
            authorityPublicKey: authority.publicKey.x963Representation, transportPublicKey: transport.publicKey.x963Representation,
            minimumEnvelopeVersion: 1)
        let invitation = try PairingInvitationV2(invitation: publicInvitation,
            windowID: AuthorityPairingSetupAccess.secureRandom(16), secret: Self.invitationSecret,
            lifetimeMilliseconds: Self.lifetimeMilliseconds)
        let epoch = UUID()
        let now: @Sendable () -> AuthorityMoment = {
            AuthorityMoment(epoch: epoch, milliseconds: DispatchTime.now().uptimeNanoseconds / 1_000_000)
        }
        let window = try AuthorityPairingV2Window(invitation: invitation, predecessor: nil, started: now())
        let observation = Observation()
        let allowPeer = Mutex(false), offLinkSources = Mutex<UInt32>(0)
        let fixture = subnet.map {
            PairingSetupListener.IngressFixture(peerSubnet: $0,
                now: { .init(epoch: epoch, milliseconds: 100) },
                channelAllocated: { observation.value.withLock { $0.channels += 1 } })
        }
        let ingress = PairingSetupV2Ingress(windowID: invitation.windowID, lifetimeMilliseconds: invitation.lifetimeMilliseconds,
            reserve: { proof in
                observation.value.withLock { $0.verificationAttempts += 1 }
                try window.reserve(proof, at: now())
                observation.value.withLock { $0.reservations += 1 }
            }, disconnect: {
                _ = window.disconnected($0)
                observation.value.withLock { $0.retirements += 1 }
            })
        let listener = try PairingSetupListener(
            identity: AuthorityJournalSchema19MigrationTests.fixtureIdentity(transport), invitation: publicInvitation,
            binding: .loopback, maximumConnections: 4, handshakeTimeoutMilliseconds: 5_000, setupTimeoutMilliseconds: 30_000,
            v2: ingress, sourceKey: { endpoint in
                if useDistinctSources {
                    return observation.value.withLock {
                        $0.onLinkArrivals += 1
                        return .ipv4(0xc0000201 + UInt32($0.onLinkArrivals))
                    }
                }
                guard scenario == .lanFilter else { return PairingSetupV2Source(endpoint) }
                if allowPeer.withLock({ $0 }) { return .ipv4(0xc0000202) }
                return offLinkSources.withLock {
                    $0 += 1
                    return .ipv4(0xc6336400 + $0)
                }
            }, ingressFixture: fixture, event: { event in
                observation.value.withLock {
                    switch event {
                    case .ready(let port): $0.port = port
                    case .failed: $0.failed = true
                    case .stopped: break
                    }
                }
            }, handler: { session in
                observation.value.withLock { $0.handlers += 1 }
                do {
                    let proposal = try await session.proposal()
                    let provedConnection = await session.provedConnection
                    let connection = try XCTUnwrap(provedConnection)
                    let selected = try window.takeProposal(connection: connection, matching: proposal.encode(), at: now())
                    let transcript = try Self.transcript(for: selected, invitation: publicInvitation)
                    try await session.stage(transcript)
                    _ = try await session.receiveProof()
                    let receipt = try authority.signature(for: transcript.signingInput(purpose: .macCommit)).rawRepresentation
                    try await session.sendReceipt(receipt)
                    observation.value.withLock { $0.receipts += 1 }
                } catch {
                    observation.value.withLock { $0.failed = true }
                    throw error
                }
            })
        try listener.start()
        do {
            try await wait(observation, seconds: 5) { $0.port != nil }
            let port = try XCTUnwrap(observation.value.withLock { $0.port })
            switch scenario {
            case .lanFilter:
                let offLinkAttempts = 2 * PairingRegistrationBudget.ingressBurst
                await withTaskGroup(of: Bool.self) { group in
                    for _ in 0..<offLinkAttempts {
                        group.addTask {
                            do {
                                try await Self.pairNativeClient(port: port, invitation: invitation)
                                return true
                            } catch { return false }
                        }
                    }
                    for await paired in group {
                        XCTAssertFalse(paired, "An off-link candidate completed pairing")
                    }
                }
                XCTAssertEqual(offLinkSources.withLock { $0 }, UInt32(offLinkAttempts))
                XCTAssertEqual(observation.value.withLock { $0.channels }, 0)
                XCTAssertEqual(observation.value.withLock { $0.reservations }, 0)
                allowPeer.withLock { $0 = true }
                try await Self.pairNativeClient(port: port, invitation: invitation)
                XCTAssertEqual(observation.value.withLock { $0.channels }, 1)
            case .rejectsUnprovedClient:
                try await rejectUnprovedClient(port: port, invitation: invitation, observation: observation)
            case .defaultPairing:
                if let directory = ProcessInfo.processInfo.environment["REMOZIO_ANDROID_PAIRING_LOOPBACK_DIR"] {
                    let ready = try Ready(port: port, publicInvitation: publicInvitation.exportText(),
                        windowID: invitation.windowID.map { String(format: "%02x", $0) }.joined())
                    try JSONEncoder().encode(ready).write(
                        to: URL(fileURLWithPath: directory, isDirectory: true).appendingPathComponent("ready.json"), options: .atomic)
                } else {
                    try await Self.pairNativeClient(port: port, invitation: invitation)
                }
            }
            try await wait(observation, seconds: 110) { $0.receipts == 1 }
            XCTAssertEqual(observation.value.withLock { $0.reservations }, 1)
            XCTAssertEqual(observation.value.withLock { $0.receipts }, 1)
            XCTAssertEqual(observation.value.withLock { $0.handlers }, 1)
        } catch {
            await listener.closeAndWait()
            throw error
        }
        await listener.closeAndWait()
    }

    private func rejectUnprovedClient(port: UInt16, invitation: PairingInvitationV2, observation: Observation) async throws {
        let unrelated = try PairingInvitationV2(invitation: invitation.invitation, windowID: invitation.windowID,
            secret: Data(repeating: 0x64, count: 32), lifetimeMilliseconds: invitation.lifetimeMilliseconds)
        do {
            try await Self.pairNativeClient(port: port, invitation: unrelated)
            XCTFail("The client without the invitation completed pairing")
        } catch {}
        try await wait(observation, seconds: 2) { $0.retirements == 1 }
        let rejected = observation.value.withLock { $0 }
        XCTAssertEqual(rejected.verificationAttempts, 1)
        XCTAssertEqual(rejected.handlers, 0)
        XCTAssertEqual(rejected.reservations, 0)
        XCTAssertEqual(rejected.receipts, 0)
        try await Self.pairNativeClient(port: port, invitation: invitation)
    }

    private func wait(_ observation: Observation, seconds: Int, until ready: (State) -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(seconds))
        while ContinuousClock.now < deadline {
            let snapshot = observation.value.withLock { $0 }
            if snapshot.failed { throw FixtureError.listenerFailed }
            if ready(snapshot) { return }
            try await Task.sleep(for: .milliseconds(20))
        }
        throw FixtureError.timeout
    }

    static func transcript(for proposal: PairingPhoneProposal, invitation: PairingInvitation) throws -> PairingTranscript {
        let mac = try ChannelOffer(role: .mac, scope: proposal.phone.scope, nonce: AuthorityPairingSetupAccess.secureRandom(32),
            envelopeVersions: [1], requests: [], auditVersions: [])
        let issued = UInt64(Date().timeIntervalSince1970 * 1000)
        return try PairingTranscript(setupID: AuthorityPairingSetupAccess.secureRandom(16),
            challenge: AuthorityPairingSetupAccess.secureRandom(32), phone: proposal.phone, mac: mac,
            minimumEnvelopeVersion: invitation.minimumEnvelopeVersion, selectedEnvelopeVersion: 1,
            macAuthorityKey: invitation.authorityPublicKey, macTransportKey: invitation.transportPublicKey,
            transportKey: proposal.transportKey, decisionKey: proposal.decisionKey, biometricKey: proposal.biometricKey,
            enrollmentTag: AuthorityPairingSetupAccess.secureRandom(32), replacement: proposal.replacement,
            expectedTrustRevision: Data(repeating: 1, count: 16), issuedAtUnixMillis: issued, expiresAtUnixMillis: issued + 30_000)
    }

    static func pairNativeClient(port: UInt16, invitation: PairingInvitationV2,
                                 afterVerifiedReceipt: @Sendable () async throws -> Void = {},
                                 afterChallenge: @Sendable () async -> Void = {}) async throws {
        let transport = P256.Signing.PrivateKey()
        let biometric = P256.Signing.PrivateKey()
        let scope = try ChannelScope(macID: invitation.invitation.macID, accountID: invitation.invitation.accountID,
            phoneID: invitation.replacement?.phoneID ?? Data(repeating: 3, count: 16), enrollmentEpoch: Data(repeating: 4, count: 16))
        let proposal = try PairingPhoneProposal(phone: ChannelOffer(role: .phone, scope: scope,
            nonce: AuthorityPairingSetupAccess.secureRandom(32), envelopeVersions: [1], requests: [], auditVersions: []),
            transportKey: .init(keyID: Data(repeating: 5, count: 16), publicKey: transport.publicKey.x963Representation),
            decisionKey: .init(keyID: Data(repeating: 6, count: 16), publicKey: P256.Signing.PrivateKey().publicKey.x963Representation),
            biometricKey: .init(keyID: Data(repeating: 7, count: 16), publicKey: biometric.publicKey.x963Representation), replacement: invitation.replacement)
        let (channel, connection) = try AuthorityJournalSchema19MigrationTests.fixtureConnectLookup(port: port,
            purpose: PairingSetupPreludeV2.applicationProtocol, serverKey: invitation.invitation.transportPublicKey,
            identity: AuthorityJournalSchema19MigrationTests.fixtureIdentity(transport))
        defer { channel.abort() }
        try await channel.start(timeoutMilliseconds: 2_000)
        let metadata = try XCTUnwrap(connection.metadata(definition: NWProtocolTLS.definition) as? NWProtocolTLS.Metadata)
        let label = PairingInvitationV2.exporterLabel
        let secret = try XCTUnwrap(sec_protocol_metadata_create_secret(metadata.securityProtocolMetadata, label.utf8.count, label, 32))
        let exporter = Data(DispatchData._unconditionallyBridgeFromObjectiveC(secret))
        let prelude = try await AuthorityJournalSchema19MigrationTests.fixtureReadNativeFrame(from: channel, maximum: PairingSetupPreludeV2.maximumBytes)
        guard case .challenge(let challenge) = try PairingSetupPreludeV2.decode(prelude) else { throw FixtureError.unexpectedFrame }
        await afterChallenge()
        let tag = try invitation.proof(proposal: proposal, challenge: challenge, exporter: exporter)
        try await AuthorityJournalSchema19MigrationTests.fixtureSendNativeFrame(
            PairingSetupPreludeV2.proposal(proposal, tag: tag).encode(), to: channel)
        let frame = try await AuthorityJournalSchema19MigrationTests.fixtureReadNativeFrame(from: channel, maximum: PairingSetupFrame.maximumBytes)
        guard case .transcript(let transcript) = try PairingSetupFrame.decode(frame) else { throw FixtureError.unexpectedFrame }
        try proposal.validate(transcript)
        try invitation.invitation.validateMacClaims(in: transcript)
        let digest = try transcript.digest()
        let proof = try biometric.signature(for: transcript.signingInput(purpose: .phoneBiometric)).rawRepresentation
        try await AuthorityJournalSchema19MigrationTests.fixtureSendNativeFrame(
            PairingSetupFrame.proof(setupID: transcript.setupID, digest: digest, signature: proof).encode(), to: channel)
        let response = try await AuthorityJournalSchema19MigrationTests.fixtureReadNativeFrame(from: channel, maximum: PairingSetupFrame.maximumBytes)
        guard case .receipt(let setup, let receivedDigest, let signature) = try PairingSetupFrame.decode(response) else {
            throw FixtureError.unexpectedFrame
        }
        XCTAssertEqual(setup, transcript.setupID)
        XCTAssertEqual(receivedDigest, digest)
        XCTAssertTrue(try transcript.verify(signature: signature, publicKey: invitation.invitation.authorityPublicKey, purpose: .macCommit))
        try await afterVerifiedReceipt()
        await channel.close()
    }
}
