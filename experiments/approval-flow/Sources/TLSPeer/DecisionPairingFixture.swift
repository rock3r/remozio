#if !DEBUG
#error("The decision proof fixture must not enter a release build")
#endif

import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import Security
import Synchronization
@testable import RemozioCore

/// Real loopback TLS and a checkpointed pairing commit. Native XPC identity, administrator consent
/// and hardware custody are outside this normal-user fixture.
// The listener drains before close releases the fixture-owned continuity store.
private final class DecisionPairingFixture: @unchecked Sendable {
    let journal: AuthorityJournal
    let endpoint: AuthorityPairingXPCEndpoint
    let invitation: PairingInvitationV2
    private let requiresDecisionProof: Bool
    private let continuity: ContinuityStore
    private let auditEpoch: Data
    private let initialHead: UInt64
    private final class SigningCount: Sendable { let value = Mutex(0) }
    private let signed: SigningCount
    private let authorization = Data(count: MemoryLayout<AuthorizationExternalForm>.size)

    init(directory: String, transport: Data, rePair: Bool, requiresDecisionProof: Bool) throws {
        self.requiresDecisionProof = requiresDecisionProof
        guard let canonical = realpath(directory, nil) else { throw ProbeError.invalidInput }
        defer { free(canonical) }
        let root = String(cString: canonical)
        try Self.createStore(root: root, directory: "pairing-journal", file: "journal.sqlite")
        try Self.createStore(root: root, directory: "pairing-continuity", file: "continuity.sqlite")
        let mac = Self.id(1), account = Self.id(2)
        let clock = try AuthorityClock()
        let limits = try CBORLimits(maxBytes: 16_384, maxDepth: 12, maxItems: 1_024)
        let database = try JournalDatabase(lease: .init(anchor: root, relativeDirectory: "pairing-journal", owner: getuid()),
            macID: mac, accountID: account, recordLimits: limits, descriptorLimits: limits, decisionLimits: limits,
            maximumConsumptions: 32, busyMilliseconds: 100, initialize: true)
        let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1)
        let app = try AuthorityCodeEntry(role: .app, teamID: "SYNTHETIC1", identifier: "dev.remozio.fixture.pairing",
            installedGeneration: 1, minimumGeneration: 1, codeDirectoryHash: Data(repeating: 4, count: 20), active: true)
        let descriptor = try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(mac), 2: .bytes(account), 3: .bytes(Self.id(8)), 4: .unsigned(1),
            5: .unsigned(1), 6: .null, 7: .null, 8: .null,
        ]), limits: limits), limits: limits)
        let capabilities = ContractCapabilities(contracts: [contract: []])
        let writer = try database.write { tx in
            let trust = try tx.configureApprovalAuthority(capabilities: capabilities, allowedContracts: [contract])
            let writer = try tx.createEpoch(descriptor)
            _ = try tx.installCodePolicy(.init(entries: [app]), expectedRevision: nil)
            if rePair {
                let old = try StoredApprovalEnrollment(epoch: Self.id(10), notificationTag: Data(repeating: 11, count: 32),
                    identityPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
                    approval: .init(phoneID: Self.id(3), active: true, capabilities: capabilities, keys: [
                        .init(id: Self.id(12), keyClass: .decision, publicKey: P256.Signing.PrivateKey().publicKey.x963Representation),
                        .init(id: Self.id(13), keyClass: .biometric, publicKey: P256.Signing.PrivateKey().publicKey.x963Representation),
                    ]))
                let revision = try tx.addApprovalEnrollment(old, expectedTrustRevision: trust, eventID: Self.id(14),
                    receiptTimeMs: nil, writer: writer, expectedAuditHead: 0)
                _ = try tx.revokeApprovalEnrollment(phoneID: old.approval.phoneID, epoch: old.epoch, expectedTrustRevision: revision,
                    eventID: Self.id(15), receiptTimeMs: nil, writer: writer, expectedAuditHead: 1)
            }
            return writer
        }
        auditEpoch = writer.epoch
        initialHead = try database.read { tx in
            guard let epoch = try tx.epoch(writer.epoch) else { throw ProbeError.invalidInput }
            return epoch.head
        }
        let checkpoint = try database.read {
            try CheckpointedJournal.checkpoint(transaction: $0, epoch: writer.epoch, generation: 1, authorityGeneration: 1)
        }
        let continuity = try ContinuityStore(lease: .init(anchor: root, relativeDirectory: "pairing-continuity", owner: getuid()),
            macID: mac, accountID: account, initialize: checkpoint)
        self.continuity = continuity
        let coordinator = try ApprovalRequestCoordinator(database: database, continuity: continuity, writer: writer,
            clockEpoch: clock.epoch, maximumRequests: 4, maximumRetainedBytes: 65_536, requestLimits: limits,
            captureLimits: limits, decisionLimits: limits, signingLimits: limits, auditLimits: limits)
        let journal = AuthorityJournal(requests: coordinator)
        self.journal = journal
        let authority = P256.Signing.PrivateKey()
        let signed = SigningCount()
        self.signed = signed
        let policy = try XPCPeerPolicy(teamID: app.teamID, componentIdentifier: app.identifier,
            approvedCodeDirectoryHashes: [app.codeDirectoryHash], expectedUserID: getuid())
        let access = try AuthorityPairingSetupAccess(journal: journal, macID: mac, accountID: account,
            authorityPublicKey: authority.publicKey.x963Representation, appPolicy: policy,
            configuration: .init(transportPublicKey: transport, lifetimeMilliseconds: 30_000, decisionProofRequired: requiresDecisionProof),
            minimumEnvelopeVersion: 1, auditVersions: [], now: clock.now,
            unixMilliseconds: { UInt64(Date().timeIntervalSince1970 * 1000) }, validateSelf: { _ in },
            commit: { attempt, proof, event, authorize, validate in
                try journal.commitPairingFixture(attempt, biometricProof: proof, authorityPublicKey: authority.publicKey.x963Representation,
                    addEventID: event, recheckAdministrator: authorize, now: clock.now, validate: validate, sign: {
                        let signature = try authority.signature(for: $0).rawRepresentation
                        signed.value.withLock { $0 += 1 }
                        return signature
                    })
            })
        let endpoint = AuthorityPairingXPCEndpoint(access: access, budget: try AuthorityXPCWorkBudget(),
            verify: {}, authorize: { _ in }, invalidate: {})
        self.endpoint = endpoint
        let version = Mutex<UInt64>(0)
        endpoint.pairingHello { reply in version.withLock { $0 = reply } }
        guard version.withLock({ $0 }) == 1 else { throw ProbeError.invalidInput }
        let predecessor: PairedPhoneSelection?
        if rePair {
            let phones = try access.pairedPhones(includeRePair: true)
            guard let selection = phones.rePairSelection(for: DeliveryRecipient(phoneID: Self.id(3), enrollmentEpoch: Self.id(10))) else {
                throw ProbeError.invalidInput
            }
            predecessor = selection
        } else { predecessor = nil }
        let reply = Mutex<Data?>(nil)
        endpoint.openPairingV2(label: "Decision proof fixture", predecessor: predecessor) { value in
            reply.withLock { $0 = value }
        }
        guard let bytes = reply.withLock({ $0 }) else { throw ProbeError.invalidInput }
        invitation = try .decode(bytes)
    }

    func handle(_ session: PairingSetupNetworkSession, peerPoint: Data, legacyCommit: Bool) async throws {
        let proposal = try await session.proposal()
        guard proposal.transportKey.publicKey == peerPoint, let connection = await session.provedConnection else {
            throw ProbeError.invalidInput
        }
        let staged = Mutex<Data?>(nil)
        endpoint.stagePairingV2(try proposal.encode(), connection: connection, authorization: authorization) { value in
            staged.withLock { $0 = value }
        }
        guard let bytes = staged.withLock({ $0 }) else { throw ProbeError.invalidInput }
        let transcript = try PairingTranscript.decode(bytes)
        try await session.stage(transcript)
        let proof: PairingPhoneProof
        do { proof = try await session.receivePhoneProof() }
        catch PairingSetupChannelError.rejected {
            try report(phase: 1, transcript: transcript, receipts: 0)
            return
        }
        guard (proof.decision != nil) == requiresDecisionProof else { throw ProbeError.invalidInput }
        let receipt = Mutex<Data?>(nil)
        let reply: @Sendable (Data?) -> Void = { value in receipt.withLock { $0 = value } }
        let digest = try transcript.digest()
        if let decision = proof.decision, !legacyCommit {
            endpoint.commitPairingWithDecisionProof(transcript.setupID, confirmedDigest: digest, biometricProof: proof.biometric,
                decisionProof: decision, authorization: authorization, reply: reply)
        } else {
            endpoint.commitPairing(transcript.setupID, confirmedDigest: digest, biometricProof: proof.biometric,
                authorization: authorization, reply: reply)
        }
        guard let signature = receipt.withLock({ $0 }) else {
            try report(phase: 2, transcript: transcript, receipts: 0)
            return
        }
        try await session.sendReceipt(signature)
        try report(phase: 3, transcript: transcript, receipts: 1)
    }

    private func report(phase: Int, transcript: PairingTranscript, receipts: Int) throws {
        let scope = transcript.phone.scope
        let fields = try journal.read { tx -> [String: Int] in
            let commit = try tx.committedPairing(setupID: transcript.setupID, authenticatedPhoneID: scope.phoneID,
                authenticatedEnrollmentEpoch: scope.enrollmentEpoch)
            let rows = try tx.approvalEnrollments()
            guard let head = try tx.epoch(auditEpoch)?.head, head >= initialHead else { throw ProbeError.invalidInput }
            let predecessorRevoked = transcript.replacement.map { prior in
                rows.contains { $0.approval.phoneID == prior.phoneID && $0.epoch == prior.epoch && !$0.approval.active }
            } ?? false
            return ["phase": phase, "commits": commit == nil ? 0 : 1, "auditDelta": Int(head - initialHead),
                "active": rows.filter(\.approval.active).count, "predecessorRevoked": predecessorRevoked ? 1 : 0,
                "receiptSignatures": signed.value.withLock { $0 }, "receipts": receipts]
        }
        emit(fields)
    }

    func close() throws {
        endpoint.close()
        try journal.close()
        continuity.close()
    }

    private static func id(_ byte: UInt8) -> Data { Data(repeating: byte, count: 16) }

    private static func createStore(root: String, directory: String, file: String) throws {
        let path = root + "/" + directory
        guard mkdir(path, 0o700) == 0 else { throw ProbeError.invalidInput }
        for name in ["writer.lock", file] {
            let fd = Darwin.open(path + "/" + name, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0o600)
            guard fd >= 0 else { throw ProbeError.invalidInput }
            Darwin.close(fd)
        }
    }
}

func runDecisionPairingFixture(identity: SecIdentity, peer: Data, directory: String, rePair: Bool,
                               requiresDecisionProof: Bool, legacyCommit: Bool) throws -> Never {
    var certificate: SecCertificate?
    guard SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess, let certificate,
          let key = SecCertificateCopyKey(certificate), let transport = SecKeyCopyExternalRepresentation(key, nil) as Data? else {
        throw ProbeError.invalidInput
    }
    let peerPoint = try P256.Signing.PublicKey(derRepresentation: peer).x963Representation
    let fixture = try DecisionPairingFixture(directory: directory, transport: transport, rePair: rePair,
        requiresDecisionProof: requiresDecisionProof)
    let invitation = fixture.invitation
    let invitationText = try invitation.exportText()
    let ingress = PairingSetupV2Ingress(windowID: invitation.windowID, lifetimeMilliseconds: invitation.lifetimeMilliseconds,
        reserve: { try fixture.endpoint.reservePairingV2($0) },
        disconnect: { fixture.endpoint.disconnectPairingV2($0) })
    let listener = try PairingSetupListener(identity: identity, invitation: invitation.invitation, binding: .loopback,
        maximumConnections: 2, handshakeTimeoutMilliseconds: 5_000, setupTimeoutMilliseconds: 15_000, v2: ingress,
        requiresDecisionProof: requiresDecisionProof, event: { event in
            switch event {
            case .ready(let port):
                guard let bytes = try? JSONSerialization.data(withJSONObject: ["port": Int(port), "invitation": invitationText]) else {
                    exit(1)
                }
                FileHandle.standardOutput.write(bytes + Data([10]))
            case .failed: exit(1)
            case .stopped: break
            }
        }, handler: { session in
            do { try await fixture.handle(session, peerPoint: peerPoint, legacyCommit: legacyCommit) }
            catch { emit(["phase": 0]); throw error }
        })
    try listener.start()
    DispatchQueue.global().async {
        _ = getchar()
        Task {
            await listener.closeAndWait()
            do { try fixture.close(); exit(0) }
            catch { exit(1) }
        }
    }
    dispatchMain()
}
