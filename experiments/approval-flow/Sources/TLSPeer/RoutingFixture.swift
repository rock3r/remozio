#if !DEBUG
#error("The routing fixture must never enter a release build")
#endif

import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
@testable import RemozioCore

/// Disposable normal-user Root and IPC shim. Native TLS and the production Transport handler remain real.
/// This fixture does not qualify OS caller validation, installed XPC, Secure Enclave custody or pairing.
final class RoutingFixture: @unchecked Sendable {
    let clock: AuthorityClock
    let journal: AuthorityJournal
    let providers: AuthorityRequestProviders
    let access: AuthorityTransportAccess
    let presence: AuthorityPresenceRuntime
    let authorityPublicKey: Data
    private let auditWriter: AuditEpochWriter
    private let auditEpoch: Data
    private let commandRequestID: Data?
    private let wall = Wall()
    private let limits: CBORLimits
    private final class Wall: @unchecked Sendable {
        private let lock = NSLock()
        private var offset: UInt64 = 0
        func advance() { lock.withLock { offset += 60_000 } }
        func now() -> UInt64? { lock.withLock {
            let value = Date().timeIntervalSince1970 * 1000
            guard value.isFinite, value >= 0, value < Double(UInt64.max) else { return nil }
            let result = UInt64(value).addingReportingOverflow(offset)
            return result.overflow ? nil : result.partialValue
        } }
    }
    init(directory: String, phoneTransport: Data, decision: Data, biometric: Data, supported: Bool,
         auditSupported: Bool = false, maximumPayloadBytes: Int = 16_384, commandCapture: Data? = nil) throws {
        guard getuid() != 0, geteuid() != 0, let canonical = realpath(directory, nil) else { throw ProbeError.invalidInput }
        defer { free(canonical) }
        let root = String(cString: canonical), store = root + "/routing-journal"
        guard mkdir(store, 0o700) == 0 else { throw ProbeError.invalidInput }
        for name in ["writer.lock", "journal.sqlite"] {
            let fd = Darwin.open(store + "/" + name, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0o600)
            guard fd >= 0 else { throw ProbeError.invalidInput }; Darwin.close(fd)
        }
        let clock = try AuthorityClock(), limits = try CBORLimits(maxBytes: 16_384, maxDepth: 12, maxItems: 1024)
        self.clock = clock; self.limits = limits
        let database = try JournalDatabase(lease: ProtectedJournalLease(anchor: root, relativeDirectory: "routing-journal", owner: getuid()),
            macID: Self.id(1), accountID: Self.id(2), recordLimits: limits, descriptorLimits: limits, decisionLimits: limits,
            maximumConsumptions: 32, busyMilliseconds: 100, initialize: true,
            routingPolicy: RoutingJournalPolicy(clockEpoch: clock.epoch, challengeLifetimeMillis: 30_000, maximumOperations: 32,
                payloadLimits: limits, signingLimits: limits))
        let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1)
        let trust = try database.write { try $0.configureApprovalAuthority(capabilities: .init(contracts: [contract: []]), allowedContracts: [contract]) }
        let descriptor = try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(Self.id(1)), 2: .bytes(Self.id(2)), 3: .bytes(Self.id(8)),
            4: .unsigned(7), 5: .unsigned(1), 6: .null, 7: .null, 8: .null,
        ]), limits: limits), limits: limits)
        let writer = try database.write { try $0.createEpoch(descriptor) }; self.auditEpoch = writer.epoch; self.auditWriter = writer
        let phoneContract = try RequestContract(requestKind: commandCapture == nil ? .onePasswordAccess : .command, wireVersion: 1, schemaVersion: 1)
        let enrollment = try StoredApprovalEnrollment(epoch: Self.id(4), notificationTag: Data(repeating: 5, count: 32),
            identityPublicKey: P256.Signing.PublicKey(derRepresentation: phoneTransport).x963Representation,
            approval: ApprovalEnrollment(phoneID: Self.id(3), active: true, capabilities: .init(contracts: [phoneContract: []]), keys: [
                EnrolledApprovalKey(id: Self.id(6), keyClass: .decision, publicKey: decision),
                EnrolledApprovalKey(id: Self.id(7), keyClass: .biometric, publicKey: biometric),
            ]))
        _ = try database.write { try $0.addApprovalEnrollment(enrollment, expectedTrustRevision: trust,
            eventID: Self.id(9), receiptTimeMs: nil, writer: writer, expectedAuditHead: 0) }
        _ = try database.write { try $0.installCodePolicy(AuthorityCodePolicy(entries: [AuthorityCodeEntry(role: .transport,
            teamID: "SYNTHETIC1", identifier: "dev.remozio.fixture.transport", installedGeneration: 1, minimumGeneration: 1,
            codeDirectoryHash: Data(repeating: 7, count: 20), active: true)]), expectedRevision: nil) }
        let owner = try ApprovalRequestCoordinator(database: database, writer: writer, clockEpoch: clock.epoch,
            maximumRequests: 4, maximumRetainedBytes: 65_536, requestLimits: limits, captureLimits: limits,
            decisionLimits: limits, signingLimits: limits, auditLimits: limits)
        let journal = AuthorityJournal(requests: owner); self.journal = journal
        let presence = try AuthorityPresenceRuntime(configuration: .init(macID: Self.id(1), accountID: Self.id(2), ownerUID: getuid(),
            policy: .init(observationLifetimeMilliseconds: 1000, unavailableGraceMilliseconds: 0)), clockEpoch: clock.epoch)
        self.presence = presence
        let key = P256.Signing.PrivateKey(), raw = key.rawRepresentation
        authorityPublicKey = key.publicKey.x963Representation
        let configuration = try AuthorityServiceConfiguration(macID: Self.id(1), accountID: Self.id(2), journalDirectory: store,
            serviceName: "dev.remozio.fixture.routing", teamID: "SYNTHETIC1", transportIdentifier: "dev.remozio.fixture.transport",
            transportHashes: [Data(repeating: 7, count: 20)], transportUID: getuid(), maximumPayloadBytes: maximumPayloadBytes, auditVersions: auditSupported ? [1] : [])
        let wall = self.wall
        providers = try AuthorityRequestProviders(configuration: configuration, publicKey: authorityPublicKey,
            signing: { try P256.Signing.PrivateKey(rawRepresentation: raw).signature(for: $0).rawRepresentation },
            routing: { throw AuthorityPresenceError.unavailable }, presence: presence,
            routingWallTime: supported ? { @Sendable in wall.now() } : nil)
        access = try AuthorityTransportAccess(journal: journal, peerPolicy: configuration.transportPolicy, macID: Self.id(1), accountID: Self.id(2),
            maximumPayloadBytes: maximumPayloadBytes, minimumEnvelopeVersion: 1, auditVersions: auditSupported ? [1] : [])
        commandRequestID = try journal.withRequests { owner in
            let now = try clock.now()
            _ = try owner.setLocalRoutingMode(commandCapture == nil ? .present : .away,
                expectedRevision: 0, now: now, receiptTimeMs: nil)
            guard let commandCapture else { return nil }
            let window: UInt64 = 60_000
            // This fixture retains only the capture bytes. It has no command target or execution owner.
            return try owner.admitFixture(ApprovalRequestDraft(contract: contract, requiredFeatures: [], capture: commandCapture,
                actions: [.init(choice: .execute, scope: .currentRequest), .init(choice: .decline, scope: .currentRequest)],
                firstObservedAt: now, deadlineMilliseconds: now.milliseconds + window,
                createdUnixMilliseconds: 1000, expiresUnixMilliseconds: 1000 + window),
                now: now, receiptTimeMs: nil).requestID
        }
    }
    func driver() throws -> any AuthorityXPCDriver {
        let access = access, providers = providers, clock = clock
        let routing: (@Sendable (AuthorityPeerBinding, PhoneRoutingFrame) throws -> PhoneRoutingFrame)?
        if let provider = providers.phoneRouting {
            routing = { binding, frame in try access.phoneRouting(binding: binding, frame: frame,
                handler: { try provider($0, $1, $2, { try clock.now() }) }) }
        } else { routing = nil }
        let audit: (@Sendable (AuthorityPeerBinding, PhoneAuditFrame) throws -> PhoneAuditFrame)?
        if let provider = providers.phoneAudit {
            audit = { binding, frame in try access.phoneAudit(binding: binding, frame: frame,
                handler: { try provider($0, $1, $2, { try clock.now() }, $3) }) }
        } else { audit = nil }
        let requestFrame: (@Sendable (AuthorityPeerBinding, Data) throws -> Data?)?
        let pending: (@Sendable (AuthorityPeerBinding) throws -> [Data])?
        let exchange: (@Sendable (AuthorityPeerBinding, AuthorityRequestExchange.Query) throws -> Data?)?
        if commandRequestID != nil {
            requestFrame = { binding, id in
                try access.requestFrame(binding: binding, requestID: id,
                    handler: { try providers.requestFrame($0, $1, $2, { try clock.now() }) })
            }
            pending = { binding in
                try access.pendingRequestIDs(binding: binding,
                    handler: { try providers.pendingRequestIDs($0, $1, { try clock.now() }) })
            }
            exchange = { binding, query in
                try access.exchangeRequest(binding: binding, query: query,
                    handler: { try providers.exchangeRequest($0, $1, $2, { try clock.now() }) })
            }
        } else {
            requestFrame = nil; pending = nil; exchange = nil
        }
        let endpoint = try AuthorityXPCEndpoint(macID: Self.id(1), accountID: Self.id(2), budget: AuthorityXPCWorkBudget(),
            activityJournal: journal, verify: {}, verifyHandshakePolicy: { try access.verifyCurrent() }, invalidate: {},
            snapshot: { try access.snapshot() }, validate: { try access.validate($0) }, requestFrame: requestFrame,
            pendingRequestIDs: pending, exchangeRequest: exchange, phoneAudit: audit, phoneRouting: routing)
        return RoutingFixtureDriver(endpoint)
    }
    func control(_ command: String) throws -> [String: UInt64] {
        switch command {
        case "present":
            let clock = clock
            _ = try journal.withRequests { owner in
                try owner.setLocalRoutingMode(.present, expectedRevision: owner.localRoutingState().revision, now: clock.now(), receiptTimeMs: nil)
            }
        case "audit-seed":
            let clock = clock
            for index in 0..<12 {
                _ = try journal.withRequests { owner in
                    try owner.setLocalRoutingMode(index % 2 == 0 ? .automatic : .present,
                        expectedRevision: owner.localRoutingState().revision, now: clock.now(), receiptTimeMs: nil)
                }
            }
        case "audit-prune":
            try journal.write { tx in
                guard let epoch = try tx.epoch(self.auditEpoch) else { throw ProbeError.invalidInput }
                try tx.prune(epoch: self.auditEpoch, through: epoch.head, expectedHead: epoch.head)
            }
        case "audit-revoke":
            _ = try journal.write { tx in
                guard let epoch = try tx.epoch(self.auditEpoch) else { throw ProbeError.invalidInput }
                return try tx.revokeApprovalEnrollment(phoneID: Self.id(3), epoch: Self.id(4),
                    expectedTrustRevision: tx.approvalTrustSnapshot().revision, eventID: Self.id(11),
                    receiptTimeMs: nil, writer: self.auditWriter, expectedAuditHead: epoch.head)
            }
        case "expire": wall.advance()
        case "command-snapshot":
            guard let requestID = commandRequestID else { throw ProbeError.invalidInput }
            let epoch = auditEpoch, limits = limits
            return try journal.read { tx in
                let receipt = try tx.consumption(requestID: requestID)
                let page = try tx.page(epoch: epoch, after: 0, maximumRecords: 64, maximumBytes: 16_384)
                let records = try page.canonicalRecords.map { try AuditEventMetadata.decode($0, limits: limits) }
                    .filter { $0.requestID == requestID }
                return ["receipt": receipt == nil ? 0 : 1,
                    "consumed": UInt64(records.filter { $0.kind == .consumed }.count),
                    "dispatched": UInt64(records.filter { $0.kind == .dispatched }.count)]
            }
        case "snapshot": break
        default: throw ProbeError.invalidInput
        }
        let epoch = auditEpoch, limits = limits
        return try journal.read { tx in
            let state = try tx.routingState()
            let page = try tx.page(epoch: epoch, after: 0, maximumRecords: 64, maximumBytes: 16_384)
            let records = try page.canonicalRecords.map { try AuditEventMetadata.decode($0, limits: limits) }
            return ["revision": state.revision, "routingEvents": UInt64(records.filter { $0.kind == .routingChanged }.count),
                "head": try tx.epoch(epoch)?.head ?? 0]
        }
    }
    func close() throws { presence.close(); try journal.close() }
    private static func id(_ n: UInt8) -> Data { Data(repeating: n, count: 16) }
}

/// Only the RPC carrier is simulated. The endpoint, role policy, journal owner and routing provider remain real.
private final class RoutingFixtureDriver: AuthorityXPCDriver, @unchecked Sendable {
    private let endpoint: AuthorityXPCEndpoint
    init(_ endpoint: AuthorityXPCEndpoint) { self.endpoint = endpoint }
    func start(invalidated: @escaping @Sendable () -> Void) {}
    func hello(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { endpoint.hello { reply(.hello($0)) } }
    func snapshot(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { endpoint.trustSnapshot { reply($0.map(AuthorityXPCReply.snapshot) ?? .failed) } }
    func validate(_ binding: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { endpoint.validatePeer(binding) { reply(.validation($0)) } }
    func deliveryVersion(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
        endpoint.requestDeliveryVersion { reply(.deliveryVersion($0)) }
    }
    func requestFrame(_ binding: Data, requestID: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
        endpoint.requestFrame(binding, requestID: requestID) { reply($0.map(AuthorityXPCReply.requestFrame) ?? .failed) }
    }
    func discoveryVersion(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
        endpoint.requestDiscoveryVersion { reply(.discoveryVersion($0)) }
    }
    func pendingRequests(_ binding: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
        endpoint.pendingRequestIDs(binding) { reply($0.map(AuthorityXPCReply.pendingRequests) ?? .failed) }
    }
    func exchangeVersion(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
        endpoint.requestExchangeVersion { reply(.exchangeVersion($0)) }
    }
    func exchange(_ binding: Data, query: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
        endpoint.exchangeRequest(binding, query: query) { reply($0.map(AuthorityXPCReply.exchange) ?? .failed) }
    }
    func auditVersion(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { endpoint.phoneAuditVersion { reply(.auditVersion($0)) } }
    func audit(_ binding: Data, frame: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
        endpoint.phoneAudit(binding, frame: frame) { reply($0.map(AuthorityXPCReply.audit) ?? .failed) }
    }
    func routingVersion(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { endpoint.phoneRoutingVersion { reply(.routingVersion($0)) } }
    func routing(_ binding: Data, frame: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
        endpoint.phoneRouting(binding, frame: frame) { reply($0.map(AuthorityXPCReply.routing) ?? .failed) }
    }
    func close() { endpoint.close() }
}
