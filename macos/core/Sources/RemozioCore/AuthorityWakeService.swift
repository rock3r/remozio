import Darwin
import Foundation
import RemozioProtocol

/// Owns the request service and its asynchronous publisher. Presence remains a required live runtime input.
public actor AuthorityWakeService {
    public nonisolated let presence: AuthorityPresenceRuntime?
    private let publisher: AuthorityWakePublisher
    private let startRequests: @Sendable () throws -> Void
    private let closeRequests: @Sendable () throws -> Void
    private let interval: UInt64
    private var task: Task<Void, Never>?
    private var started = false
    private var closed = false
    private var retired = false
    public var isRetired: Bool { retired }
    init(publisher: AuthorityWakePublisher, interval: UInt64,
         startRequests: @escaping @Sendable () throws -> Void, closeRequests: @escaping @Sendable () throws -> Void,
         presence: AuthorityPresenceRuntime? = nil) {
        self.presence = presence; self.publisher = publisher; self.interval = interval; self.startRequests = startRequests; self.closeRequests = closeRequests
    }
    deinit { task?.cancel(); presence?.close(); publisher.hintFeed.close(); if !closed { try? closeRequests() } }
    /// Restore the hardware Root signer and both protected stores before any listener starts.
    public static func open(configuration: AuthorityWakeStartupConfiguration,
                            routing: @escaping @Sendable () throws -> PresenceRouting,
                            reconcileExpired: @escaping @Sendable ([ApprovalRequestState]) throws -> Void) throws -> AuthorityWakeService {
        guard getuid() == 0, geteuid() == 0 else { throw GatewayServiceError.wrongAccount }
        let clock = try AuthorityClock()
        let journal = try AuthorityService.openJournal(configuration: configuration.request.service)
        return try compose(configuration: configuration, journal: journal, clock: clock, presence: nil, appEndpoint: nil,
            routing: routing, reconcileExpired: reconcileExpired)
    }
    public static func open(configuration: AuthorityPresenceStartupConfiguration,
                            reconcileExpired: @escaping @Sendable ([ApprovalRequestState]) throws -> Void) throws -> AuthorityWakeService {
        try open(configuration: configuration.wake, accountPresence: configuration.presence,
            appEndpoint: configuration.endpoint, reconcileExpired: reconcileExpired)
    }
    /// Enable the durable mode ledger and share one Root epoch with observations, signing and wake publication.
    /// The owning authenticated GUI endpoint supplies observations; unavailable observations keep their explicit unknown state.
    public static func open(configuration: AuthorityWakeStartupConfiguration, accountPresence: AuthorityAccountPresenceConfiguration,
                            appEndpoint: AuthorityPresenceEndpointConfiguration,
                            reconcileExpired: @escaping @Sendable ([ApprovalRequestState]) throws -> Void) throws -> AuthorityWakeService {
        guard getuid() == 0, geteuid() == 0 else { throw GatewayServiceError.wrongAccount }
        guard accountPresence.macID == configuration.request.service.macID,
              accountPresence.accountID == configuration.request.service.accountID,
              accountPresence.ownerUID != configuration.request.service.transportPolicy.expectedUserID,
              accountPresence.ownerUID != configuration.gatewayPolicy.expectedUserID,
              appEndpoint.appPolicy.expectedUserID == accountPresence.ownerUID,
              appEndpoint.serviceName != configuration.request.service.serviceName,
              appEndpoint.serviceName != configuration.gatewayServiceName else { throw AuthorityPresenceError.wrongScope }
        let clock = try AuthorityClock()
        let limits = try CBORLimits(maxBytes: 65_536, maxDepth: 16, maxItems: 4096)
        let policy = try RoutingJournalPolicy(clockEpoch: clock.epoch, challengeLifetimeMillis: 30_000, maximumOperations: 1024,
            payloadLimits: limits, signingLimits: CBORLimits(maxBytes: 131_072, maxDepth: 16, maxItems: 4096))
        let journal = try AuthorityService.openJournal(configuration: configuration.request.service, routingPolicy: policy)
        let presence = AuthorityPresenceRuntime(configuration: accountPresence, clockEpoch: clock.epoch)
        return try compose(configuration: configuration, journal: journal, clock: clock, presence: presence, appEndpoint: appEndpoint,
            routing: { throw AuthorityPresenceError.unavailable }, reconcileExpired: reconcileExpired)
    }
    private static func compose(configuration: AuthorityWakeStartupConfiguration, journal: AuthorityJournal, clock: AuthorityClock,
                                presence: AuthorityPresenceRuntime?, appEndpoint: AuthorityPresenceEndpointConfiguration?, routing: @escaping @Sendable () throws -> PresenceRouting,
                                reconcileExpired: @escaping @Sendable ([ApprovalRequestState]) throws -> Void) throws -> AuthorityWakeService {
        do {
            let signer = try EnclaveAuthorityRequestSigner.load(path: configuration.request.keyRecordPath,
                configuration: configuration.request.service, expectedPublicKey: configuration.request.authorityPublicKey, journal: journal)
            let providers: AuthorityRequestProviders
            if let presence { providers = try AuthorityRequestProviders(configuration: configuration.request.service, signer: signer, presence: presence) }
            else { providers = try AuthorityRequestProviders(configuration: configuration.request.service, signer: signer, routing: routing) }
            let channel = try GatewayRootChannel(serviceName: configuration.gatewayServiceName, gatewayPolicy: configuration.gatewayPolicy,
                timeoutMilliseconds: configuration.timeoutMilliseconds)
            let ownerRouting: (@Sendable (ApprovalRequestCoordinator, AuthorityMoment) throws -> PresenceRouting)?
            if let presence { ownerRouting = { owner, moment in try presence.routing(owner: owner, now: moment) } }
            else { ownerRouting = nil }
            let publisher = try AuthorityWakePublisher(journal: journal, channel: channel, registration: configuration.registration,
                leaseMilliseconds: configuration.leaseMilliseconds, clock: { try clock.now() }, routing: routing,
                ownerRouting: ownerRouting)
            let service = try AuthorityService(configuration: configuration.request.service, journal: journal,
                maintenanceIntervalMilliseconds: configuration.request.maintenanceIntervalMilliseconds,
                validateSelf: AuthoritySelfValidation.validate, requestClock: { try clock.now() }, requestProviders: providers,
                wakeHintFeed: publisher.hintFeed, reconcileExpired: reconcileExpired)
            let presenceListener: AuthorityPresenceXPCListener?
            if let presence, let appEndpoint {
                presenceListener = try AuthorityPresenceXPCListener(configuration: appEndpoint, journal: journal, presence: presence, clock: clock)
            } else { presenceListener = nil }
            return AuthorityWakeService(publisher: publisher, interval: configuration.pollMilliseconds,
                startRequests: { try service.start(); try presenceListener?.start() },
                closeRequests: { presenceListener?.close(); try service.close() }, presence: presence)
        } catch { presence?.close(); try? journal.close(); throw error }
    }
    public func start() async throws {
        guard !started, !closed else { throw AuthorityWakePublisherError.closed }
        started = true
        do {
            try startRequests()
            try await publisher.start()
            guard !closed else { throw AuthorityWakePublisherError.closed }
            task = Task { [weak self, publisher, interval] in
                do { try await publisher.run(intervalMilliseconds: interval) }
                catch { await self?.publisherDidStop() }
            }
        } catch { try? await close(); throw error }
    }
    public func close() async throws {
        guard !closed else { return }
        closed = true
        let previous = task; task = nil; previous?.cancel()
        await publisher.close()
        await previous?.value
        presence?.close()
        try closeRequests()
    }
    private func publisherDidStop() async {
        guard !closed else { return }
        retired = true
        task = nil // This callback runs on the terminating worker; do not await that worker from its own close path.
        try? await close()
    }
}
