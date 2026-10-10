import Darwin
import Foundation

/// Owns the request service and its asynchronous publisher. Presence remains a required live runtime input.
public actor AuthorityWakeService {
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
         startRequests: @escaping @Sendable () throws -> Void, closeRequests: @escaping @Sendable () throws -> Void) {
        self.publisher = publisher; self.interval = interval; self.startRequests = startRequests; self.closeRequests = closeRequests
    }
    deinit { task?.cancel(); publisher.hintFeed.close(); if !closed { try? closeRequests() } }
    /// Restore the hardware Root signer and both protected stores before any listener starts.
    public static func open(configuration: AuthorityWakeStartupConfiguration,
                            routing: @escaping @Sendable () throws -> PresenceRouting,
                            reconcileExpired: @escaping @Sendable ([ApprovalRequestState]) throws -> Void) throws -> AuthorityWakeService {
        guard getuid() == 0, geteuid() == 0 else { throw GatewayServiceError.wrongAccount }
        let journal = try AuthorityService.openJournal(configuration: configuration.request.service)
        do {
            let clock = try AuthorityClock()
            let signer = try EnclaveAuthorityRequestSigner.load(path: configuration.request.keyRecordPath,
                configuration: configuration.request.service, expectedPublicKey: configuration.request.authorityPublicKey, journal: journal)
            let providers = try AuthorityRequestProviders(configuration: configuration.request.service, signer: signer, routing: routing)
            let channel = try GatewayRootChannel(serviceName: configuration.gatewayServiceName, gatewayPolicy: configuration.gatewayPolicy,
                timeoutMilliseconds: configuration.timeoutMilliseconds)
            let publisher = try AuthorityWakePublisher(journal: journal, channel: channel, registration: configuration.registration,
                leaseMilliseconds: configuration.leaseMilliseconds, clock: { try clock.now() }, routing: routing)
            let service = try AuthorityService(configuration: configuration.request.service, journal: journal,
                maintenanceIntervalMilliseconds: configuration.request.maintenanceIntervalMilliseconds,
                validateSelf: AuthoritySelfValidation.validate, requestClock: { try clock.now() }, requestProviders: providers,
                wakeHintFeed: publisher.hintFeed, reconcileExpired: reconcileExpired)
            return AuthorityWakeService(publisher: publisher, interval: configuration.pollMilliseconds,
                startRequests: { try service.start() }, closeRequests: { try service.close() })
        } catch { try? journal.close(); throw error }
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
        try closeRequests()
    }
    private func publisherDidStop() async {
        guard !closed else { return }
        retired = true
        task = nil // This callback runs on the terminating worker; do not await that worker from its own close path.
        try? await close()
    }
}
