import Foundation

/// Owns startup retries and the resulting trust service. Status is diagnostic, never action authority.
/// The synchronous status callback must not block or reenter this runner.
public final class AuthorityServiceRunner: @unchecked Sendable {
    public enum Status: Equatable, Sendable {
        case idle, starting, waiting(retryMilliseconds: Int), running, retired, failed(AuthorityStartupFailure), closed
    }
    typealias Shutdown = @Sendable () throws -> Void
    typealias Retirement = @Sendable () -> Void
    private let lock = NSLock()
    private let stopLock = NSLock()
    private let queue = DispatchQueue(label: "dev.remozio.authority.startup")
    private let open: @Sendable (@escaping Retirement) throws -> Shutdown
    private let report: @Sendable (Status) -> Void
    private let maximumRetryMilliseconds: Int
    private var retryMilliseconds: Int
    private var timer: DispatchSourceTimer?
    private var shutdown: Shutdown?
    private var activeAttempt: UUID?
    private var stopRequested = false
    private var started = false
    private var currentStatus = Status.idle

    /// Every attempt reloads protected configuration and performs the complete configured storage validation.
    public convenience init(configurationPath: String, initialRetryMilliseconds: Int = 1000,
                            maximumRetryMilliseconds: Int = 30_000,
                            report: @escaping @Sendable (Status) -> Void) throws {
        try self.init(initialRetryMilliseconds: initialRetryMilliseconds,
            maximumRetryMilliseconds: maximumRetryMilliseconds, open: {
                let configuration = try AuthorityServiceConfiguration.load(path: configurationPath)
                let service = try AuthorityService(configuration: configuration)
                try service.start()
                return { try service.close() }
            }, report: report)
    }

    /// Every retry reloads protected request inputs and restores the pinned hardware signer. There is no trust-only fallback.
    /// Presence and target cleanup belong to the runtime owner. Their callbacks must not reenter the service or journal.
    public convenience init(requestConfigurationPath: String,
                            routing: @escaping @Sendable () throws -> PresenceRouting,
                            reconcileExpired: @escaping @Sendable ([ApprovalRequestState]) throws -> Void,
                            initialRetryMilliseconds: Int = 1000, maximumRetryMilliseconds: Int = 30_000,
                            report: @escaping @Sendable (Status) -> Void) throws {
        try self.init(requestConfiguration: { try AuthorityRequestStartupConfiguration.load(path: requestConfigurationPath) },
            openRequestService: { configuration, retired in
                let service = try AuthorityService(requestStartup: configuration, routing: routing, reconcileExpired: reconcileExpired,
                    onMaintenanceFailure: retired)
                try service.start()
                return { try service.close() }
            }, initialRetryMilliseconds: initialRetryMilliseconds, maximumRetryMilliseconds: maximumRetryMilliseconds, report: report)
    }

    /// Fixture loading seam for the same reload-before-open retry composition.
    convenience init(requestConfiguration: @escaping @Sendable () throws -> AuthorityRequestStartupConfiguration,
                     openRequestService: @escaping @Sendable (AuthorityRequestStartupConfiguration, @escaping Retirement) throws -> Shutdown,
                     initialRetryMilliseconds: Int = 1000, maximumRetryMilliseconds: Int = 30_000,
                     report: @escaping @Sendable (Status) -> Void) throws {
        try self.init(initialRetryMilliseconds: initialRetryMilliseconds, maximumRetryMilliseconds: maximumRetryMilliseconds,
            openReportingRetirement: { retired in try openRequestService(requestConfiguration(), retired) }, report: report)
    }

    /// The factory either throws after releasing its resources, or transfers one running service's shutdown operation.
    convenience init(initialRetryMilliseconds: Int, maximumRetryMilliseconds: Int,
                     open: @escaping @Sendable () throws -> Shutdown,
                     report: @escaping @Sendable (Status) -> Void) throws {
        try self.init(initialRetryMilliseconds: initialRetryMilliseconds, maximumRetryMilliseconds: maximumRetryMilliseconds,
            openReportingRetirement: { _ in try open() }, report: report)
    }

    private init(initialRetryMilliseconds: Int, maximumRetryMilliseconds: Int,
                 openReportingRetirement: @escaping @Sendable (@escaping Retirement) throws -> Shutdown,
                 report: @escaping @Sendable (Status) -> Void) throws {
        guard (100...60_000).contains(initialRetryMilliseconds),
              (initialRetryMilliseconds...300_000).contains(maximumRetryMilliseconds) else {
            throw AuthorityServiceConfigurationError.invalidConfiguration
        }
        retryMilliseconds = initialRetryMilliseconds
        self.maximumRetryMilliseconds = maximumRetryMilliseconds
        self.open = openReportingRetirement; self.report = report
    }

    deinit { timer?.cancel(); try? shutdown?() }

    public var status: Status { lock.withLock { currentStatus } }

    public func start() throws {
        try lock.withLock {
            guard !started, !isStopping else { throw AuthorityXPCEndpointError.unavailable }
            started = true
            queue.async { [weak self] in self?.attempt() }
        }
    }

    /// Prevents further attempts, waits for an active attempt, and closes any service that it produced.
    public func close() throws {
        stopLock.withLock { stopRequested = true }
        try lock.withLock {
            timer?.cancel(); timer = nil
            activeAttempt = nil
            if let shutdown { try shutdown(); self.shutdown = nil }
            setStatus(.closed)
        }
    }

    private var isStopping: Bool { stopLock.withLock { stopRequested } }
    private func setStatus(_ status: Status) {
        guard currentStatus != status else { return }
        currentStatus = status
        report(status)
    }
    private func retire(attempt: UUID) {
        lock.withLock {
            guard !isStopping, activeAttempt == attempt, shutdown != nil else { return }
            setStatus(.retired)
        }
    }
    private final class RetirementSignal: @unchecked Sendable {
        private let lock = NSLock()
        private var marked = false
        func mark() -> Bool { lock.withLock { guard !marked else { return false }; marked = true; return true } }
        var isMarked: Bool { lock.withLock { marked } }
    }
    private func attempt() {
        lock.withLock {
            guard !isStopping, shutdown == nil else { return }
            timer?.cancel(); timer = nil
            setStatus(.starting)
            let attempt = UUID(), retirement = RetirementSignal()
            activeAttempt = attempt
            do {
                shutdown = try open { [weak self] in
                    guard retirement.mark() else { return }
                    self?.queue.async { [weak self] in self?.retire(attempt: attempt) }
                }
                if isStopping { return } // The waiting close call owns disposal of this new service.
                setStatus(retirement.isMarked ? .retired : .running)
            } catch {
                activeAttempt = nil
                guard !isStopping else { return }
                let failure = AuthorityStartupFailure(error: error)
                guard failure == .temporaryStorageFailure else {
                    setStatus(.failed(failure))
                    return
                }
                let delay = retryMilliseconds
                retryMilliseconds = min(delay * 2, maximumRetryMilliseconds)
                let timer = DispatchSource.makeTimerSource(queue: queue)
                timer.schedule(deadline: .now() + .milliseconds(delay), leeway: .milliseconds(10))
                timer.setEventHandler { [weak self] in self?.attempt() }
                self.timer = timer
                timer.resume()
                setStatus(.waiting(retryMilliseconds: delay))
            }
        }
    }
}
