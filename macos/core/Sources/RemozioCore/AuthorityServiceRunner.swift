import Foundation

/// Owns startup retries and the resulting trust service. Status is diagnostic, never action authority.
/// The synchronous status callback must not block or reenter this runner.
public final class AuthorityServiceRunner: @unchecked Sendable {
    public enum Status: Equatable, Sendable {
        case idle, starting, waiting(retryMilliseconds: Int), running, failed(AuthorityStartupFailure), closed
    }
    typealias Shutdown = @Sendable () throws -> Void
    private let lock = NSLock()
    private let stopLock = NSLock()
    private let queue = DispatchQueue(label: "dev.remozio.authority.startup")
    private let open: @Sendable () throws -> Shutdown
    private let report: @Sendable (Status) -> Void
    private let maximumRetryMilliseconds: Int
    private var retryMilliseconds: Int
    private var timer: DispatchSourceTimer?
    private var shutdown: Shutdown?
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

    /// The factory either throws after releasing its resources, or transfers one running service's shutdown operation.
    init(initialRetryMilliseconds: Int, maximumRetryMilliseconds: Int,
         open: @escaping @Sendable () throws -> Shutdown,
         report: @escaping @Sendable (Status) -> Void) throws {
        guard (100...60_000).contains(initialRetryMilliseconds),
              (initialRetryMilliseconds...300_000).contains(maximumRetryMilliseconds) else {
            throw AuthorityServiceConfigurationError.invalidConfiguration
        }
        retryMilliseconds = initialRetryMilliseconds
        self.maximumRetryMilliseconds = maximumRetryMilliseconds
        self.open = open; self.report = report
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
    private func attempt() {
        lock.withLock {
            guard !isStopping, shutdown == nil else { return }
            timer?.cancel(); timer = nil
            setStatus(.starting)
            do {
                shutdown = try open()
                if isStopping { return } // The waiting close call owns disposal of this new service.
                setStatus(.running)
            } catch {
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
