import Foundation

/// Serial, non-overlapping authority maintenance. Callbacks must not reenter the service owner.
final class AuthorityMaintenanceLoop: @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private let interval: Int
    private let work: @Sendable () throws -> Void
    private let failed: @Sendable () -> Void
    private var timer: DispatchSourceTimer?
    private var started = false
    private var closed = false

    init(intervalMilliseconds: Int, work: @escaping @Sendable () throws -> Void,
         failed: @escaping @Sendable () -> Void) throws {
        guard (100...60_000).contains(intervalMilliseconds) else { throw AuthorityXPCEndpointError.invalidConfiguration }
        interval = intervalMilliseconds; self.work = work; self.failed = failed
    }
    deinit { timer?.cancel() }

    func start() throws {
        try lock.withLock {
            guard !started, !closed else { throw AuthorityXPCEndpointError.unavailable }
            started = true
            let timer = DispatchSource.makeTimerSource(queue: DispatchQueue(label: "dev.remozio.authority.maintenance"))
            timer.schedule(deadline: .now(), repeating: .milliseconds(interval), leeway: .milliseconds(10))
            timer.setEventHandler { [weak self] in self?.tick() }
            self.timer = timer
            timer.resume()
        }
    }
    func close() {
        lock.withLock { closed = true; timer?.cancel(); timer = nil }
    }
    private func tick() {
        let failure = lock.withLock {
            guard !closed else { return false }
            do { try work(); return false }
            catch { closed = true; timer?.cancel(); timer = nil; return true }
        }
        if failure { failed() }
    }
}
