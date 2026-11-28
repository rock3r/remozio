import Darwin
import Foundation
import OSLog

/// Keeps failed cleanup alive after connection disposal. Pending scope ownership also keeps daemon shutdown waiting.
final class SetupAuditUpgradeCleanupOwner: @unchecked Sendable {
    enum Failure: String, CaseIterable, Sendable {
        case transactionActive = "transaction_active"
        case leaseBusy = "lease_busy"
        case cleanupUnavailable = "cleanup_unavailable"
        case other

        init(_ error: any Error) {
            switch error {
            case JournalDatabaseError.transactionActive, PreparationStoreError.transactionActive: self = .transactionActive
            case JournalLeaseError.busy: self = .leaseBusy
            case AdministrativeSetupError.unavailable, RuntimeActivationError.unavailable: self = .cleanupUnavailable
            default: self = .other
            }
        }
    }

    struct ShutdownWait: Equatable, Sendable {
        let cause: Failure
        let count: Int

        var message: String { "setup_shutdown_wait cleanup=audit_upgrade cause=\(cause.rawValue) count=\(count)" }
    }

    private struct Pending {
        let invocation: SetupAuditUpgradeInvocation
        var lastFailure: Failure?
    }

    private static let logger = Logger(subsystem: "dev.sebastiano.remozio", category: "maintenance")
    private let lock = NSLock()
    private let processID = getpid()
    private let now: @Sendable () -> ContinuousClock.Instant
    private let report: @Sendable (ShutdownWait) -> Void
    private var pending: [ObjectIdentifier: Pending] = [:]
    private var settling: Set<ObjectIdentifier> = []
    private var lastReport: ContinuousClock.Instant?

    init(now: @escaping @Sendable () -> ContinuousClock.Instant = { .now },
         report: @escaping @Sendable (ShutdownWait) -> Void = { wait in
             // Only the fixed event fields and count are public.
             SetupAuditUpgradeCleanupOwner.logger.error("\(wait.message, privacy: .public)")
         }) {
        self.now = now
        self.report = report
    }

    /// Transfers retention before attempting cleanup. No lock is held while closing a possibly active invocation.
    func settle(_ invocation: SetupAuditUpgradeInvocation) -> Bool {
        guard getpid() == processID else { return false }
        let key = ObjectIdentifier(invocation)
        let admitted = lock.withLock { () -> Bool in
            if pending[key] == nil { pending[key] = Pending(invocation: invocation) }
            return settling.insert(key).inserted
        }
        guard admitted else { return false }
        let failure: Failure?
        do { try invocation.close(); failure = nil }
        catch { failure = Failure(error) }
        lock.withLock {
            settling.remove(key)
            if let failure { pending[key]?.lastFailure = failure }
            else {
                pending.removeValue(forKey: key)
                if pending.isEmpty { lastReport = nil }
            }
        }
        return failure == nil
    }
    /// Attempts each retained cleanup once. This never resumes an upgrade, imports rights or starts services.
    func retry(reportShutdownWait: Bool = false) -> Bool {
        guard getpid() == processID else { return false }
        let values = lock.withLock { pending.values.map(\.invocation) }
        for invocation in values { _ = settle(invocation) }
        let instant = reportShutdownWait ? now() : nil
        let (idle, messages) = lock.withLock { () -> (Bool, [ShutdownWait]) in
            let idle = pending.isEmpty
            guard let instant, lastReport.map({ instant >= $0.advanced(by: .seconds(30)) }) ?? true else {
                return (idle, [])
            }
            let failures = Dictionary(grouping: pending.values.compactMap(\.lastFailure), by: { $0 })
            guard !failures.isEmpty else { return (idle, []) }
            lastReport = instant
            return (idle, Failure.allCases.compactMap { cause in
                failures[cause].map { ShutdownWait(cause: cause, count: $0.count) }
            })
        }
        for message in messages { report(message) }
        return idle
    }
}
