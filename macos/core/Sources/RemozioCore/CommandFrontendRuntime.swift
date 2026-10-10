import Darwin
import RemozioMach

enum CommandFrontendRuntimeError: Error, Equatable { case closed, native(Int32) }

struct CommandFrontendSignals: OptionSet {
    let rawValue: UInt32
    static let interrupt = Self(rawValue: UInt32(REMOZIO_FRONTEND_INTERRUPT))
    static let terminate = Self(rawValue: UInt32(REMOZIO_FRONTEND_TERMINATE))
    static let hangup = Self(rawValue: UInt32(REMOZIO_FRONTEND_HANGUP))
    static let quit = Self(rawValue: UInt32(REMOZIO_FRONTEND_QUIT))
    static let resize = Self(rawValue: UInt32(REMOZIO_FRONTEND_RESIZE))
    static let suspend = Self(rawValue: UInt32(REMOZIO_FRONTEND_SUSPEND))
    static let continued = Self(rawValue: UInt32(REMOZIO_FRONTEND_CONTINUE))
    static let backgroundRead = Self(rawValue: UInt32(REMOZIO_FRONTEND_BACKGROUND_READ))
    static let backgroundWrite = Self(rawValue: UInt32(REMOZIO_FRONTEND_BACKGROUND_WRITE))
    static let brokenPipe = Self(rawValue: UInt32(REMOZIO_FRONTEND_BROKEN_PIPE))
}

/// Internal CLI owner. The main-thread loop serializes its operations with the relay and original session.
final class CommandFrontendRuntime {
    private var handle: OpaquePointer?
    private let startupStatus: Int32
    private let reportCleanupFailure: (Int32) -> Void

    // Keep a partially initialized native owner even when setup fails. Cleanup must precede descriptor reuse.
    init(reportCleanupFailure: @escaping (Int32) -> Void) {
        self.reportCleanupFailure = reportCleanupFailure
        var value: OpaquePointer?
        startupStatus = remozio_frontend_runtime_open(&value)
        handle = value
    }
    deinit {
        if let handle {
            let status = remozio_frontend_runtime_close(handle)
            if status != 0 { reportCleanupFailure(status) }
            // A failed cleanup intentionally retains native resources until CLI process exit.
        }
    }
    func checkReady() throws { _ = try owner() }
    func attach(session: RetainedCommandExecutionSession, terminal: CommandFrontendTerminal?) throws {
        try check(remozio_frontend_runtime_attach(try owner(), session.borrowedResultPort(),
            terminal?.borrowedReadinessDescriptor() ?? -1))
    }
    func takeSignals() throws -> CommandFrontendSignals {
        var signals: UInt32 = 0
        try check(remozio_frontend_runtime_take_signals(try owner(), &signals))
        return .init(rawValue: signals)
    }
    /// The loop must first restore its terminal and observe a local suspend event.
    func suspend(waitMilliseconds: UInt32) throws {
        try check(remozio_frontend_runtime_suspend(try owner(), waitMilliseconds))
    }
    func jobTicket() throws -> UInt64 {
        var ticket: UInt64 = 0
        try check(remozio_frontend_runtime_job_ticket(try owner(), &ticket))
        return ticket
    }
    /// Requires a fresh verified stop and successful terminal restoration in this same serialized loop.
    func suspendConfirmed(ticket: UInt64, deadlineMilliseconds: UInt64, waitMilliseconds: UInt32) throws -> Bool {
        var queued = false
        try check(remozio_frontend_runtime_suspend_confirmed(try owner(), ticket, deadlineMilliseconds, waitMilliseconds, &queued))
        return queued
    }
    /// The event notification grants no authentication, packet-consumption, or resubmission permission.
    func wait(interests: CommandFrontendWaitInterests? = nil, milliseconds: Int64) throws {
        var events: UInt32 = 0
        let status = remozio_frontend_runtime_wait(try owner(), interests?.result ?? false,
            interests?.read ?? false, interests?.write ?? false, milliseconds, &events)
        if status != EINTR { try check(status) }
    }
    func close() throws {
        guard let handle else { return }
        try check(remozio_frontend_runtime_close(handle))
        self.handle = nil
    }
    private func owner() throws -> OpaquePointer {
        try check(startupStatus)
        guard let handle else { throw CommandFrontendRuntimeError.closed }
        return handle
    }
    private func check(_ status: Int32) throws {
        if status != 0 { throw CommandFrontendRuntimeError.native(status) }
    }
}
