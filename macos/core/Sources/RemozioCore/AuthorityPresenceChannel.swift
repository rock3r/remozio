import Darwin
import Foundation

public enum AuthorityPresenceChannelError: Error, Equatable {
    case wrongAccount, closed, busy, unsupportedVersion, invalidMessage, timedOut
}
enum PresenceClientCall: Sendable { case hello, current, publish(Data), setMode(Data) }
enum PresenceClientReply: Sendable { case version(UInt64), status(Data?), failed }
protocol PresenceClientDriver: Sendable {
    func start(closed: @escaping @Sendable () -> Void)
    func invoke(_ call: PresenceClientCall, reply: @escaping @Sendable (PresenceClientReply) -> Void)
    func close()
}
private final class NativePresenceClientDriver: PresenceClientDriver, @unchecked Sendable {
    private let connection: NSXPCConnection
    private let policy: XPCPeerPolicy
    init(configuration: AuthorityPresenceClientConfiguration) {
        policy = configuration.rootPolicy
        connection = NSXPCConnection(machServiceName: configuration.serviceName, options: .privileged)
        connection.remoteObjectInterface = NSXPCInterface(with: AuthorityPresenceXPCProtocol.self)
        policy.configure(connection)
    }
    func start(closed: @escaping @Sendable () -> Void) {
        connection.interruptionHandler = closed; connection.invalidationHandler = closed; connection.activate()
    }
    func invoke(_ call: PresenceClientCall, reply: @escaping @Sendable (PresenceClientReply) -> Void) {
        guard let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in reply(.failed) }) as? any AuthorityPresenceXPCProtocol else {
            reply(.failed); return
        }
        switch call {
        case .hello: proxy.hello { [self] in checked(.version($0), reply: reply) }
        case .current: proxy.current { [self] in checked(.status($0), reply: reply) }
        case .publish(let payload): proxy.publish(payload) { [self] in checked(.status($0), reply: reply) }
        case .setMode(let payload): proxy.setMode(payload) { [self] in checked(.status($0), reply: reply) }
        }
    }
    private func checked(_ value: PresenceClientReply, reply: @Sendable (PresenceClientReply) -> Void) {
        do { _ = try policy.verifyCredentials(connection); reply(value) } catch { reply(.failed) }
    }
    func close() { connection.invalidate() }
    deinit { connection.invalidate() }
}
private final class PresenceChannelLifetime: @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private var closed = false
    func close() { lock.withLock { closed = true } }
    func ifOpen(_ body: () -> Void) -> Bool { lock.withLock { guard !closed else { return false }; body(); return true } }
}

/// A lost reply may follow a committed mode change. Reconnect and read Root state; never replay the mutation automatically.
public actor AuthorityPresenceChannel {
    private enum State { case new, opening, open, closed }
    private let driver: any PresenceClientDriver
    private let macID: Data
    private let accountID: Data
    private let timeout: UInt64
    private let verifyAccount: @Sendable () throws -> Void
    private let onClose: @Sendable () -> Void
    private let lifetime = PresenceChannelLifetime()
    private let sample: @Sendable (UUID) throws -> AuthorityMoment
    private var state = State.new
    private var binding: AuthorityPresenceBinding?
    private var lastTime: UInt64?
    private var sequence: UInt64 = 0
    private var pending: (id: UUID, continuation: CheckedContinuation<PresenceClientReply, any Error>)?
    private var timer: Task<Void, Never>?
    public init(configuration: AuthorityPresenceClientConfiguration, onClose: @escaping @Sendable () -> Void) {
        driver = NativePresenceClientDriver(configuration: configuration)
        macID = configuration.macID; accountID = configuration.accountID; timeout = configuration.timeoutMilliseconds
        verifyAccount = {
            guard getuid() == configuration.ownerUID, geteuid() == configuration.ownerUID else { throw AuthorityPresenceChannelError.wrongAccount }
        }
        self.onClose = onClose; sample = { try AuthorityClock(epoch: $0).now() }
    }
    init(driver: any PresenceClientDriver, macID: Data, accountID: Data, timeoutMilliseconds: UInt64 = 5000,
         verifyAccount: @escaping @Sendable () throws -> Void = {}, onClose: @escaping @Sendable () -> Void = {},
         sample: @escaping @Sendable (UUID) throws -> AuthorityMoment) {
        self.driver = driver; self.macID = macID; self.accountID = accountID; timeout = timeoutMilliseconds
        self.verifyAccount = verifyAccount; self.onClose = onClose; self.sample = sample
    }
    deinit { timer?.cancel(); driver.close() }
    public func start() async throws -> AuthorityPresenceStatus {
        try verifyAccount()
        guard state == .new else { throw AuthorityPresenceChannelError.closed }
        state = .opening
        do {
            guard case .version(let version) = try await perform(.hello), version == 1 else { throw AuthorityPresenceChannelError.unsupportedVersion }
            try Task.checkCancellation()
            guard state == .opening, lifetime.ifOpen({}) else { throw AuthorityPresenceChannelError.closed }
            state = .open
            return try await current()
        } catch { close(); throw error }
    }
    public func current() async throws -> AuthorityPresenceStatus { try await status(.current) }
    public func observationMoment() throws -> AuthorityMoment {
        guard state == .open, let binding, lifetime.ifOpen({}) else { throw AuthorityPresenceChannelError.closed }
        return try sample(binding.clockEpoch)
    }
    public func publish(_ snapshot: PresenceSnapshot, sampledAt: AuthorityMoment) async throws -> AuthorityPresenceStatus {
        let binding = try mutationBinding()
        let next = try nextSequence()
        let bytes = try AuthorityPresenceCodec.encodePublication(binding: binding, sequence: next, sampledAt: sampledAt, snapshot: snapshot)
        sequence = next
        do { return try await status(.publish(bytes)) }
        catch { close(); throw error }
    }
    public func setMode(_ mode: RoutingMode, expectedRevision: UInt64) async throws -> AuthorityPresenceStatus {
        let binding = try mutationBinding()
        let next = try nextSequence()
        let bytes = try AuthorityPresenceCodec.encodeModeChange(binding: binding, sequence: next, mode: mode, expectedRevision: expectedRevision)
        sequence = next
        do {
            let value = try await status(.setMode(bytes)), expected = expectedRevision.addingReportingOverflow(1)
            guard value.conflict || (!expected.overflow && value.state.mode == mode && value.state.revision == expected.partialValue) else {
                throw AuthorityPresenceChannelError.invalidMessage
            }
            return value
        } catch { close(); throw error }
    }
    public nonisolated func abort() { lifetime.close(); driver.close(); Task { await self.close() } }
    public func close() {
        guard state != .closed else { return }
        state = .closed; lifetime.close(); binding = nil; lastTime = nil; timer?.cancel(); timer = nil; driver.close()
        let previous = pending; pending = nil; previous?.continuation.resume(throwing: AuthorityPresenceChannelError.closed)
        onClose()
    }
    private func mutationBinding() throws -> AuthorityPresenceBinding {
        guard state == .open, let binding, pending == nil, lifetime.ifOpen({}) else {
            throw pending == nil ? AuthorityPresenceChannelError.closed : .busy
        }
        return binding
    }
    private func nextSequence() throws -> UInt64 {
        let next = sequence.addingReportingOverflow(1)
        guard !next.overflow else { close(); throw AuthorityPresenceChannelError.closed }
        return next.partialValue
    }
    private func status(_ call: PresenceClientCall) async throws -> AuthorityPresenceStatus {
        guard case .status(let bytes) = try await perform(call), let bytes else { close(); throw AuthorityPresenceChannelError.invalidMessage }
        do {
            try Task.checkCancellation()
            guard state == .open, lifetime.ifOpen({}) else { throw AuthorityPresenceChannelError.closed }
            let value = try AuthorityPresenceCodec.decodeStatus(bytes, expectedMacID: macID, expectedAccountID: accountID)
            let now = try sample(value.binding.clockEpoch)
            guard binding == nil || binding == value.binding,
                  now.epoch == value.sampledAt.epoch, now.milliseconds >= value.sampledAt.milliseconds,
                  now.milliseconds - value.sampledAt.milliseconds <= timeout,
                  lastTime.map({ value.sampledAt.milliseconds >= $0 }) ?? true else { throw AuthorityPresenceChannelError.invalidMessage }
            binding = value.binding; lastTime = value.sampledAt.milliseconds
            return value
        } catch { close(); throw error }
    }
    private func perform(_ call: PresenceClientCall) async throws -> PresenceClientReply {
        try verifyAccount(); try Task.checkCancellation()
        switch call {
        case .hello: guard state == .opening else { throw AuthorityPresenceChannelError.closed }
        case .current, .publish, .setMode: guard state == .open else { throw AuthorityPresenceChannelError.closed }
        }
        guard pending == nil else { throw AuthorityPresenceChannelError.busy }
        let id = UUID(), lifetime = lifetime, driver = driver
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                pending = (id, continuation)
                timer = Task { [weak self, timeout] in
                    do { try await Task.sleep(for: .milliseconds(timeout)) } catch { return }
                    await self?.expire(id)
                }
                if case .hello = call {
                    driver.start { [weak self] in lifetime.close(); Task { await self?.close() } }
                }
                guard lifetime.ifOpen({ driver.invoke(call) { [weak self] value in Task { await self?.complete(id, value: value) } } }) else {
                    close(); return
                }
            }
        } onCancel: { [weak self] in lifetime.close(); driver.close(); Task { await self?.close() } }
    }
    private func complete(_ id: UUID, value: PresenceClientReply) {
        guard let previous = pending, previous.id == id, state != .closed else { return }
        pending = nil; timer?.cancel(); timer = nil
        if case .failed = value { previous.continuation.resume(throwing: AuthorityPresenceChannelError.closed); close() }
        else { previous.continuation.resume(returning: value) }
    }
    private func expire(_ id: UUID) {
        guard let previous = pending, previous.id == id else { return }
        pending = nil; previous.continuation.resume(throwing: AuthorityPresenceChannelError.timedOut); close()
    }
}
