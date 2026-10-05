import Foundation

@objc public protocol TransportAuthorityXPCProtocol {
    /// Harmless first call. Contains no scope, key, request, or credential material.
    func hello(reply: @escaping @Sendable (UInt64) -> Void)
    /// Optional request-delivery extension. Zero means unavailable; version one uses requestFrame.
    func requestDeliveryVersion(reply: @escaping @Sendable (UInt64) -> Void)
    func requestFrame(_ binding: Data, requestID: Data, reply: @escaping @Sendable (Data?) -> Void)
    func trustSnapshot(reply: @escaping @Sendable (Data?) -> Void)
    func validatePeer(_ binding: Data, reply: @escaping @Sendable (Bool) -> Void)
}

public enum AuthorityXPCError: Error { case unsupportedRequestDelivery, invalidConfiguration, invalidState, concurrentOperation, closed, failed, timedOut, invalidMessage }
enum AuthorityXPCReply: Sendable { case hello(UInt64), deliveryVersion(UInt64), requestFrame(Data), snapshot(Data), validation(Bool), failed }
protocol AuthorityXPCDriver: Sendable {
    func start(invalidated: @escaping @Sendable () -> Void)
    func hello(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void)
    func deliveryVersion(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void)
    func requestFrame(_ binding: Data, requestID: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void)
    func snapshot(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void)
    func validate(_ binding: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void)
    func close()
}

extension AuthorityXPCDriver {
    func deliveryVersion(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.deliveryVersion(0)) }
    func requestFrame(_ binding: Data, requestID: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.failed) }
}

private final class NativeAuthorityXPC: AuthorityXPCDriver, @unchecked Sendable {
    private let connection: NSXPCConnection
    private let policy: XPCPeerPolicy
    init(serviceName: String, policy: XPCPeerPolicy) {
        self.policy = policy
        connection = NSXPCConnection(machServiceName: serviceName, options: .privileged)
        connection.remoteObjectInterface = NSXPCInterface(with: TransportAuthorityXPCProtocol.self)
        policy.configure(connection)
    }
    func start(invalidated: @escaping @Sendable () -> Void) {
        connection.interruptionHandler = invalidated
        connection.invalidationHandler = invalidated
        connection.activate()
    }
    private func proxy(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) -> (any TransportAuthorityXPCProtocol)? {
        connection.remoteObjectProxyWithErrorHandler { _ in reply(.failed) } as? any TransportAuthorityXPCProtocol
    }
    private func checked(_ result: AuthorityXPCReply, _ reply: @Sendable (AuthorityXPCReply) -> Void) {
        do { _ = try policy.verifyCredentials(connection); reply(result) }
        catch { reply(.failed) }
    }
    func hello(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
        guard let proxy = proxy(reply) else { reply(.failed); return }
        proxy.hello { [self] version in checked(.hello(version), reply) }
    }
    func deliveryVersion(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
        guard let proxy = proxy(reply) else { reply(.failed); return }
        proxy.requestDeliveryVersion { [self] version in checked(.deliveryVersion(version), reply) }
    }
    func requestFrame(_ binding: Data, requestID: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
        guard let proxy = proxy(reply) else { reply(.failed); return }
        proxy.requestFrame(binding, requestID: requestID) { [self] bytes in
            checked(bytes.map(AuthorityXPCReply.requestFrame) ?? .failed, reply)
        }
    }
    func snapshot(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
        guard let proxy = proxy(reply) else { reply(.failed); return }
        proxy.trustSnapshot { [self] data in checked(data.map(AuthorityXPCReply.snapshot) ?? .failed, reply) }
    }
    func validate(_ binding: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
        guard let proxy = proxy(reply) else { reply(.failed); return }
        proxy.validatePeer(binding) { [self] allowed in checked(.validation(allowed), reply) }
    }
    func close() { connection.invalidate() }
    deinit { connection.invalidate() }
}

private final class XPCLifetime: @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private var cancelled = false
    func cancel() { lock.withLock { cancelled = true } }
    func ifActive(_ body: () -> Void) -> Bool {
        lock.withLock { guard !cancelled else { return false }; body(); return true }
    }
}

/// One transport-to-root connection. A successful harmless handshake is required before any binding data is sent.
/// Interruption retires the instance. Construct a new instance and fetch fresh trust after reconnecting.
public actor AuthorityXPCChannel {
    public static let maximumSnapshotBytes = 1_048_576
    public static let maximumBindingBytes = 4096
    private enum State { case new, opening, open, closed }
    private enum Operation { case hello, deliveryVersion, requestFrame, snapshot, validation }
    private var deliveryVersion: UInt64?
    private let driver: any AuthorityXPCDriver
    private let cancellation = XPCLifetime()
    private let timeoutMilliseconds: UInt64
    private let onClose: @Sendable () -> Void
    private var state = State.new
    private var pending: (id: UUID, operation: Operation, continuation: CheckedContinuation<AuthorityXPCReply, Error>)?
    private var deadline: Task<Void, Never>?

    public init(serviceName: String, peerPolicy: XPCPeerPolicy, timeoutMilliseconds: UInt64 = 5000,
                onClose: @escaping @Sendable () -> Void) throws {
        guard (1...255).contains(serviceName.utf8.count), serviceName.hasPrefix("dev.remozio."),
              serviceName.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 46 || $0 == 45 }),
              peerPolicy.expectedUserID == 0, (1...60_000).contains(timeoutMilliseconds) else { throw AuthorityXPCError.invalidConfiguration }
        driver = NativeAuthorityXPC(serviceName: serviceName, policy: peerPolicy)
        self.timeoutMilliseconds = timeoutMilliseconds; self.onClose = onClose
    }
    init(driver: any AuthorityXPCDriver, timeoutMilliseconds: UInt64 = 5000,
         onClose: @escaping @Sendable () -> Void = {}) {
        self.driver = driver; self.timeoutMilliseconds = timeoutMilliseconds; self.onClose = onClose
    }
    deinit { deadline?.cancel(); driver.close() }

    public func start() async throws {
        guard state == .new else { throw AuthorityXPCError.invalidState }
        state = .opening
        do {
            _ = try await perform(.hello)
            try Task.checkCancellation()
            guard cancellation.ifActive({}), state == .opening else { throw AuthorityXPCError.closed }
            state = .open
        } catch { finish(.closed); throw error }
    }
    public func trustSnapshot() async throws -> Data {
        guard case .snapshot(let data) = try await perform(.snapshot) else { throw AuthorityXPCError.invalidMessage }
        return data
    }
    /// Decode only after authenticating the authority; a malformed or wrong-scope snapshot retires the connection.
    public func fetchTrust(expectedMacID: Data, expectedAccountID: Data) async throws -> DirectApprovalTrust {
        let bytes = try await trustSnapshot()
        do { return try AuthorityTrustCodec.decodeSnapshot(bytes, expectedMacID: expectedMacID, expectedAccountID: expectedAccountID) }
        catch { finish(.invalidMessage); throw error }
    }
    public func validatePeer(_ binding: AuthorityPeerBinding) async throws -> Bool {
        try await validatePeer(binding: AuthorityTrustCodec.encodeBinding(binding))
    }
    public func validatePeer(binding: Data) async throws -> Bool {
        guard !binding.isEmpty, binding.count <= Self.maximumBindingBytes else { throw AuthorityXPCError.invalidMessage }
        guard case .validation(let allowed) = try await perform(.validation, binding: binding) else { throw AuthorityXPCError.invalidMessage }
        return allowed
    }
    /// Fetch a frame for a known request. Empty means no currently eligible frame, never a confirmed request outcome.
    /// This does not authorize an action. The root owns the queued frame and revalidates its recipient.
    public func requestFrame(binding: AuthorityPeerBinding, requestID: Data) async throws -> Data? {
        guard requestID.count == 16 else { throw AuthorityXPCError.invalidMessage }
        if deliveryVersion == nil {
            guard case .deliveryVersion(let version) = try await perform(.deliveryVersion) else { throw AuthorityXPCError.invalidMessage }
            deliveryVersion = version
        }
        guard deliveryVersion == 1 else { throw AuthorityXPCError.unsupportedRequestDelivery }
        let encoded = try AuthorityTrustCodec.encodeBinding(binding)
        guard case .requestFrame(let bytes) = try await perform(.requestFrame, binding: encoded, requestID: requestID) else {
            throw AuthorityXPCError.invalidMessage
        }
        if bytes.isEmpty { return nil }
        do { try AuthorityRequestFrame.validate(bytes, binding: binding, requestID: requestID) }
        catch { finish(.invalidMessage); throw error }
        return bytes
    }

    public nonisolated func abort() {
        cancellation.cancel(); driver.close()
        Task { await self.close() }
    }
    public func close() { finish(.closed) }

    private func perform(_ operation: Operation, binding: Data? = nil, requestID: Data? = nil) async throws -> AuthorityXPCReply {
        guard state == .open || (state == .opening && operation == .hello) else { throw AuthorityXPCError.closed }
        guard pending == nil else { throw AuthorityXPCError.concurrentOperation }
        try Task.checkCancellation()
        let cancellation = cancellation, driver = driver
        let result = try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let id = UUID()
                pending = (id, operation, continuation)
                deadline = Task { [weak self, timeoutMilliseconds] in
                    do { try await Task.sleep(for: .milliseconds(Int64(timeoutMilliseconds))) } catch { return }
                    await self?.expired(id)
                }
                let reply: @Sendable (AuthorityXPCReply) -> Void = { [weak self] result in
                    Task { await self?.received(result, id: id) }
                }
                if operation == .hello {
                    driver.start { [weak self] in
                        cancellation.cancel()
                        Task { await self?.close() }
                    }
                }
                guard cancellation.ifActive({
                    switch operation {
                    case .hello: driver.hello(reply)
                    case .deliveryVersion: driver.deliveryVersion(reply)
                    case .requestFrame: driver.requestFrame(binding!, requestID: requestID!, reply)
                    case .snapshot: driver.snapshot(reply)
                    case .validation: driver.validate(binding!, reply)
                    }
                }) else { finish(.closed); return }
            }
        } onCancel: {
            cancellation.cancel(); driver.close()
            Task { await self.close() }
        }
        try Task.checkCancellation()
        guard cancellation.ifActive({}), state != .closed else { finish(.closed); throw AuthorityXPCError.closed }
        return result
    }
    private func received(_ reply: AuthorityXPCReply, id: UUID) {
        guard let current = pending, current.id == id else { return }
        guard cancellation.ifActive({}) else { finish(.closed); return }
        if case .failed = reply { finish(.failed); return }
        switch (current.operation, reply) {
        case (.hello, .hello(1)), (.validation, .validation), (.deliveryVersion, .deliveryVersion): break
        case (.requestFrame, .requestFrame(let bytes)) where bytes.count <= AuthorityRequestFrame.maximumBytes: break
        case (.snapshot, .snapshot(let bytes)) where !bytes.isEmpty && bytes.count <= Self.maximumSnapshotBytes: break
        default: finish(.invalidMessage); return
        }
        pending = nil; deadline?.cancel(); deadline = nil
        current.continuation.resume(returning: reply)
    }
    private func expired(_ id: UUID) { if pending?.id == id { finish(.timedOut) } }
    private func finish(_ error: AuthorityXPCError) {
        guard state != .closed else { return }
        state = .closed; cancellation.cancel(); deadline?.cancel(); deadline = nil
        let current = pending; pending = nil
        driver.close(); onClose(); current?.continuation.resume(throwing: error)
    }
}
