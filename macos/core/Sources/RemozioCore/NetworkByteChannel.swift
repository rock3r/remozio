import Foundation
import Network

public enum NetworkChannelError: Error { case invalidState, concurrentOperation, closed, failed, timedOut, invalidChunk }

enum ByteConnectionEvent: Sendable { case ready, failed, cancelled }
protocol ByteConnectionDriver: Sendable {
    func start(_ event: @escaping @Sendable (ByteConnectionEvent) -> Void)
    func receive(_ result: @escaping @Sendable (Data?, Bool, Bool) -> Void)
    func send(_ data: Data, result: @escaping @Sendable (Bool) -> Void)
    func cancel()
}

private final class NativeByteConnection: ByteConnectionDriver, @unchecked Sendable {
    private let connection: NWConnection
    private let queue = DispatchQueue(label: "dev.remozio.channel")
    private let admit: @Sendable (NWConnection) -> Bool

    init(_ connection: NWConnection, admit: @escaping @Sendable (NWConnection) -> Bool) {
        self.connection = connection
        self.admit = admit
    }

    func start(_ event: @escaping @Sendable (ByteConnectionEvent) -> Void) {
        connection.stateUpdateHandler = { [admit, connection] state in
            switch state {
            case .ready: event(admit(connection) ? .ready : .failed)
            case .failed: event(.failed)
            case .cancelled: event(.cancelled)
            default: break
            }
        }
        connection.start(queue: queue)
    }

    func receive(_ result: @escaping @Sendable (Data?, Bool, Bool) -> Void) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: NetworkByteChannel.maximumChunkBytes) { data, _, ended, error in
            result(data, ended, error != nil)
        }
    }

    func send(_ data: Data, result: @escaping @Sendable (Bool) -> Void) {
        connection.send(content: data, completion: .contentProcessed { result($0 != nil) })
    }

    func cancel() {
        connection.stateUpdateHandler = nil
        connection.cancel()
    }
}

/// Owns one Network.framework connection. It queues at most one read and one write.
/// The caller configures TLS and supplies a synchronous admission check before any byte operation.
public actor NetworkByteChannel {
    public static let maximumChunkBytes = 32_768
    private enum State { case new, starting, open, closed }
    private let driver: any ByteConnectionDriver
    private var state = State.new
    private var readEnded = false
    private var opening: CheckedContinuation<Void, Error>?
    private var reading: CheckedContinuation<Data?, Error>?
    private var writing: CheckedContinuation<Void, Error>?
    private var deadline: Task<Void, Never>?

    /// The connection must be unstarted and exclusively owned by this channel after construction.
    /// Admission must verify the negotiated TLS profile. It must not block or perform network access.
    public init(connection: NWConnection, admission: @escaping @Sendable (NWConnection) -> Bool) {
        driver = NativeByteConnection(connection, admit: admission)
    }

    init(driver: any ByteConnectionDriver) { self.driver = driver }

    deinit { deadline?.cancel(); driver.cancel() }

    public func start(timeoutMilliseconds: UInt64 = 15_000) async throws {
        guard state == .new, (1...60_000).contains(timeoutMilliseconds) else { throw NetworkChannelError.invalidState }
        try Task.checkCancellation()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                opening = continuation
                state = .starting
                deadline = Task { [weak self] in
                    do { try await Task.sleep(for: .milliseconds(Int64(timeoutMilliseconds))) }
                    catch { return }
                    await self?.openingExpired()
                }
                driver.start { [weak self] event in Task { await self?.changed(event) } }
            }
        } onCancel: { Task { await self.close() } }
        try Task.checkCancellation()
    }

    /// Returns one bounded chunk, or nil after input ends. EOF proves no application outcome.
    public func receive() async throws -> Data? {
        guard state == .open else { throw NetworkChannelError.closed }
        guard reading == nil else { throw NetworkChannelError.concurrentOperation }
        try Task.checkCancellation()
        if readEnded { return nil }
        let data: Data? = try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                reading = continuation
                driver.receive { [weak self] data, ended, failed in
                    Task { await self?.received(data, ended: ended, failed: failed) }
                }
            }
        } onCancel: { Task { await self.close() } }
        try Task.checkCancellation()
        return data
    }

    /// Completion means the local network stack processed the chunk, not that the peer acted on it.
    public func send(_ data: Data) async throws {
        guard state == .open else { throw NetworkChannelError.closed }
        guard writing == nil else { throw NetworkChannelError.concurrentOperation }
        guard (1...Self.maximumChunkBytes).contains(data.count) else { throw NetworkChannelError.invalidChunk }
        try Task.checkCancellation()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                writing = continuation
                driver.send(data) { [weak self] failed in Task { await self?.sent(failed: failed) } }
            }
        } onCancel: { Task { await self.close() } }
        try Task.checkCancellation()
    }

    /// Aborts this incarnation and settles all waiters. It never retries an application message.
    public func close() { finish(NetworkChannelError.closed) }

    private func openingExpired() {
        if state == .starting { finish(NetworkChannelError.timedOut) }
    }

    private func changed(_ event: ByteConnectionEvent) {
        guard state != .closed else { return }
        switch event {
        case .ready:
            guard state == .starting else { return }
            state = .open
            deadline?.cancel(); deadline = nil
            let waiter = opening; opening = nil
            waiter?.resume()
        case .failed: finish(NetworkChannelError.failed)
        case .cancelled: finish(NetworkChannelError.closed)
        }
    }

    private func received(_ data: Data?, ended: Bool, failed: Bool) {
        guard state == .open, let waiter = reading else { return }
        guard !failed, (data?.count ?? 0) <= Self.maximumChunkBytes,
              ended || !(data?.isEmpty ?? true) else { finish(NetworkChannelError.failed); return }
        reading = nil
        readEnded = ended
        waiter.resume(returning: data?.isEmpty == false ? data : nil)
    }

    private func sent(failed: Bool) {
        guard state == .open, let waiter = writing else { return }
        if failed { finish(NetworkChannelError.failed); return }
        writing = nil
        waiter.resume()
    }

    private func finish(_ error: Error) {
        guard state != .closed else { return }
        state = .closed
        deadline?.cancel(); deadline = nil
        driver.cancel()
        let open = opening; opening = nil
        let read = reading; reading = nil
        let write = writing; writing = nil
        open?.resume(throwing: error)
        read?.resume(throwing: error)
        write?.resume(throwing: error)
    }
}
