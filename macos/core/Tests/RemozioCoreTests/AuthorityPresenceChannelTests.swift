import Foundation
import XCTest
@testable import RemozioCore

final class AuthorityPresenceChannelTests: XCTestCase, @unchecked Sendable {
    private final class Driver: PresenceClientDriver, @unchecked Sendable {
        private let lock = NSRecursiveLock()
        let mac = Data(repeating: 1, count: 16)
        let account = Data(repeating: 2, count: 16)
        let epoch = UUID()
        private var binding: AuthorityPresenceBinding
        private var mode: RoutingMode = .automatic
        private var revision: UInt64 = 0
        private var time: UInt64 = 100
        private var version: UInt64 = 1
        private var noReply = false
        private var wrongMode = false
        private var operations: [String] = []
        private var sequences: [UInt64] = []
        private var closes = 0
        private var invalidated: (@Sendable () -> Void)?
        init() throws { binding = try .init(macID: mac, accountID: account, clockEpoch: epoch, connectionID: UUID()) }
        var calls: [String] { lock.withLock { operations } }
        var sentSequences: [UInt64] { lock.withLock { sequences } }
        var closeCount: Int { lock.withLock { closes } }
        func configure(version: UInt64? = nil, time: UInt64? = nil, noReply: Bool? = nil, wrongMode: Bool? = nil) {
            lock.withLock {
                if let version { self.version = version }; if let time { self.time = time }
                if let noReply { self.noReply = noReply }; if let wrongMode { self.wrongMode = wrongMode }
            }
        }
        func changeBinding(mac: Data? = nil, connectionID: UUID? = nil) throws {
            try lock.withLock { binding = try .init(macID: mac ?? self.mac, accountID: account,
                clockEpoch: epoch, connectionID: connectionID ?? binding.connectionID) }
        }
        func start(closed: @escaping @Sendable () -> Void) { lock.withLock { invalidated = closed } }
        func disconnect() { let callback = lock.withLock { invalidated }; callback?() }
        func invoke(_ call: PresenceClientCall, reply: @escaping @Sendable (PresenceClientReply) -> Void) {
            let result: PresenceClientReply? = lock.withLock {
                do {
                    switch call {
                    case .hello: operations.append("hello"); return noReply ? nil : .version(version)
                    case .current: operations.append("current")
                    case .setMode(let bytes):
                        operations.append("mode")
                        let change = try AuthorityPresenceCodec.decodeModeChange(bytes); sequences.append(change.sequence)
                        if change.expectedRevision != revision { return noReply ? nil : .status(try status(conflict: true)) }
                        revision += 1; mode = wrongMode ? .automatic : change.mode
                    case .publish(let bytes):
                        operations.append("publish"); sequences.append(try AuthorityPresenceCodec.decodePublication(bytes).sequence)
                    }
                    return noReply ? nil : .status(try status())
                } catch { return .failed }
            }
            if let result { reply(result) }
        }
        private func status(conflict: Bool = false) throws -> Data {
            var router = PresenceRouter(configuration: try .init(observationLifetimeMilliseconds: 1000, unavailableGraceMilliseconds: 0))
            return try AuthorityPresenceCodec.encodeStatus(.init(binding: binding, sampledAt: .init(epoch: epoch, milliseconds: time),
                state: .init(mode: mode, revision: revision), routing: router.evaluate(mode: mode, snapshot: .init(),
                    now: .init(epoch: epoch, milliseconds: time)), conflict: conflict))
        }
        func close() { lock.withLock { closes += 1 } }
    }
    private func channel(_ driver: Driver, timeout: UInt64 = 5000, localTime: UInt64 = 200) -> AuthorityPresenceChannel {
        AuthorityPresenceChannel(driver: driver, macID: driver.mac, accountID: driver.account, timeoutMilliseconds: timeout,
            sample: { .init(epoch: $0, milliseconds: localTime) })
    }
    func testHarmlessHandshakeThenBoundedStatusAndOrderedMutations() async throws {
        let driver = try Driver(), channel = channel(driver)
        let initial = try await channel.start()
        XCTAssertEqual(driver.calls, ["hello", "current"]); XCTAssertEqual(initial.state, .init(mode: .automatic, revision: 0))
        let present = try await channel.setMode(.present, expectedRevision: 0)
        XCTAssertEqual(present.state, .init(mode: .present, revision: 1))
        let at = try await channel.observationMoment()
        _ = try await channel.publish(.init(), sampledAt: at)
        let away = try await channel.setMode(.away, expectedRevision: 1)
        XCTAssertEqual(away.state, .init(mode: .away, revision: 2)); XCTAssertEqual(driver.sentSequences, [1, 2, 3])
        await channel.close()
    }
    func testUnsupportedVersionSendsNoAccountDataOrStatusQuery() async throws {
        for version: UInt64 in [0, 2, UInt64.max] {
            let driver = try Driver(), channel = channel(driver)
            driver.configure(version: version)
            do { _ = try await channel.start(); XCTFail() }
            catch { XCTAssertEqual(error as? AuthorityPresenceChannelError, .unsupportedVersion) }
            XCTAssertEqual(driver.calls, ["hello"]); XCTAssertEqual(driver.closeCount, 1)
        }
    }
    func testWrongScopeAndConnectionReplacementRetireClient() async throws {
        for wrongScope in [false, true] {
            let driver = try Driver(), channel = channel(driver)
            _ = try await channel.start()
            try driver.changeBinding(mac: wrongScope ? Data(repeating: 9, count: 16) : nil, connectionID: wrongScope ? nil : UUID())
            do { _ = try await channel.current(); XCTFail() } catch { }
            do { _ = try await channel.setMode(.away, expectedRevision: 0); XCTFail() }
            catch { XCTAssertEqual(error as? AuthorityPresenceChannelError, .closed) }
            XCTAssertFalse(driver.calls.contains("mode")); XCTAssertEqual(driver.closeCount, 1)
        }
    }
    func testFutureOldAndRegressedStatusCannotBeDisplayedAsCurrent() async throws {
        for time: UInt64 in [201, 0, 99] {
            let driver = try Driver(), channel = channel(driver, timeout: 100)
            _ = try await channel.start()
            driver.configure(time: time)
            do { _ = try await channel.current(); XCTFail() }
            catch { XCTAssertEqual(error as? AuthorityPresenceChannelError, .invalidMessage) }
            XCTAssertEqual(driver.closeCount, 1)
        }
    }
    func testInvalidPublicationDoesNotConsumeASequence() async throws {
        let driver = try Driver(), channel = channel(driver)
        let initial = try await channel.start()
        let wrong = AuthorityMoment(epoch: UUID(), milliseconds: 100)
        do { _ = try await channel.publish(.init(), sampledAt: wrong); XCTFail() } catch { }
        _ = try await channel.setMode(.away, expectedRevision: initial.state.revision)
        XCTAssertEqual(driver.sentSequences, [1]); XCTAssertEqual(driver.closeCount, 0)
        await channel.close()
    }
    func testConflictIsCurrentStateAndDoesNotRetryAutomatically() async throws {
        let driver = try Driver(), channel = channel(driver)
        _ = try await channel.start()
        let result = try await channel.setMode(.away, expectedRevision: 99)
        XCTAssertTrue(result.conflict); XCTAssertEqual(result.state, .init(mode: .automatic, revision: 0))
        XCTAssertEqual(driver.calls, ["hello", "current", "mode"])
        let confirmed = try await channel.setMode(.present, expectedRevision: 0)
        XCTAssertFalse(confirmed.conflict); XCTAssertEqual(confirmed.state.mode, .present)
        XCTAssertEqual(driver.sentSequences, [1, 2]); await channel.close()
    }
    func testLostModeReplyRetiresWithoutResubmission() async throws {
        let driver = try Driver(), channel = channel(driver, timeout: 150, localTime: 100)
        _ = try await channel.start(); driver.configure(noReply: true)
        do { _ = try await channel.setMode(.away, expectedRevision: 0); XCTFail() }
        catch { XCTAssertEqual(error as? AuthorityPresenceChannelError, .timedOut) }
        XCTAssertEqual(driver.calls, ["hello", "current", "mode"]); XCTAssertEqual(driver.closeCount, 1)
        do { _ = try await channel.current(); XCTFail() }
        catch { XCTAssertEqual(error as? AuthorityPresenceChannelError, .closed) }
    }
    func testWrongSuccessReceiptDoesNotConfirmTheRequestedMode() async throws {
        let driver = try Driver(), channel = channel(driver)
        _ = try await channel.start(); driver.configure(wrongMode: true)
        do { _ = try await channel.setMode(.present, expectedRevision: 0); XCTFail() }
        catch { XCTAssertEqual(error as? AuthorityPresenceChannelError, .invalidMessage) }
        XCTAssertEqual(driver.closeCount, 1)
    }
    func testAbortStopsSensitiveCallsBeforeActorProcessesInvalidation() async throws {
        let driver = try Driver(), channel = channel(driver)
        _ = try await channel.start(); channel.abort()
        do { _ = try await channel.setMode(.away, expectedRevision: 0); XCTFail() }
        catch { XCTAssertEqual(error as? AuthorityPresenceChannelError, .closed) }
        XCTAssertFalse(driver.calls.contains("mode"))
    }
    func testWrongAccountStopsBeforeStartingConnection() async throws {
        let driver = try Driver()
        let channel = AuthorityPresenceChannel(driver: driver, macID: driver.mac, accountID: driver.account,
            verifyAccount: { throw AuthorityPresenceChannelError.wrongAccount }, sample: { .init(epoch: $0, milliseconds: 100) })
        do { _ = try await channel.start(); XCTFail() }
        catch { XCTAssertEqual(error as? AuthorityPresenceChannelError, .wrongAccount) }
        XCTAssertTrue(driver.calls.isEmpty)
        await channel.close()
    }
}
