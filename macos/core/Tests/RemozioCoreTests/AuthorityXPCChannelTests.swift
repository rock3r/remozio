import Foundation
import XCTest
@testable import RemozioCore

final class AuthorityXPCChannelTests: XCTestCase, @unchecked Sendable {
    private final class Driver: AuthorityXPCDriver, @unchecked Sendable {
        let helloSent = XCTestExpectation(description: "hello")
        let snapshotSent = XCTestExpectation(description: "snapshot")
        let validationSent = XCTestExpectation(description: "validation")
        private let lock = NSLock()
        private var invalidated: (@Sendable () -> Void)?
        private var helloReply: (@Sendable (AuthorityXPCReply) -> Void)?
        private var snapshotReply: (@Sendable (AuthorityXPCReply) -> Void)?
        private var validationReply: (@Sendable (AuthorityXPCReply) -> Void)?
        private var bindings: [Data] = []
        private var closes = 0
        let interruptOnStart: Bool
        init(interruptOnStart: Bool = false) { self.interruptOnStart = interruptOnStart }
        var sentBindings: [Data] { lock.withLock { bindings } }
        var closeCount: Int { lock.withLock { closes } }
        func start(invalidated: @escaping @Sendable () -> Void) {
            lock.withLock { self.invalidated = invalidated }
            if interruptOnStart { invalidated() }
        }
        func hello(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
            lock.withLock { helloReply = reply }; helloSent.fulfill()
        }
        func snapshot(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
            lock.withLock { snapshotReply = reply }; snapshotSent.fulfill()
        }
        func validate(_ binding: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
            lock.withLock { bindings.append(binding); validationReply = reply }; validationSent.fulfill()
        }
        func close() { lock.withLock { closes += 1 } }
        func interrupt() { lock.withLock { invalidated }?() }
        func completeHello(_ value: AuthorityXPCReply = .hello(1)) { lock.withLock { helloReply }?(value) }
        func completeSnapshot(_ value: AuthorityXPCReply) { lock.withLock { snapshotReply }?(value) }
        func completeValidation(_ value: AuthorityXPCReply) { lock.withLock { validationReply }?(value) }
    }
    private func opened(timeout: UInt64 = 5000) async throws -> (AuthorityXPCChannel, Driver) {
        let driver = Driver()
        let active = AuthorityXPCChannel(driver: driver, timeoutMilliseconds: timeout)
        let start = Task { try await active.start() }
        await fulfillment(of: [driver.helloSent], timeout: 2)
        driver.completeHello(); try await start.value
        return (active, driver)
    }
    private func failure<T>(_ task: Task<T, Error>) async {
        do { _ = try await task.value; XCTFail("Expected failure") } catch { }
    }
    func testOnlyHarmlessHelloBeforeHandshakeAndNoRepeatedStart() async throws {
        let driver = Driver()
        let active = AuthorityXPCChannel(driver: driver)
        await failure(Task { try await active.trustSnapshot() })
        let opening = Task { try await active.start() }
        await fulfillment(of: [driver.helloSent], timeout: 2)
        await failure(Task { try await active.validatePeer(binding: Data([1])) })
        XCTAssertTrue(driver.sentBindings.isEmpty)
        driver.completeHello(); try await opening.value
        await failure(Task { try await active.start() })
        await active.close()
    }
    func testSnapshotAndValidationAreBoundedAndSingleFlight() async throws {
        let (channel, driver) = try await opened()
        let snapshot = Task { try await channel.trustSnapshot() }
        await fulfillment(of: [driver.snapshotSent], timeout: 2)
        await failure(Task { try await channel.validatePeer(binding: Data([1])) })
        driver.completeSnapshot(.snapshot(Data([4, 5])))
        let bytes = try await snapshot.value
        XCTAssertEqual(bytes, Data([4, 5]))
        await failure(Task { try await channel.validatePeer(binding: Data()) })
        await failure(Task { try await channel.validatePeer(binding: Data(count: AuthorityXPCChannel.maximumBindingBytes + 1)) })
        let validation = Task { try await channel.validatePeer(binding: Data([1, 2])) }
        await fulfillment(of: [driver.validationSent], timeout: 2)
        driver.completeValidation(.validation(false))
        let allowed = try await validation.value
        XCTAssertFalse(allowed); XCTAssertEqual(driver.sentBindings, [Data([1, 2])])
        XCTAssertEqual(driver.closeCount, 0)
        await channel.close()
    }
    func testWrongVersionAndFailureCannotOpenChannel() async {
        for result in [AuthorityXPCReply.hello(0), .hello(2), .failed, .validation(true)] {
            let driver = Driver()
            let active = AuthorityXPCChannel(driver: driver)
            let start = Task { try await active.start() }
            await fulfillment(of: [driver.helloSent], timeout: 2)
            driver.completeHello(result); await failure(start)
            await failure(Task { try await active.validatePeer(binding: Data([1])) })
            XCTAssertTrue(driver.sentBindings.isEmpty); XCTAssertGreaterThan(driver.closeCount, 0)
        }
    }
    func testInterruptionAndLateReplyCannotReviveConnection() async throws {
        let (channel, driver) = try await opened()
        let pending = Task { try await channel.trustSnapshot() }
        await fulfillment(of: [driver.snapshotSent], timeout: 2)
        driver.interrupt(); driver.completeSnapshot(.snapshot(Data([1])))
        await failure(pending)
        await failure(Task { try await channel.start() })
        await failure(Task { try await channel.validatePeer(binding: Data([1])) })
        XCTAssertTrue(driver.sentBindings.isEmpty)
    }
    func testCancellationClosesPendingValidationAndLateReplyIsIgnored() async throws {
        let (channel, driver) = try await opened()
        let pending = Task { try await channel.validatePeer(binding: Data([1])) }
        await fulfillment(of: [driver.validationSent], timeout: 2)
        pending.cancel(); driver.completeValidation(.validation(true))
        await failure(pending)
        XCTAssertGreaterThan(driver.closeCount, 0)
        await failure(Task { try await channel.trustSnapshot() })
    }
    func testTimeoutAndOversizedReplyRetireConnection() async throws {
        let stalled = AuthorityXPCChannel(driver: Driver(), timeoutMilliseconds: 10)
        await failure(Task { try await stalled.start() })
        for bytes in [Data(), Data(count: AuthorityXPCChannel.maximumSnapshotBytes + 1)] {
            let (channel, driver) = try await opened()
            let pending = Task { try await channel.trustSnapshot() }
            await fulfillment(of: [driver.snapshotSent], timeout: 2)
            driver.completeSnapshot(.snapshot(bytes)); await failure(pending)
            XCTAssertGreaterThan(driver.closeCount, 0)
        }
    }
    func testCloseNotifiesOwnerOnceEvenWithRepeatedInvalidation() async throws {
        let notification = XCTestExpectation(description: "owner notified")
        notification.assertForOverFulfill = true
        let driver = Driver()
        let channel = AuthorityXPCChannel(driver: driver, onClose: { notification.fulfill() })
        let start = Task { try await channel.start() }
        await fulfillment(of: [driver.helloSent], timeout: 2)
        driver.completeHello(); try await start.value
        driver.interrupt()
        await fulfillment(of: [notification], timeout: 2)
        driver.interrupt(); driver.completeHello()
        await channel.close(); await channel.close()
        await failure(Task { try await channel.trustSnapshot() })
    }
    func testSynchronousInterruptionDuringStartDoesNotDeadlockOrSendHello() async {
        let driver = Driver(interruptOnStart: true)
        let channel = AuthorityXPCChannel(driver: driver, timeoutMilliseconds: 10)
        await failure(Task { try await channel.start() })
        XCTAssertTrue(driver.sentBindings.isEmpty); XCTAssertGreaterThan(driver.closeCount, 0)
    }
}
