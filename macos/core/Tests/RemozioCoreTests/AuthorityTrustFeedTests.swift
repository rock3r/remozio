import CryptoKit
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class AuthorityTrustFeedTests: XCTestCase, @unchecked Sendable {
    private final class Driver: AuthorityXPCDriver, @unchecked Sendable {
        private let lock = NSLock()
        private var bytes: Data
        private var pauseSnapshot = false
        private var pauseValidation = false
        private var snapshotReply: (@Sendable (AuthorityXPCReply) -> Void)?
        private var validationReply: (@Sendable (AuthorityXPCReply) -> Void)?
        private var invalidated: (@Sendable () -> Void)?
        private var validations = 0
        let snapshotSent = XCTestExpectation(description: "held snapshot")
        let validationSent = XCTestExpectation(description: "held validation")
        init(_ trust: DirectApprovalTrust) throws { bytes = try AuthorityTrustCodec.encodeSnapshot(trust) }
        var validationCount: Int { lock.withLock { validations } }
        func replace(_ trust: DirectApprovalTrust) throws { let bytes = try AuthorityTrustCodec.encodeSnapshot(trust); lock.withLock { self.bytes = bytes } }
        func holdSnapshot() { lock.withLock { pauseSnapshot = true } }
        func holdValidation() { lock.withLock { pauseValidation = true } }
        func start(invalidated: @escaping @Sendable () -> Void) { lock.withLock { self.invalidated = invalidated } }
        func hello(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.hello(1)) }
        func snapshot(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
            let value = lock.withLock { () -> Data? in
                if pauseSnapshot { snapshotReply = reply; return nil }; return bytes
            }
            if let value { reply(.snapshot(value)) } else { snapshotSent.fulfill() }
        }
        func validate(_ binding: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
            let held = lock.withLock {
                validations += 1
                if pauseValidation { validationReply = reply; return true }; return false
            }
            if held { validationSent.fulfill() } else { reply(.validation(true)) }
        }
        func finishSnapshot() {
            let value = lock.withLock { (snapshotReply, bytes) }; value.0?(.snapshot(value.1))
        }
        func finishValidation(_ allowed: Bool = true) {
            let reply = lock.withLock { pauseValidation = false; let value = validationReply; validationReply = nil; return value }
            reply?(.validation(allowed))
        }
        func interrupt() { lock.withLock { invalidated }?() }
        func close() { }
    }
    private final class Listener: OwnedDirectListener, @unchecked Sendable {
        private let lock = NSLock()
        private var closed = false
        var isClosed: Bool { lock.withLock { closed } }
        func start() throws { }
        func close() { lock.withLock { closed = true } }
    }
    private final class Listeners: @unchecked Sendable {
        private let lock = NSLock()
        private var storage: [Listener] = []
        var values: [Listener] { lock.withLock { storage } }
        func make() -> Listener { lock.withLock { let value = Listener(); storage.append(value); return value } }
    }
    private let mac = Data(repeating: 1, count: 16), account = Data(repeating: 2, count: 16)
    private func trust(empty: Bool = false) throws -> DirectApprovalTrust {
        let peer = try DirectApprovalPeer(scope: ChannelScope(macID: mac, accountID: account,
            phoneID: Data(repeating: 3, count: 16), enrollmentEpoch: Data(repeating: 4, count: 16)),
            transportPublicKey: P256.Signing.PrivateKey().publicKey.derRepresentation, requests: [], auditVersions: [], maximumPayloadBytes: 1024)
        return DirectApprovalTrust(macID: mac, accountID: account, revision: UUID(), peers: empty ? [] : [peer])
    }
    private func feed(_ driver: Driver, maximumWaiting: Int = 8) -> AuthorityTrustFeed {
        AuthorityTrustFeed(macID: mac, accountID: account, maximumWaiting: maximumWaiting,
            factory: { AuthorityXPCChannel(driver: driver, onClose: $0) })
    }
    private func host(_ listeners: Listeners) -> DirectApprovalTransportHost {
        DirectApprovalTransportHost(macID: mac, accountID: account, factory: { _, _, _, _ in listeners.make() }, validatePeer: { _, _ in })
    }
    func testUnchangedRefreshKeepsListenerAndRevocationStopsIt() async throws {
        let trust = try trust(), driver = try Driver(trust), feed = feed(driver), listeners = Listeners(), host = host(listeners)
        try await feed.start(host: host); try await host.start()
        let first = try XCTUnwrap(listeners.values.first)
        try await feed.refresh(); try await feed.refresh()
        XCTAssertEqual(listeners.values.count, 1); XCTAssertFalse(first.isClosed)
        try driver.replace(self.trust(empty: true)); try await feed.refresh()
        XCTAssertTrue(first.isClosed)
        let state = await host.state; XCTAssertEqual(state, .noEligiblePhones)
        await feed.close(); await host.close()
    }
    func testOldReplyAndDisconnectCannotReplaceNewIncarnation() async throws {
        let firstDriver = try Driver(trust()), old = feed(firstDriver), listeners = Listeners(), host = host(listeners)
        try await old.start(host: host); try await host.start()
        firstDriver.holdSnapshot()
        let pending = Task { try await old.refresh() }
        await fulfillment(of: [firstDriver.snapshotSent], timeout: 2)
        let second = feed(try Driver(trust()))
        try await second.start(host: host)
        let current = try XCTUnwrap(listeners.values.last)
        XCTAssertEqual(listeners.values.count, 2)
        firstDriver.finishSnapshot()
        do { try await pending.value; XCTFail("Retired snapshot accepted") } catch { }
        await old.close()
        XCTAssertFalse(current.isClosed)
        try await second.refresh(); XCTAssertEqual(listeners.values.count, 2)
        await second.close(); XCTAssertTrue(current.isClosed); await host.close()
    }
    func testCancelledQueuedValidationDoesNotCancelActiveOperation() async throws {
        let trust = try trust(), driver = try Driver(trust), feed = feed(driver), host = host(Listeners())
        try await feed.start(host: host)
        driver.holdValidation()
        let first = Task { try await feed.validatePeer(trust.peers[0], revision: trust.revision) }
        await fulfillment(of: [driver.validationSent], timeout: 2)
        let cancelled = Task { try await feed.validatePeer(trust.peers[0], revision: trust.revision) }
        cancelled.cancel()
        do { try await cancelled.value; XCTFail("Cancellation ignored") } catch { }
        let next = Task { try await feed.validatePeer(trust.peers[0], revision: trust.revision) }
        driver.finishValidation()
        try await first.value; try await next.value
        XCTAssertEqual(driver.validationCount, 2)
        await feed.close(); await host.close()
    }
    func testCapacityRejectsExtraWorkAndDenialKeepsConnection() async throws {
        let trust = try trust(), driver = try Driver(trust), feed = feed(driver, maximumWaiting: 0), host = host(Listeners())
        try await feed.start(host: host); driver.holdValidation()
        let first = Task { try await feed.validatePeer(trust.peers[0], revision: trust.revision) }
        await fulfillment(of: [driver.validationSent], timeout: 2)
        do { try await feed.validatePeer(trust.peers[0], revision: trust.revision); XCTFail("Capacity ignored") } catch { }
        driver.finishValidation(false)
        do { try await first.value; XCTFail("Denial ignored") } catch { }
        try await feed.validatePeer(trust.peers[0], revision: trust.revision)
        XCTAssertEqual(driver.validationCount, 2)
        await feed.close(); await host.close()
    }
    func testLossDuringValidationClearsHostAndRejectsLateAllow() async throws {
        let trust = try trust(), driver = try Driver(trust), feed = feed(driver), listeners = Listeners(), host = host(listeners)
        try await feed.start(host: host); try await host.start(); driver.holdValidation()
        let pending = Task { try await feed.validatePeer(trust.peers[0], revision: trust.revision) }
        await fulfillment(of: [driver.validationSent], timeout: 2)
        driver.interrupt(); driver.finishValidation()
        do { try await pending.value; XCTFail("Late allow accepted") } catch { }
        await feed.close()
        XCTAssertTrue(try XCTUnwrap(listeners.values.last).isClosed)
        do { try await host.start(); XCTFail("Disconnected host restarted") } catch { }
        await host.close()
    }
}
