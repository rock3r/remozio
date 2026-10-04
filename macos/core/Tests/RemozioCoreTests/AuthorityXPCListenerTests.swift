import Foundation
import XCTest
@testable import RemozioCore

final class AuthorityXPCListenerTests: XCTestCase {
    private final class Connection: OwnedAuthorityConnection, @unchecked Sendable {
        private let lock = NSLock()
        private var starts = 0
        private var stops = 0
        let onActivate: @Sendable () -> Void
        let onClose: @Sendable () -> Void
        init(onActivate: @escaping @Sendable () -> Void = {}, onClose: @escaping @Sendable () -> Void = {}) {
            self.onActivate = onActivate; self.onClose = onClose
        }
        func activate() { lock.withLock { starts += 1 }; onActivate() }
        func close() { lock.withLock { stops += 1 }; onClose() }
        var activations: Int { lock.withLock { starts } }
        var closures: Int { lock.withLock { stops } }
    }
    func testReservationIncludesSetupAndRejectsBeforeStartOrAfterClose() throws {
        let registry = try AuthorityConnectionRegistry(maximum: 1, timeoutMilliseconds: 5000)
        XCTAssertNil(registry.reserve()); try registry.start()
        XCTAssertThrowsError(try registry.start())
        let id = try XCTUnwrap(registry.reserve())
        XCTAssertNil(registry.reserve())
        let connection = Connection()
        XCTAssertTrue(registry.install(connection, id: id)); XCTAssertEqual(connection.activations, 1)
        registry.close(); registry.close(); XCTAssertEqual(connection.closures, 1)
        XCTAssertNil(registry.reserve()); XCTAssertThrowsError(try registry.start())
    }
    func testFailedSetupAndRepeatedRemovalReleaseOnlyTheirSlot() throws {
        let registry = try AuthorityConnectionRegistry(maximum: 1, timeoutMilliseconds: 5000)
        try registry.start()
        let old = try XCTUnwrap(registry.reserve()); registry.remove(old)
        let current = try XCTUnwrap(registry.reserve()), connection = Connection()
        XCTAssertTrue(registry.install(connection, id: current))
        registry.remove(old); registry.expire(old)
        XCTAssertNil(registry.reserve()); XCTAssertEqual(connection.closures, 0)
        registry.remove(current); registry.remove(current)
        XCTAssertEqual(connection.closures, 1); XCTAssertNotNil(registry.reserve())
        registry.close()
    }
    func testExpiryDuringSetupNeverActivatesLateConnection() throws {
        let registry = try AuthorityConnectionRegistry(maximum: 1, timeoutMilliseconds: 5000)
        try registry.start(); let id = try XCTUnwrap(registry.reserve())
        registry.expire(id)
        let late = Connection()
        XCTAssertFalse(registry.install(late, id: id))
        XCTAssertEqual(late.activations, 0); XCTAssertEqual(late.closures, 1)
        XCTAssertNotNil(registry.reserve()); registry.close()
    }
    func testHandshakeCancelsExpiryAndRetainsConnectionSlot() throws {
        let registry = try AuthorityConnectionRegistry(maximum: 1, timeoutMilliseconds: 5000)
        try registry.start(); let id = try XCTUnwrap(registry.reserve())
        let connection = Connection(onActivate: { registry.handshake(id) })
        XCTAssertTrue(registry.install(connection, id: id))
        registry.expire(id)
        XCTAssertEqual(connection.closures, 0); XCTAssertNil(registry.reserve())
        registry.close(); XCTAssertEqual(connection.closures, 1)
    }
    func testShutdownDuringActivationAndRecursiveRemovalDoNotDeadlock() throws {
        let registry = try AuthorityConnectionRegistry(maximum: 1, timeoutMilliseconds: 5000)
        try registry.start(); let id = try XCTUnwrap(registry.reserve())
        let connection = Connection(onActivate: { registry.close() }, onClose: { registry.remove(id) })
        XCTAssertFalse(registry.install(connection, id: id))
        XCTAssertEqual(connection.activations, 1); XCTAssertGreaterThan(connection.closures, 0)
        XCTAssertNil(registry.reserve())
    }
    func testRealDeadlineClosesStalledHandshake() throws {
        let closed = expectation(description: "handshake deadline")
        let registry = try AuthorityConnectionRegistry(maximum: 1, timeoutMilliseconds: 100)
        try registry.start(); let id = try XCTUnwrap(registry.reserve())
        let connection = Connection(onClose: { closed.fulfill() })
        XCTAssertTrue(registry.install(connection, id: id))
        wait(for: [closed], timeout: 2)
        XCTAssertEqual(connection.closures, 1); XCTAssertNotNil(registry.reserve())
        registry.close()
    }
    func testConfigurationBounds() {
        for maximum in [0, 65] { XCTAssertThrowsError(try AuthorityConnectionRegistry(maximum: maximum, timeoutMilliseconds: 5000)) }
        for timeout: UInt64 in [0, 60_001] { XCTAssertThrowsError(try AuthorityConnectionRegistry(maximum: 1, timeoutMilliseconds: timeout)) }
    }
}
