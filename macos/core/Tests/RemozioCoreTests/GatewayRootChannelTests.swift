import CryptoKit
import Foundation
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

final class GatewayRootChannelTests: XCTestCase, @unchecked Sendable {
    private final class Driver: GatewayRootDriver {
        struct State {
            var calls: [GatewayRootCall] = []
            var closed = 0
            var version: UInt64 = 1
            var hold = false
            var response: Data?
            var reply: (@Sendable (GatewayRootResponse) -> Void)?
        }
        let value = Mutex(State())
        func start(closed: @escaping @Sendable () -> Void) {}
        func invoke(_ call: GatewayRootCall, reply: @escaping @Sendable (GatewayRootResponse) -> Void) {
            let result: GatewayRootResponse? = value.withLock { state in
                state.calls.append(call)
                if state.hold { state.reply = reply; return nil }
                switch call {
                case .hello: return .version(state.version)
                case .synchronize: return .synchronized(true)
                case .command: return .command(state.response)
                }
            }
            if let result { reply(result) }
        }
        func close() { value.withLock { $0.closed += 1 } }
    }
    private func snapshot() throws -> GatewayHostSnapshot {
        let id = Data(repeating: 1, count: 16)
        let identity = try GatewayRegistrationIdentity(ownerID: id, macID: id, accountID: id, gatewayID: id,
            lifecycleEpoch: id, rootPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation)
        return try GatewayHostSnapshot(registration: identity, rootEpoch: UUID(), sequence: 1, observedAtMilliseconds: 100,
            leaseDeadlineMilliseconds: 200, enrollments: [], active: false, phoneRouting: false)
    }
    func testSensitiveCallsCannotPrecedeHandshakeOrFollowUnknownVersion() async throws {
        let driver = Driver(), channel = GatewayRootChannel(driver: driver)
        do { try await channel.synchronize(snapshot()); XCTFail() } catch {}
        XCTAssertEqual(driver.value.withLock { $0.calls.count }, 0)
        driver.value.withLock { $0.version = 2 }
        do { try await channel.start(); XCTFail() } catch {}
        do { try await channel.synchronize(snapshot()); XCTFail() } catch {}
        XCTAssertEqual(driver.value.withLock { $0.calls.count }, 1)
        if case .hello = driver.value.withLock({ $0.calls[0] }) {} else { XCTFail() }
        await channel.close()
    }
    func testValidHandshakeAllowsBoundedSnapshotAndUnverifiedRecoveryData() async throws {
        let driver = Driver(), channel = GatewayRootChannel(driver: driver)
        driver.value.withLock { $0.response = try? GatewayRootCommand.reply([.bytes(Data([1])), .bytes(Data(repeating: 2, count: 64))]) }
        try await channel.start()
        try await channel.synchronize(snapshot())
        let reply = try await channel.head(query: Data([1]))
        XCTAssertEqual(reply.canonicalPayload, Data([1]))
        XCTAssertEqual(reply.signature.count, 64)
        XCTAssertEqual(driver.value.withLock { $0.calls.count }, 3)
        await channel.close()
    }
    func testMalformedRecoveryReplyRetiresChannel() async throws {
        let driver = Driver(), channel = GatewayRootChannel(driver: driver)
        driver.value.withLock { $0.response = try? GatewayRootCommand.reply([.bytes(Data([1])), .bytes(Data(repeating: 2, count: 63))]) }
        try await channel.start()
        do { _ = try await channel.head(query: Data([1])); XCTFail() } catch {}
        do { try await channel.synchronize(snapshot()); XCTFail() } catch {}
        XCTAssertEqual(driver.value.withLock { $0.calls.count }, 2)
        await channel.close()
    }
    func testTimeoutClosesConnectionAndLateHelloCannotReopenIt() async throws {
        let driver = Driver(), channel = GatewayRootChannel(driver: driver, timeoutMilliseconds: 20)
        driver.value.withLock { $0.hold = true }
        do { try await channel.start(); XCTFail() } catch {
            XCTAssertEqual(error as? GatewayRootChannelError, .timedOut)
        }
        driver.value.withLock { $0.reply }?(.version(1))
        do { try await channel.synchronize(snapshot()); XCTFail() } catch {}
        XCTAssertEqual(driver.value.withLock { $0.calls.count }, 1)
        await channel.close()
    }
    func testWrongAccountCannotSendHello() async throws {
        let driver = Driver(), channel = GatewayRootChannel(driver: driver, verifyAccount: { throw GatewayServiceError.wrongAccount })
        do { try await channel.start(); XCTFail() } catch { XCTAssertEqual(error as? GatewayServiceError, .wrongAccount) }
        XCTAssertEqual(driver.value.withLock { $0.calls.count }, 0)
        await channel.close()
    }
}
