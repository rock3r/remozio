import CryptoKit
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class AuthorityPendingRequestsTests: XCTestCase, @unchecked Sendable {
    private let mac = Data(repeating: 1, count: 16)
    private let account = Data(repeating: 2, count: 16)
    private func id(_ n: UInt8) -> Data { Data(repeating: n, count: 16) }
    private func binding() throws -> AuthorityPeerBinding {
        try AuthorityPeerBinding(scope: ChannelScope(macID: mac, accountID: account, phoneID: id(3), enrollmentEpoch: id(4)),
            transportPublicKey: P256.Signing.PrivateKey().publicKey.derRepresentation, revision: UUID())
    }
    private final class Driver: AuthorityXPCDriver, @unchecked Sendable {
        let version: UInt64
        let bytes: Data?
        let respond: Bool
        private let lock = NSLock()
        private var versions = 0
        private var bindings: [Data] = []
        init(version: UInt64 = 1, bytes: Data? = nil, respond: Bool = true) {
            self.version = version; self.bytes = bytes; self.respond = respond
        }
        var counts: (versions: Int, bindings: [Data]) { lock.withLock { (versions, bindings) } }
        func start(invalidated: @escaping @Sendable () -> Void) {}
        func hello(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.hello(1)) }
        func snapshot(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.snapshot(Data([1]))) }
        func validate(_ binding: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.validation(true)) }
        func discoveryVersion(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
            lock.withLock { versions += 1 }
            if respond { reply(.discoveryVersion(version)) }
        }
        func pendingRequests(_ binding: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
            lock.withLock { bindings.append(binding) }; reply(bytes.map(AuthorityXPCReply.pendingRequests) ?? .failed)
        }
        func close() {}
    }
    func testCodecBoundsIDsAndBindsExactEnrollmentAndRevision() throws {
        let peer = try binding()
        var ids = (0..<4096).map { value -> Data in
            var bytes = Data(repeating: 0, count: 16)
            bytes[14] = UInt8(value >> 8); bytes[15] = UInt8(value & 255)
            return bytes
        }
        let expected = ids
        ids.reverse()
        let bytes = try AuthorityPendingRequests.encode(ids, binding: peer)
        XCTAssertLessThan(bytes.count, AuthorityPendingRequests.maximumBytes)
        XCTAssertEqual(try AuthorityPendingRequests.decode(bytes, binding: peer), expected)
        XCTAssertThrowsError(try AuthorityPendingRequests.decode(bytes, binding: binding()))
        XCTAssertThrowsError(try AuthorityPendingRequests.encode(ids + [id(8)], binding: peer))
        XCTAssertThrowsError(try AuthorityPendingRequests.encode([id(8), id(8)], binding: peer))
        XCTAssertThrowsError(try AuthorityPendingRequests.encode([Data(count: 15)], binding: peer))
        XCTAssertEqual(try AuthorityPendingRequests.decode(AuthorityPendingRequests.encode([], binding: peer), binding: peer), [])
    }
    func testCodecRejectsUnsortedDuplicateAndUnknownVersions() throws {
        let peer = try binding(), limits = try CBORLimits(maxBytes: 4096, maxDepth: 3, maxItems: 32)
        for (version, values) in [(UInt64(1), [id(8), id(7)]), (1, [id(8), id(8)]), (2, [])] {
            let bytes = try DeterministicCBOR.encode(.map([
                0: .unsigned(version), 1: .bytes(AuthorityTrustCodec.encodeBinding(peer)),
                2: .array(values.map(CBORValue.bytes)),
            ]), limits: limits)
            XCTAssertThrowsError(try AuthorityPendingRequests.decode(bytes, binding: peer))
        }
    }
    func testClientNegotiatesBeforeBindingAndCachesVersion() async throws {
        let peer = try binding(), bytes = try AuthorityPendingRequests.encode([id(8)], binding: peer)
        let driver = Driver(bytes: bytes), channel = AuthorityXPCChannel(driver: driver)
        try await channel.start()
        let first = try await channel.pendingRequestIDs(binding: peer), second = try await channel.pendingRequestIDs(binding: peer)
        XCTAssertEqual(first, [id(8)]); XCTAssertEqual(second, first)
        XCTAssertEqual(driver.counts.versions, 1)
        XCTAssertEqual(driver.counts.bindings, try Array(repeating: AuthorityTrustCodec.encodeBinding(peer), count: 2))
        await channel.close()
    }
    func testUnsupportedDiscoveryKeepsCommonOperationsAndSendsNoBinding() async throws {
        for version: UInt64 in [0, 2, UInt64.max] {
            let driver = Driver(version: version), channel = AuthorityXPCChannel(driver: driver)
            try await channel.start()
            do { _ = try await channel.pendingRequestIDs(binding: binding()); XCTFail() }
            catch { guard case AuthorityXPCError.unsupportedRequestDiscovery = error else { return XCTFail("Wrong error") } }
            XCTAssertTrue(driver.counts.bindings.isEmpty)
            let bytes = try await channel.trustSnapshot()
            XCTAssertEqual(bytes, Data([1]))
            await channel.close()
        }
    }
    func testVersionTimeoutDoesNotSendBinding() async throws {
        let driver = Driver(respond: false), channel = AuthorityXPCChannel(driver: driver, timeoutMilliseconds: 20)
        try await channel.start()
        do { _ = try await channel.pendingRequestIDs(binding: binding()); XCTFail() }
        catch { guard case AuthorityXPCError.timedOut = error else { return XCTFail("Wrong error") } }
        XCTAssertTrue(driver.counts.bindings.isEmpty)
        await channel.close()
    }
    func testBadReplyRetiresClientInsteadOfTreatingItAsEmptyDiscovery() async throws {
        let peer = try binding()
        for bytes in [nil, Data(), Data([0]), try AuthorityPendingRequests.encode([], binding: binding()),
                      Data(count: AuthorityPendingRequests.maximumBytes + 1)] as [Data?] {
            let driver = Driver(bytes: bytes), channel = AuthorityXPCChannel(driver: driver)
            try await channel.start()
            do { _ = try await channel.pendingRequestIDs(binding: peer); XCTFail() } catch {}
            do { _ = try await channel.trustSnapshot(); XCTFail("Bad reply must retire connection") } catch {}
            await channel.close()
        }
    }
    func testEndpointRequiresHelloAndDiscoveryNegotiation() throws {
        let trust = DirectApprovalTrust(macID: mac, accountID: account, revision: UUID(), peers: [])
        for hello in [false, true] {
            let endpoint = try AuthorityXPCEndpoint(macID: mac, accountID: account, budget: AuthorityXPCWorkBudget(),
                verify: {}, invalidate: {}, snapshot: { trust }, validate: { _ in true },
                pendingRequestIDs: { _ in XCTFail("Unnegotiated handler"); return [] })
            if hello { endpoint.hello { XCTAssertEqual($0, 1) } }
            endpoint.pendingRequestIDs(try AuthorityTrustCodec.encodeBinding(binding())) { XCTAssertNil($0) }
        }
    }
    func testEndpointReturnsScopedListAndDisablesDiscoveryWithoutProvider() throws {
        let trust = DirectApprovalTrust(macID: mac, accountID: account, revision: UUID(), peers: []), peer = try binding()
        for ids in [[], [id(9), id(8)]] {
            let expected = try AuthorityPendingRequests.encode(ids, binding: peer)
            let endpoint = try AuthorityXPCEndpoint(macID: mac, accountID: account, budget: AuthorityXPCWorkBudget(),
                verify: {}, invalidate: {}, snapshot: { trust }, validate: { _ in true }, pendingRequestIDs: { _ in ids })
            endpoint.hello { XCTAssertEqual($0, 1) }
            endpoint.requestDiscoveryVersion { XCTAssertEqual($0, 1) }
            endpoint.requestDeliveryVersion { XCTAssertEqual($0, 0) }
            endpoint.pendingRequestIDs(try AuthorityTrustCodec.encodeBinding(peer)) { XCTAssertEqual($0, expected) }
            endpoint.close()
        }
        let disabled = try AuthorityXPCEndpoint(macID: mac, accountID: account, budget: AuthorityXPCWorkBudget(),
            verify: {}, invalidate: {}, snapshot: { trust }, validate: { _ in true })
        disabled.hello { XCTAssertEqual($0, 1) }
        disabled.requestDiscoveryVersion { XCTAssertEqual($0, 0) }
        disabled.trustSnapshot { XCTAssertNotNil($0) }
        disabled.close()
    }
}
