import CryptoKit
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class AuthorityRequestFrameTests: XCTestCase, @unchecked Sendable {
    private let mac = Data(repeating: 1, count: 16)
    private let account = Data(repeating: 2, count: 16)
    private let requestID = Data(repeating: 5, count: 16)

    private final class Driver: AuthorityXPCDriver, @unchecked Sendable {
        let version: UInt64
        let frame: Data
        let respond: Bool
        private let lock = NSLock()
        private var requests = 0
        private var versions = 0
        init(version: UInt64 = 1, frame: Data = Data(), respond: Bool = true) {
            self.version = version; self.frame = frame; self.respond = respond
        }
        var counts: (requests: Int, versions: Int) { lock.withLock { (requests, versions) } }
        func start(invalidated: @escaping @Sendable () -> Void) {}
        func hello(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.hello(1)) }
        func snapshot(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.snapshot(Data([1]))) }
        func validate(_ binding: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.validation(true)) }
        func deliveryVersion(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
            lock.withLock { versions += 1 }
            if respond { reply(.deliveryVersion(version)) }
        }
        func requestFrame(_ binding: Data, requestID: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
            lock.withLock { requests += 1 }; reply(.requestFrame(frame))
        }
        func close() {}
    }
    private func binding() throws -> AuthorityPeerBinding {
        try AuthorityPeerBinding(scope: ChannelScope(macID: mac, accountID: account,
            phoneID: Data(repeating: 3, count: 16), enrollmentEpoch: Data(repeating: 4, count: 16)),
            transportPublicKey: P256.Signing.PrivateKey().publicKey.derRepresentation, revision: UUID())
    }
    private func frame(request: Data? = nil, status: Bool = false) throws -> Data {
        let limits = try CBORLimits(maxBytes: 4096, maxDepth: 12, maxItems: 256)
        let payload = try IssuedRequestPayload(contract: RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1),
            macID: mac, accountID: account, requestID: request ?? requestID, challenge: Data(repeating: 6, count: 32),
            requiredFeatures: [], createdUnixMilliseconds: 1, expiresUnixMilliseconds: 2, canonicalCapture: Data([0xa0]),
            permittedActions: [.init(choice: .decline, scope: .currentRequest)], bodyLimits: limits, captureLimits: limits)
        return try ApprovalMessage(wireVersion: 1, type: status ? .status : .request, purpose: status ? .status : .issuedRequest,
            body: payload.encode(limits: limits), signature: Data(repeating: 0, count: 64)).encode(maximumBodyBytes: 4096)
    }
    func testClientNegotiatesBeforeSendingAndCachesSupportedVersion() async throws {
        let bytes = try frame(), peer = try binding()
        let driver = Driver(frame: bytes), channel = AuthorityXPCChannel(driver: driver)
        try await channel.start()
        let first = try await channel.requestFrame(binding: peer, requestID: requestID)
        let second = try await channel.requestFrame(binding: peer, requestID: requestID)
        XCTAssertEqual(first, bytes); XCTAssertEqual(second, bytes)
        XCTAssertEqual(driver.counts.requests, 2); XCTAssertEqual(driver.counts.versions, 1)
        await channel.close()
    }
    func testUnsupportedVersionSendsNoBindingAndKeepsCommonProtocolUsable() async throws {
        for version: UInt64 in [0, 2, UInt64.max] {
            let driver = Driver(version: version), channel = AuthorityXPCChannel(driver: driver)
            try await channel.start()
            do { _ = try await channel.requestFrame(binding: binding(), requestID: requestID); XCTFail() }
            catch { guard case AuthorityXPCError.unsupportedRequestDelivery = error else { return XCTFail("wrong error") } }
            XCTAssertEqual(driver.counts.requests, 0)
            let snapshot = try await channel.trustSnapshot()
            XCTAssertEqual(snapshot, Data([1]))
            await channel.close()
        }
    }
    func testVersionTimeoutSendsNoRequestMaterial() async throws {
        let driver = Driver(respond: false), channel = AuthorityXPCChannel(driver: driver, timeoutMilliseconds: 20)
        try await channel.start()
        do { _ = try await channel.requestFrame(binding: binding(), requestID: requestID); XCTFail() }
        catch { guard case AuthorityXPCError.timedOut = error else { return XCTFail("wrong error") } }
        XCTAssertEqual(driver.counts.requests, 0)
        await channel.close()
    }
    func testEmptyFrameIsNoEligibleFrameAndMalformedFrameRetiresClient() async throws {
        let emptyDriver = Driver(), empty = AuthorityXPCChannel(driver: emptyDriver)
        try await empty.start()
        let absent = try await empty.requestFrame(binding: binding(), requestID: requestID)
        XCTAssertNil(absent); await empty.close()
        for bytes in [Data([0]), try frame(request: Data(repeating: 9, count: 16)), try frame(status: true),
                      Data(repeating: 0, count: AuthorityRequestFrame.maximumBytes + 1)] {
            let driver = Driver(frame: bytes), channel = AuthorityXPCChannel(driver: driver)
            try await channel.start()
            do { _ = try await channel.requestFrame(binding: binding(), requestID: requestID); XCTFail() } catch {}
            do { _ = try await channel.trustSnapshot(); XCTFail("Malformed reply did not retire client") } catch {}
            await channel.close()
        }
    }
    func testEndpointRequiresHelloAndDeliveryNegotiationBeforeHandler() throws {
        let trust = DirectApprovalTrust(macID: mac, accountID: account, revision: UUID(), peers: [])
        for hello in [false, true] {
            let endpoint = try AuthorityXPCEndpoint(macID: mac, accountID: account, budget: AuthorityXPCWorkBudget(),
                verify: {}, invalidate: {}, snapshot: { trust }, validate: { _ in true },
                requestFrame: { _, _ in XCTFail("Handler called before negotiation"); return nil })
            if hello { endpoint.hello { XCTAssertEqual($0, 1) } }
            endpoint.requestFrame(try AuthorityTrustCodec.encodeBinding(binding()), requestID: requestID) { XCTAssertNil($0) }
        }
    }
    func testEndpointReturnsScopedFrameOrExplicitEmptyResponse() throws {
        let trust = DirectApprovalTrust(macID: mac, accountID: account, revision: UUID(), peers: [])
        let expectedID = requestID
        for bytes in [nil, try frame()] as [Data?] {
            let endpoint = try AuthorityXPCEndpoint(macID: mac, accountID: account, budget: AuthorityXPCWorkBudget(),
                verify: {}, invalidate: {}, snapshot: { trust }, validate: { _ in true }, requestFrame: { _, id in
                    XCTAssertEqual(id, expectedID); return bytes
                })
            endpoint.hello { XCTAssertEqual($0, 1) }
            endpoint.requestDeliveryVersion { XCTAssertEqual($0, 1) }
            endpoint.requestFrame(try AuthorityTrustCodec.encodeBinding(binding()), requestID: requestID) {
                XCTAssertEqual($0, bytes ?? Data())
            }
            endpoint.close()
        }
    }
    func testDisabledEndpointDoesNotAdvertiseDeliveryAndRejectsWrongFrameKind() throws {
        let trust = DirectApprovalTrust(macID: mac, accountID: account, revision: UUID(), peers: [])
        let disabled = try AuthorityXPCEndpoint(macID: mac, accountID: account, budget: AuthorityXPCWorkBudget(),
            verify: {}, invalidate: {}, snapshot: { trust }, validate: { _ in true })
        disabled.hello { XCTAssertEqual($0, 1) }
        disabled.requestDeliveryVersion { XCTAssertEqual($0, 0) }
        disabled.trustSnapshot { XCTAssertNotNil($0) }
        disabled.close()
        let wrong = try frame(status: true)
        let endpoint = try AuthorityXPCEndpoint(macID: mac, accountID: account, budget: AuthorityXPCWorkBudget(),
            verify: {}, invalidate: {}, snapshot: { trust }, validate: { _ in true }, requestFrame: { _, _ in wrong })
        endpoint.hello { XCTAssertEqual($0, 1) }
        endpoint.requestDeliveryVersion { XCTAssertEqual($0, 1) }
        endpoint.requestFrame(try AuthorityTrustCodec.encodeBinding(binding()), requestID: requestID) { XCTAssertNil($0) }
        endpoint.close()
    }
}
