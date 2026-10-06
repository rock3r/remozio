import CryptoKit
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class AuthorityRequestExchangeTests: XCTestCase, @unchecked Sendable {
    private let mac = Data(repeating: 1, count: 16), account = Data(repeating: 2, count: 16)
    private let request = Data(repeating: 5, count: 16)
    private final class Driver: AuthorityXPCDriver, @unchecked Sendable {
        let version: UInt64, response: Data
        let hold: Bool
        private let lock = NSLock()
        private var versions = 0, exchanges = 0
        private var callback: (@Sendable (AuthorityXPCReply) -> Void)?
        let sent = XCTestExpectation(description: "exchange sent")
        var counts: (Int, Int) { lock.withLock { (versions, exchanges) } }
        init(version: UInt64 = 1, response: Data = Data(), hold: Bool = false) {
            self.version = version; self.response = response; self.hold = hold
        }
        func start(invalidated: @escaping @Sendable () -> Void) {}
        func hello(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.hello(1)) }
        func snapshot(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.snapshot(Data([1]))) }
        func validate(_ binding: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.validation(true)) }
        func exchangeVersion(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
            lock.withLock { versions += 1 }; reply(.exchangeVersion(version))
        }
        func exchange(_ binding: Data, query: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
            lock.withLock { exchanges += 1; if hold { callback = reply } }
            if hold { sent.fulfill() } else { reply(.exchange(response)) }
        }
        func finish() { lock.withLock { callback }?(.exchange(response)) }
        func close() {}
    }
    private func binding() throws -> AuthorityPeerBinding {
        try AuthorityPeerBinding(scope: ChannelScope(macID: mac, accountID: account,
            phoneID: Data(repeating: 3, count: 16), enrollmentEpoch: Data(repeating: 4, count: 16)),
            transportPublicKey: P256.Signing.PrivateKey().publicKey.derRepresentation, revision: UUID())
    }
    private func status(requestID: Data? = nil) throws -> Data {
        let limits = try CBORLimits(maxBytes: 3968, maxDepth: 4, maxItems: 64)
        let payload = try RequestStatusPayload(macID: mac, accountID: account, requestID: requestID ?? request,
            requestDigest: Data(repeating: 6, count: 32), challenge: Data(repeating: 7, count: 32), revision: 1,
            phase: .queued, reason: .none, observationID: Data(repeating: 8, count: 16), observedAgeMs: 10,
            authorizationRemainingMs: 100, estimatedLifetimeMs: nil, lateObservation: false,
            terminalAgeMs: nil, decisionPhoneID: nil)
        return try ApprovalMessage(wireVersion: 1, type: .status, purpose: .status,
            body: payload.encode(limits: limits), signature: Data(repeating: 0, count: 64)).encode(maximumBodyBytes: 3968)
    }
    func testQueryRoundTripsBoundedDecisionOrReadOnlyStatusAndRejectsInvalidFields() throws {
        for frame: Data? in [nil, Data([1]), Data(repeating: 2, count: 4096)] {
            let bytes = try AuthorityRequestExchange.encode(requestID: request, decisionFrame: frame)
            let decoded = try AuthorityRequestExchange.decode(bytes)
            XCTAssertEqual(decoded.requestID, request); XCTAssertEqual(decoded.decisionFrame, frame)
        }
        XCTAssertThrowsError(try AuthorityRequestExchange.encode(requestID: Data()))
        XCTAssertThrowsError(try AuthorityRequestExchange.encode(requestID: request, decisionFrame: Data()))
        XCTAssertThrowsError(try AuthorityRequestExchange.encode(requestID: request, decisionFrame: Data(repeating: 1, count: 4097)))
        for bytes in [Data([0xa0]), Data(repeating: 1, count: 4353)] {
            XCTAssertThrowsError(try AuthorityRequestExchange.decode(bytes))
        }
    }
    func testClientNegotiatesBeforeQueryAndCachesVersion() async throws {
        let bytes = try status(), driver = Driver(response: bytes), channel = AuthorityXPCChannel(driver: driver), peer = try binding()
        try await channel.start()
        let first = try await channel.exchangeRequest(binding: peer, requestID: request)
        let second = try await channel.exchangeRequest(binding: peer, requestID: request, decisionFrame: Data([1]))
        XCTAssertEqual(first, bytes); XCTAssertEqual(second, bytes)
        XCTAssertEqual(driver.counts.0, 1); XCTAssertEqual(driver.counts.1, 2)
        await channel.close()
    }
    func testUnsupportedVersionSendsNoRequestAndLeavesCommonOperationsUsable() async throws {
        for version: UInt64 in [0, 2, UInt64.max] {
            let driver = Driver(version: version), channel = AuthorityXPCChannel(driver: driver)
            try await channel.start()
            do { _ = try await channel.exchangeRequest(binding: binding(), requestID: request, decisionFrame: Data([1])); XCTFail() }
            catch { guard case AuthorityXPCError.unsupportedRequestExchange = error else { return XCTFail("wrong error") } }
            XCTAssertEqual(driver.counts.1, 0)
            let common = try await channel.trustSnapshot(); XCTAssertEqual(common, Data([1]))
            await channel.close()
        }
    }
    func testMalformedOrWrongRequestResponseRetiresChannelWhileAbsenceDoesNot() async throws {
        let empty = AuthorityXPCChannel(driver: Driver())
        try await empty.start()
        let absent = try await empty.exchangeRequest(binding: binding(), requestID: request)
        XCTAssertNil(absent)
        _ = try await empty.trustSnapshot(); await empty.close()
        for bytes in [Data([1]), try status(requestID: Data(repeating: 9, count: 16)), Data(repeating: 1, count: 4097)] {
            let channel = AuthorityXPCChannel(driver: Driver(response: bytes))
            try await channel.start()
            do { _ = try await channel.exchangeRequest(binding: binding(), requestID: request); XCTFail() } catch {}
            do { _ = try await channel.trustSnapshot(); XCTFail("malformed response kept channel") } catch {}
        }
    }
    func testCancellationAndTimeoutRejectLateExchangeResponseWithoutRetry() async throws {
        for cancel in [false, true] {
            let driver = Driver(response: try status(), hold: true)
            let channel = AuthorityXPCChannel(driver: driver, timeoutMilliseconds: cancel ? 5000 : 100)
            let peer = try binding(), request = request
            try await channel.start()
            let work = Task { try await channel.exchangeRequest(binding: peer, requestID: request, decisionFrame: Data([1])) }
            await fulfillment(of: [driver.sent], timeout: 2)
            if cancel { work.cancel() }
            do { _ = try await work.value; XCTFail("late response accepted") } catch {}
            driver.finish()
            do { _ = try await channel.trustSnapshot(); XCTFail("retired channel reopened") } catch {}
            XCTAssertEqual(driver.counts.1, 1)
        }
    }
    func testEndpointRequiresHelloAndExtensionBeforeCallingHandler() throws {
        let trust = DirectApprovalTrust(macID: mac, accountID: account, revision: UUID(), peers: [])
        for hello in [false, true] {
            let endpoint = try AuthorityXPCEndpoint(macID: mac, accountID: account, budget: AuthorityXPCWorkBudget(),
                verify: {}, invalidate: {}, snapshot: { trust }, validate: { _ in true },
                exchangeRequest: { _, _, _ in XCTFail("unnegotiated exchange"); return nil })
            if hello { endpoint.hello { XCTAssertEqual($0, 1) } }
            endpoint.exchangeRequest(try AuthorityTrustCodec.encodeBinding(binding()),
                query: try AuthorityRequestExchange.encode(requestID: request)) { XCTAssertNil($0) }
        }
    }
    func testEndpointChecksQueryAndScopedStatusAndPreservesEmptyAbsence() throws {
        let trust = DirectApprovalTrust(macID: mac, accountID: account, revision: UUID(), peers: []), request = request
        for bytes: Data? in [nil, try status(), try status(requestID: Data(repeating: 9, count: 16))] {
            let endpoint = try AuthorityXPCEndpoint(macID: mac, accountID: account, budget: AuthorityXPCWorkBudget(),
                verify: {}, invalidate: {}, snapshot: { trust }, validate: { _ in true },
                exchangeRequest: { _, id, decision in XCTAssertEqual(id, request); XCTAssertEqual(decision, Data([1])); return bytes })
            endpoint.hello { XCTAssertEqual($0, 1) }
            endpoint.requestExchangeVersion { XCTAssertEqual($0, 1) }
            let expected = try status()
            let valid = bytes == nil || bytes == expected
            endpoint.exchangeRequest(try AuthorityTrustCodec.encodeBinding(binding()),
                query: try AuthorityRequestExchange.encode(requestID: request, decisionFrame: Data([1]))) {
                XCTAssertEqual($0, valid ? bytes ?? Data() : nil)
            }
            endpoint.close()
        }
        let disabled = try AuthorityXPCEndpoint(macID: mac, accountID: account, budget: AuthorityXPCWorkBudget(),
            verify: {}, invalidate: {}, snapshot: { trust }, validate: { _ in true })
        disabled.hello { XCTAssertEqual($0, 1) }; disabled.requestExchangeVersion { XCTAssertEqual($0, 0) }
        disabled.trustSnapshot { XCTAssertNotNil($0) }; disabled.close()
    }
}
