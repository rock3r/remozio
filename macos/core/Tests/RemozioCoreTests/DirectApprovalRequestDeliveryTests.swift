import CryptoKit
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class DirectApprovalRequestDeliveryTests: XCTestCase, @unchecked Sendable {
    private static func id(_ value: UInt8) -> Data { Data(repeating: value, count: 16) }
    private static func capability(features: Set<UInt64> = []) throws -> ChannelRequestCapability {
        try .init(kind: 0, wireVersion: 1, schemaVersion: 1, features: features)
    }
    private static func scope(phone: UInt8 = 3) throws -> ChannelScope {
        try .init(macID: id(1), accountID: id(2), phoneID: id(phone), enrollmentEpoch: id(4))
    }
    private static func frame(_ request: UInt8, features: Set<UInt64> = [], bodyBytes: Int? = nil) throws -> (Data, P256.Signing.PublicKey) {
        let limits = try CBORLimits(maxBytes: 4096, maxDepth: 12, maxItems: 256)
        func payload(_ capture: Data) throws -> IssuedRequestPayload {
            try IssuedRequestPayload(contract: .init(requestKind: .command, wireVersion: 1, schemaVersion: 1),
                macID: id(1), accountID: id(2), requestID: id(request), challenge: Data(repeating: 9, count: 32),
                requiredFeatures: features, createdUnixMilliseconds: 1000, expiresUnixMilliseconds: 2000,
                canonicalCapture: capture, permittedActions: [.init(choice: .execute, scope: .currentRequest)],
                bodyLimits: limits, captureLimits: limits)
        }
        var requestPayload = try payload(Data([0xa0]))
        if let bodyBytes {
            var found = false
            for padding in 0..<bodyBytes {
                let capture = try DeterministicCBOR.encode(.map([0: .bytes(Data(count: padding))]), limits: limits)
                let candidate = try payload(capture)
                if try candidate.encode(limits: limits).count == bodyBytes {
                    requestPayload = candidate; found = true; break
                }
            }
            guard found else { throw ApprovalChannelError.invalidInput }
        }
        let payload = requestPayload
        let body = try payload.encode(limits: limits), key = P256.Signing.PrivateKey()
        let input = try SigningInput.make(wireVersion: 1, messageType: .request, purpose: .issuedRequest,
            canonicalPayload: body, payloadLimits: limits, inputLimits: limits)
        let bytes = try ApprovalMessage(wireVersion: 1, type: .request, purpose: .issuedRequest, body: body,
            signature: key.signature(for: input).rawRepresentation).encode(maximumBodyBytes: 3968)
        return (bytes, key.publicKey)
    }
    private final class Driver: AuthorityXPCDriver, @unchecked Sendable {
        private let lock = NSLock()
        let trust: DirectApprovalTrust
        let ids: [Data]
        let frames: [Data: Data]
        private var held: (@Sendable (AuthorityXPCReply) -> Void)?
        private var hold = false
        private var queries: [Data] = []
        private var discoveries = 0
        let requested = XCTestExpectation(description: "frame requested")
        init(trust: DirectApprovalTrust, ids: [Data], frames: [Data: Data]) {
            self.trust = trust; self.ids = ids; self.frames = frames
        }
        var frameIDs: [Data] { lock.withLock { queries } }
        var discoveryCount: Int { lock.withLock { discoveries } }
        func holdFrame() { lock.withLock { hold = true } }
        func finishFrame(_ bytes: Data) {
            let callback = lock.withLock { let value = held; held = nil; return value }
            callback?(.requestFrame(bytes))
        }
        func start(invalidated: @escaping @Sendable () -> Void) { }
        func hello(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.hello(1)) }
        func snapshot(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
            reply(.snapshot(try! AuthorityTrustCodec.encodeSnapshot(trust)))
        }
        func validate(_ binding: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.validation(true)) }
        func discoveryVersion(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.discoveryVersion(1)) }
        func deliveryVersion(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.deliveryVersion(1)) }
        func pendingRequests(_ bytes: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
            lock.withLock { discoveries += 1 }
            let binding = try! AuthorityTrustCodec.decodeBinding(bytes, expectedMacID: SelfID.mac, expectedAccountID: SelfID.account)
            reply(.pendingRequests(try! AuthorityPendingRequests.encode(ids, binding: binding)))
        }
        func requestFrame(_ binding: Data, requestID: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
            let waiting = lock.withLock {
                queries.append(requestID)
                if hold { held = reply; return true }; return false
            }
            if waiting { requested.fulfill() } else { reply(.requestFrame(frames[requestID] ?? Data())) }
        }
        func close() { }
    }
    private enum SelfID { static let mac = id(1), account = id(2) }
    private final class Listener: OwnedDirectListener, @unchecked Sendable {
        func start() throws { }
        func close() { }
    }
    private final class Factory: @unchecked Sendable {
        private let lock = NSLock()
        private var callback: (@Sendable (DirectApprovalPeer, NegotiatedNetworkChannel) async throws -> Void)?
        private var incarnation: UUID?
        var generation: UUID { lock.withLock { incarnation! } }
        func make(_ generation: UUID, _ handler: @escaping @Sendable (DirectApprovalPeer, NegotiatedNetworkChannel) async throws -> Void) -> Listener {
            lock.withLock { incarnation = generation; callback = handler }
            return Listener()
        }
        func run(_ peer: DirectApprovalPeer, _ channel: NegotiatedNetworkChannel) async throws {
            let handler = lock.withLock { callback! }
            try await handler(peer, channel)
        }
    }
    private actor Phone: ApprovalByteStream {
        let owner: ChannelNegotiation
        let maximum: Int
        let failWrite: Bool
        let holdWrite: Bool
        let writing = XCTestExpectation(description: "write held")
        var writeReply: CheckedContinuation<Void, Error>?
        var input: [Data]
        var output = Data()
        var phase = 0
        var payloads: [Data] = []
        var closed = false
        init(scope: ChannelScope, requests: [ChannelRequestCapability], maximum: Int = 4096,
             failWrite: Bool = false, holdWrite: Bool = false) throws {
            self.maximum = maximum; self.failWrite = failWrite; self.holdWrite = holdWrite
            owner = try ChannelNegotiation(local: ChannelOffer(role: .phone, scope: scope, nonce: Data(repeating: 7, count: 32),
                envelopeVersions: [1], requests: requests, auditVersions: []), trustedMinimum: 1)
            input = [Self.frame(try owner.offer())]
        }
        func awaitOpen(timeoutMilliseconds: UInt64) async throws { }
        func receive() async throws -> Data? {
            guard !closed, !input.isEmpty else { throw ApprovalChannelError.closed }
            return input.removeFirst()
        }
        func send(_ bytes: Data) async throws {
            guard !closed else { throw ApprovalChannelError.closed }
            if phase >= 2 {
                if failWrite { throw ApprovalChannelError.closed }
                if holdWrite {
                    writing.fulfill()
                    try await withCheckedThrowingContinuation { writeReply = $0 }
                    return
                }
            }
            output.append(bytes)
            guard output.count >= 4 else { return }
            let count = output.prefix(4).reduce(0) { ($0 << 8) | Int($1) }
            guard output.count == count + 4 else { return }
            let body = Data(output.dropFirst(4)); output.removeAll()
            switch phase {
            case 0: try owner.receiveOffer(body); input.append(Self.frame(try owner.confirmation()))
            case 1: try owner.receiveConfirmation(body)
            default:
                let envelope = try SessionEnvelope.decode(body, maximumPayloadBytes: maximum)
                XCTAssertEqual(envelope.sessionID, try owner.confirmed().sessionID)
                XCTAssertEqual(envelope.sequence, UInt64(payloads.count))
                payloads.append(envelope.payload)
            }
            phase += 1
        }
        func close() async {
            closed = true; owner.close()
            writeReply?.resume(throwing: ApprovalChannelError.closed); writeReply = nil
        }
        static func frame(_ body: Data) -> Data {
            let count = UInt32(body.count)
            return Data([UInt8(truncatingIfNeeded: count >> 24), UInt8(truncatingIfNeeded: count >> 16),
                UInt8(truncatingIfNeeded: count >> 8), UInt8(truncatingIfNeeded: count)]) + body
        }
    }
    private func setup(ids: [Data], frames: [Data: Data], maximum: Int = 4096, features: Set<UInt64> = [],
                       automatic: Bool = true,
                       handler: @escaping @Sendable (DirectApprovalSession, NegotiatedNetworkChannel) async throws -> Void = { _, _ in }) async throws -> (DirectApprovalTransportService, DirectApprovalTransportHost, Driver, Factory, DirectApprovalPeer) {
        let peer = try DirectApprovalPeer(scope: Self.scope(), transportPublicKey: P256.Signing.PrivateKey().publicKey.derRepresentation,
            requests: [Self.capability(features: features)], auditVersions: [], maximumPayloadBytes: maximum)
        let trust = DirectApprovalTrust(macID: Self.id(1), accountID: Self.id(2), revision: UUID(), peers: [peer])
        let driver = Driver(trust: trust, ids: ids, frames: frames), factory = Factory()
        let feed = AuthorityTrustFeed(macID: Self.id(1), accountID: Self.id(2), factory: { AuthorityXPCChannel(driver: driver, onClose: $0) })
        let host = DirectApprovalTransportHost(macID: Self.id(1), accountID: Self.id(2),
            factory: { generation, _, _, handler in factory.make(generation, handler) },
            validatePeer: { try await feed.validatePeer($0, revision: $1) }, handler: handler)
        let service = DirectApprovalTransportService(feed: feed, host: host, useDefaultDelivery: automatic)
        try await service.start()
        return (service, host, driver, factory, peer)
    }
    private func connect(_ phone: Phone, _ peer: DirectApprovalPeer) async throws -> NegotiatedNetworkChannel {
        try await NegotiatedNetworkChannel.accept(stream: phone, scope: peer.scope, requests: peer.requests, auditVersions: [],
            maximumPayloadBytes: peer.maximumPayloadBytes)
    }
    func testDefaultHandlerWritesExactSignedFramesAndSkipsAbsentRequests() async throws {
        let (first, key) = try Self.frame(8), second = try Self.frame(10).0
        let (service, _, driver, factory, peer) = try await setup(ids: [Self.id(8), Self.id(9), Self.id(10)],
            frames: [Self.id(8): first, Self.id(10): second])
        let phone = try Phone(scope: peer.scope, requests: peer.requests), channel = try await connect(phone, peer)
        try await factory.run(peer, channel)
        let payloads = await phone.payloads
        XCTAssertEqual(payloads, [first, second]); XCTAssertEqual(driver.discoveryCount, 1)
        XCTAssertEqual(driver.frameIDs, [Self.id(8), Self.id(9), Self.id(10)])
        let message = try ApprovalMessage.decode(payloads[0], maximumBodyBytes: 3968)
        let limits = try CBORLimits(maxBytes: 4096, maxDepth: 12, maxItems: 256)
        XCTAssertTrue(try ApprovalSignature.verify(signature: message.signature, publicKey: key.x963Representation,
            wireVersion: 1, messageType: .request, purpose: .issuedRequest, canonicalPayload: message.body,
            payloadLimits: limits, inputLimits: limits))
        await channel.closeAndWait(); await service.close()
    }
    func testReservedBodyBudgetFitsPeerPayloadLimit() async throws {
        let maximum = 1024, bodyMaximum = maximum - ApprovalMessage.overheadBytes
        let frame = try Self.frame(8, bodyBytes: bodyMaximum).0
        let message = try ApprovalMessage.decode(frame, maximumBodyBytes: bodyMaximum)
        XCTAssertEqual(message.body.count, bodyMaximum); XCTAssertLessThanOrEqual(frame.count, maximum)
        let (service, _, _, factory, peer) = try await setup(ids: [Self.id(8)], frames: [Self.id(8): frame], maximum: maximum)
        let phone = try Phone(scope: peer.scope, requests: peer.requests, maximum: maximum), channel = try await connect(phone, peer)
        try await factory.run(peer, channel)
        let payloads = await phone.payloads
        XCTAssertEqual(payloads, [frame])
        await channel.closeAndWait(); await service.close()
    }
    func testWrongScopeAndNoCommonContractCloseBeforeDiscovery() async throws {
        for wrongScope in [false, true] {
            let (service, _, driver, factory, peer) = try await setup(ids: [Self.id(8)], frames: [:])
            let phoneScope = try Self.scope(phone: wrongScope ? 5 : 3)
            let phone = try Phone(scope: phoneScope, requests: wrongScope ? peer.requests : [])
            let channel = try await NegotiatedNetworkChannel.accept(stream: phone, scope: phoneScope, requests: peer.requests,
                auditVersions: [], maximumPayloadBytes: 4096)
            do { try await factory.run(peer, channel); XCTFail("Unbound channel delivered") } catch { }
            let closed = await phone.closed, payloads = await phone.payloads
            XCTAssertTrue(closed); XCTAssertTrue(payloads.isEmpty); XCTAssertEqual(driver.discoveryCount, 0)
            await service.close()
        }
    }
    func testRuntimeFeaturesOmitUnsupportedFrame() async throws {
        let frame = try Self.frame(8, features: [1]).0
        let (service, _, driver, factory, peer) = try await setup(ids: [Self.id(8)], frames: [Self.id(8): frame], features: [1])
        let phone = try Phone(scope: peer.scope, requests: [Self.capability()]), channel = try await connect(phone, peer)
        try await factory.run(peer, channel)
        let payloads = await phone.payloads
        XCTAssertTrue(payloads.isEmpty); XCTAssertEqual(driver.frameIDs, [Self.id(8)])
        await channel.closeAndWait(); await service.close()
    }
    func testRetiredOrClosedSessionCannotWriteLateFrame() async throws {
        for closeService in [false, true] {
            let frame = try Self.frame(8).0
            let (service, host, driver, factory, peer) = try await setup(ids: [Self.id(8)], frames: [:])
            driver.holdFrame()
            let phone = try Phone(scope: peer.scope, requests: peer.requests), channel = try await connect(phone, peer)
            let delivery = Task { try await factory.run(peer, channel) }
            await fulfillment(of: [driver.requested], timeout: 2)
            if closeService { await service.close() }
            else { try await host.replaceTrust(driver.trust) }
            driver.finishFrame(frame)
            do { try await delivery.value; XCTFail("Retired session wrote") } catch { }
            let payloads = await phone.payloads, closed = await phone.closed
            XCTAssertTrue(payloads.isEmpty); XCTAssertTrue(closed)
            await service.close()
        }
    }
    func testFailedWriteDoesNotFetchAnotherFrame() async throws {
        let first = try Self.frame(8).0, second = try Self.frame(9).0
        let (service, _, driver, factory, peer) = try await setup(ids: [Self.id(8), Self.id(9)],
            frames: [Self.id(8): first, Self.id(9): second])
        let phone = try Phone(scope: peer.scope, requests: peer.requests, failWrite: true), channel = try await connect(phone, peer)
        do { try await factory.run(peer, channel); XCTFail("Failed write succeeded") } catch { }
        XCTAssertEqual(driver.frameIDs, [Self.id(8)])
        let closed = await phone.closed; XCTAssertTrue(closed)
        await service.close()
    }
    func testDeadlineClosesBlockedWrite() async throws {
        let frame = try Self.frame(8).0
        let (service, host, driver, factory, peer) = try await setup(ids: [Self.id(8)], frames: [Self.id(8): frame])
        let session = try await host.admit(peer, generation: factory.generation)
        let phone = try Phone(scope: peer.scope, requests: peer.requests, holdWrite: true), channel = try await connect(phone, peer)
        do {
            try await service.deliverPendingRequests(for: session, over: channel, timeoutMilliseconds: 100)
            XCTFail("Blocked write exceeded deadline")
        } catch ApprovalChannelError.timedOut { }
        let closed = await phone.closed; XCTAssertTrue(closed)
        XCTAssertEqual(driver.frameIDs, [Self.id(8)])
        await service.close()
    }
    func testCancellationClosesBlockedWrite() async throws {
        let frame = try Self.frame(8).0
        let (service, _, _, factory, peer) = try await setup(ids: [Self.id(8)], frames: [Self.id(8): frame])
        let phone = try Phone(scope: peer.scope, requests: peer.requests, holdWrite: true), channel = try await connect(phone, peer)
        let delivery = Task { try await factory.run(peer, channel) }
        await fulfillment(of: [phone.writing], timeout: 2)
        delivery.cancel()
        do { try await delivery.value; XCTFail("Cancelled write succeeded") } catch { }
        let closed = await phone.closed; XCTAssertTrue(closed)
        await service.close()
    }
    func testPayloadLimitClosesBeforeFirstWrite() async throws {
        let frame = try Self.frame(8).0
        let (service, _, driver, factory, peer) = try await setup(ids: [Self.id(8)], frames: [Self.id(8): frame], maximum: 128)
        let phone = try Phone(scope: peer.scope, requests: peer.requests, maximum: 128), channel = try await connect(phone, peer)
        do { try await factory.run(peer, channel); XCTFail("Oversized frame sent") } catch { }
        let payloads = await phone.payloads, closed = await phone.closed
        XCTAssertTrue(payloads.isEmpty); XCTAssertTrue(closed); XCTAssertEqual(driver.frameIDs, [Self.id(8)])
        await service.close()
    }
    func testCustomHandlerRemainsInControl() async throws {
        let expected = Data([42])
        let (service, _, driver, factory, peer) = try await setup(ids: [Self.id(8)], frames: [:], automatic: false,
            handler: { _, channel in try await channel.send(expected) })
        let phone = try Phone(scope: peer.scope, requests: peer.requests), channel = try await connect(phone, peer)
        try await factory.run(peer, channel)
        let payloads = await phone.payloads
        XCTAssertEqual(payloads, [expected]); XCTAssertEqual(driver.discoveryCount, 0)
        await channel.closeAndWait(); await service.close()
    }
    func testHandlerCannotChangeAfterHostStarts() async throws {
        let (service, host, _, _, _) = try await setup(ids: [], frames: [:])
        do { try await host.configureHandler { _, _ in }; XCTFail("Live handler replaced") } catch { }
        await service.close()
    }
}
