import Foundation
import XCTest
import RemozioProtocol
@testable import RemozioCore

final class NegotiatedNetworkChannelTests: XCTestCase, @unchecked Sendable {
    private func scope() throws -> ChannelScope {
        try ChannelScope(macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16),
            phoneID: Data(repeating: 3, count: 16), enrollmentEpoch: Data(repeating: 4, count: 16))
    }
    private actor Phone: ApprovalByteStream {
        let owner: ChannelNegotiation
        let fragment: Int
        let replay: Bool
        let wrongSession: Bool
        var input: [Data] = []
        var output = Data()
        var phase = 0
        var closes = 0
        var received: Data?
        init(scope: ChannelScope, fragment: Int = 32_768, initial: Data? = nil, replay: Bool = false, wrongSession: Bool = false) throws {
            self.fragment = fragment; self.replay = replay; self.wrongSession = wrongSession
            let handshake = try ChannelNegotiation(local: ChannelOffer(role: .phone, scope: scope, nonce: Data(repeating: 9, count: 32),
                envelopeVersions: [1], requests: [], auditVersions: []), trustedMinimum: 1)
            let bytes = try initial ?? Self.frame(handshake.offer())
            owner = handshake
            input = stride(from: 0, to: bytes.count, by: fragment).map { Data(bytes[$0..<min($0 + fragment, bytes.count)]) }
        }
        func awaitOpen() async throws { }
        func receive() async throws -> Data? {
            if !input.isEmpty { return input.removeFirst() }
            try await Task.sleep(for: .seconds(60)); return nil
        }
        func send(_ bytes: Data) async throws {
            output.append(bytes)
            guard output.count >= 4 else { return }
            let count = output.prefix(4).reduce(0) { ($0 << 8) | Int($1) }
            guard output.count >= count + 4 else { return }
            guard output.count == count + 4 else { throw ApprovalChannelError.invalidInput }
            let body = Data(output.dropFirst(4)); output.removeAll()
            switch phase {
            case 0:
                try owner.receiveOffer(body)
                let confirmation = try owner.confirmation()
                guard case let .map(fields) = try DeterministicCBOR.decode(confirmation,
                    limits: CBORLimits(maxBytes: 128, maxDepth: 2, maxItems: 8)), case let .bytes(id) = fields[2] else {
                    throw ApprovalChannelError.invalidInput
                }
                let envelope = try Self.frame(SessionEnvelope(sessionID: wrongSession ? Data(repeating: 0, count: 32) : id,
                    sequence: 0, payload: Data([7, 8])).encode(maximumPayloadBytes: 64))
                let reply = Self.frame(confirmation) + envelope + (replay ? envelope : Data())
                input += stride(from: 0, to: reply.count, by: fragment).map { Data(reply[$0..<min($0 + fragment, reply.count)]) }
            case 1: try owner.receiveConfirmation(body)
            default:
                let envelope = try SessionEnvelope.decode(body, maximumPayloadBytes: 64)
                guard envelope.sessionID == (try owner.confirmed()).sessionID, envelope.sequence == 0 else { throw ApprovalChannelError.invalidInput }
                received = envelope.payload
            }
            phase += 1
        }
        func close() async { closes += 1; owner.close() }
        static func frame(_ bytes: Data) -> Data {
            let n = UInt32(bytes.count)
            return Data([UInt8(truncatingIfNeeded: n >> 24), UInt8(truncatingIfNeeded: n >> 16),
                UInt8(truncatingIfNeeded: n >> 8), UInt8(truncatingIfNeeded: n)]) + bytes
        }
    }
    private func connect(_ phone: Phone, timeout: UInt64 = 1000) async throws -> NegotiatedNetworkChannel {
        try await NegotiatedNetworkChannel.accept(stream: phone, scope: scope(), requests: [], auditVersions: [],
            maximumPayloadBytes: 64, timeoutMilliseconds: timeout)
    }
    func testCoalescedAndFragmentedFramesSurviveNegotiation() async throws {
        for fragment in [1, 32_768] {
            let phone = try Phone(scope: scope(), fragment: fragment)
            let channel = try await connect(phone)
            let metadata = try await channel.negotiated(); XCTAssertEqual(metadata.envelopeVersion, 1)
            let payload = try await channel.receive(); XCTAssertEqual(payload, Data([7, 8]))
            try await channel.send(Data([1, 2, 3]))
            let received = await phone.received; XCTAssertEqual(received, Data([1, 2, 3]))
            await channel.closeAndWait()
            do { _ = try await channel.negotiated(); XCTFail("Closed metadata must fail") } catch { }
        }
    }
    func testWrongSessionAndReplayCloseTheOwner() async throws {
        for replay in [false, true] {
            let phone = try Phone(scope: scope(), replay: replay, wrongSession: !replay)
            let channel = try await connect(phone)
            if replay { _ = try await channel.receive() }
            do { _ = try await channel.receive(); XCTFail("Invalid envelope accepted") } catch { }
            let closes = await phone.closes; XCTAssertGreaterThan(closes, 0)
        }
    }
    func testOversizedOrZeroHeaderDoesNotWaitForABody() async throws {
        for header in [Data([0, 0, 0, 0]), Data([0, 1, 0, 1]), Data([255, 255, 255, 255])] {
            let phone = try Phone(scope: scope(), initial: header)
            do { _ = try await connect(phone); XCTFail("Invalid header accepted") }
            catch ApprovalChannelError.timedOut { XCTFail("Waited for an invalid body") }
            catch { }
            let closes = await phone.closes; XCTAssertGreaterThan(closes, 0)
        }
    }
    func testWholeHandshakeDeadlineCancelsPendingInput() async throws {
        let phone = try Phone(scope: scope(), initial: Data([0, 0]))
        do { _ = try await connect(phone, timeout: 10); XCTFail("Deadline ignored") }
        catch ApprovalChannelError.timedOut { }
        let closes = await phone.closes; XCTAssertGreaterThan(closes, 0)
    }
    func testCancelledNegotiationClosesTransferredStream() async throws {
        let phone = try Phone(scope: scope(), initial: Data())
        let task = Task { try await connect(phone) }; task.cancel()
        do { _ = try await task.value; XCTFail("Cancellation ignored") } catch { }
        let closes = await phone.closes; XCTAssertGreaterThan(closes, 0)
    }
    func testInvalidConfigurationClosesTransferredStream() async throws {
        let phone = try Phone(scope: scope())
        do {
            _ = try await NegotiatedNetworkChannel.accept(stream: phone, scope: scope(), requests: [], auditVersions: [], maximumPayloadBytes: 0)
            XCTFail("Invalid configuration accepted")
        } catch { }
        let closes = await phone.closes; XCTAssertGreaterThan(closes, 0)
    }
}
