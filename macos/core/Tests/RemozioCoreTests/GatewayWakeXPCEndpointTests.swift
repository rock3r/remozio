import CryptoKit
import Foundation
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

final class GatewayWakeXPCEndpointTests: XCTestCase, @unchecked Sendable {
    private final class State: Sendable {
        struct Value { var verified = 0; var closed = 0; var handled = 0; var allowed = true; var now: UInt64 = 100 }
        let value = Mutex(Value())
    }
    private func endpoint(_ state: State, budget: AuthorityXPCWorkBudget? = nil,
                          execute: (@Sendable (GatewayWakeSubmission, Data, GatewayWakeChallenge) async throws -> Void)? = nil) throws -> GatewayWakeXPCEndpoint {
        try GatewayWakeXPCEndpoint(verify: {
            try state.value.withLock { value in
                value.verified += 1
                guard value.allowed else { throw GatewayServiceError.wrongAccount }
            }
        }, budget: budget ?? AuthorityXPCWorkBudget(maximum: 1), sample: { state.value.withLock { $0.now } },
            challengeLifetimeMillis: 100, invalidate: { state.value.withLock { $0.closed += 1 } },
            execute: execute ?? { _, _, _ in state.value.withLock { $0.handled += 1 } })
    }
    private func message(_ challenge: Data) throws -> Data {
        let id = Data(repeating: 1, count: 16)
        return try GatewayWakeSubmission(binding: GatewaySubmissionBinding(ownerID: id, macID: id, accountID: id,
            gatewayID: id, lifecycleEpoch: id), credentialID: id, deliveryID: id, challenge: challenge).encode()
    }
    private func challenge(_ endpoint: GatewayWakeXPCEndpoint) throws -> Data {
        let value = Mutex<Data?>(nil)
        endpoint.challenge { result in value.withLock { $0 = result } }
        return try XCTUnwrap(value.withLock { $0 })
    }
    func testRequiresHandshakeAndRechecksPeerBeforeEveryInvocation() throws {
        let first = State(), before = try endpoint(first)
        before.challenge { XCTAssertNil($0) }
        XCTAssertEqual(first.value.withLock { $0.handled }, 0)
        XCTAssertEqual(first.value.withLock { $0.closed }, 1)
        let state = State(), endpoint = try endpoint(state)
        endpoint.hello { XCTAssertEqual($0, 1) }
        let nonce = try challenge(endpoint)
        state.value.withLock { $0.allowed = false }
        endpoint.wake(try message(nonce), signature: Data(repeating: 1, count: 64)) { XCTAssertFalse($0) }
        XCTAssertEqual(state.value.withLock { $0.verified }, 3)
        XCTAssertEqual(state.value.withLock { $0.handled }, 0)
    }
    func testChallengeIsRandomConnectionBoundAndSingleUse() async throws {
        let state = State(), endpoint = try endpoint(state), other = try self.endpoint(State())
        endpoint.hello { XCTAssertEqual($0, 1) }; other.hello { XCTAssertEqual($0, 1) }
        let first = try challenge(endpoint), nonce = try challenge(endpoint), crossed = try challenge(other)
        XCTAssertEqual(nonce.count, 32); XCTAssertNotEqual(first, nonce); XCTAssertNotEqual(nonce, crossed)
        let done = expectation(description: "accepted")
        let payload = try message(nonce), signature = Data(repeating: 1, count: 64)
        endpoint.wake(payload, signature: signature) { XCTAssertTrue($0); done.fulfill() }
        await fulfillment(of: [done], timeout: 2)
        endpoint.wake(payload, signature: signature) { XCTAssertFalse($0) }
        other.wake(payload, signature: signature) { XCTAssertFalse($0) }
        XCTAssertEqual(state.value.withLock { $0.handled }, 1)
        endpoint.close(); other.close()
    }
    func testExpiredRegressedSupersededAndMalformedChallengesRejectBeforeWorkBudget() throws {
        for mode in 0...4 {
            let state = State(), budget = try AuthorityXPCWorkBudget(maximum: 1), endpoint = try endpoint(state, budget: budget)
            endpoint.hello { XCTAssertEqual($0, 1) }
            let nonce = try challenge(endpoint)
            var payload = try message(nonce), signature = Data(repeating: 1, count: 64)
            switch mode {
            case 0: state.value.withLock { $0.now = 200 }
            case 1: state.value.withLock { $0.now = 99 }
            case 2: _ = try challenge(endpoint)
            case 3: payload = Data(repeating: 0, count: 513)
            default: signature.removeLast()
            }
            endpoint.wake(payload, signature: signature) { XCTAssertFalse($0) }
            XCTAssertEqual(state.value.withLock { $0.handled }, 0)
            XCTAssertTrue(budget.acquire()); budget.release()
        }
    }
    private actor Gate {
        private var continuation: CheckedContinuation<Void, Never>?
        func run(started: XCTestExpectation) async {
            await withCheckedContinuation { continuation in self.continuation = continuation; started.fulfill() }
        }
        func release() { continuation?.resume(); continuation = nil }
    }
    func testConnectionLossCancelsWorkSuppressesLateReplyAndReleasesBudget() async throws {
        let state = State(), budget = try AuthorityXPCWorkBudget(maximum: 1), gate = Gate()
        let started = expectation(description: "started"), late = expectation(description: "late response")
        late.isInverted = true
        let endpoint = try endpoint(state, budget: budget, execute: { _, _, _ in await gate.run(started: started) })
        endpoint.hello { XCTAssertEqual($0, 1) }
        let nonce = try challenge(endpoint)
        endpoint.wake(try message(nonce), signature: Data(repeating: 1, count: 64)) { _ in late.fulfill() }
        await fulfillment(of: [started], timeout: 2)
        XCTAssertFalse(budget.acquire())
        endpoint.close(); endpoint.close(); await gate.release()
        await fulfillment(of: [late], timeout: 0.1)
        XCTAssertTrue(budget.acquire()); budget.release()
        XCTAssertEqual(state.value.withLock { $0.closed }, 1)
    }
}
