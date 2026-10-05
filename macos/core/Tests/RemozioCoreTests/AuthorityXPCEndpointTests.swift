import CryptoKit
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class AuthorityXPCEndpointTests: XCTestCase {
    private final class Counter: @unchecked Sendable {
        private let lock = NSLock()
        private var count = 0
        func increment() { lock.withLock { count += 1 } }
        var value: Int { lock.withLock { count } }
    }
    private let mac = Data(repeating: 1, count: 16)
    private let account = Data(repeating: 2, count: 16)
    private func trust() -> DirectApprovalTrust { DirectApprovalTrust(macID: mac, accountID: account, revision: UUID(), peers: []) }
    private func binding() throws -> Data {
        let peer = try DirectApprovalPeer(scope: ChannelScope(macID: mac, accountID: account, phoneID: Data(repeating: 3, count: 16), enrollmentEpoch: Data(repeating: 4, count: 16)),
            transportPublicKey: P256.Signing.PrivateKey().publicKey.derRepresentation, requests: [], auditVersions: [], maximumPayloadBytes: 1024)
        return try AuthorityTrustCodec.encodeBinding(AuthorityPeerBinding(peer: peer, revision: UUID()))
    }
    func testHandshakeAndEveryOperationVerifyBeforeHandler() throws {
        let checks = Counter(), reads = Counter(), validations = Counter(), closures = Counter(), trust = trust()
        let endpoint = try AuthorityXPCEndpoint(macID: mac, accountID: account, budget: AuthorityXPCWorkBudget(),
            verify: { checks.increment() }, invalidate: { closures.increment() },
            snapshot: { reads.increment(); return trust }, validate: { _ in validations.increment(); return false })
        endpoint.hello { XCTAssertEqual($0, 1) }
        endpoint.trustSnapshot { XCTAssertNotNil($0) }
        endpoint.validatePeer(try binding()) { XCTAssertFalse($0) }
        endpoint.trustSnapshot { XCTAssertNotNil($0) }
        XCTAssertEqual(checks.value, 4); XCTAssertEqual(reads.value, 2); XCTAssertEqual(validations.value, 1)
        XCTAssertEqual(closures.value, 0)
        endpoint.close(); endpoint.close(); XCTAssertEqual(closures.value, 1)
    }
    func testReplyCanImmediatelyStartNextOperationAtCapacityOne() throws {
        let reads = Counter(), validations = Counter(), closures = Counter(), replies = Counter(), trust = trust()
        let bytes = try binding()
        let endpoint = try AuthorityXPCEndpoint(macID: mac, accountID: account, budget: AuthorityXPCWorkBudget(maximum: 1),
            verify: {}, invalidate: { closures.increment() }, snapshot: { reads.increment(); return trust },
            validate: { _ in validations.increment(); return true })
        endpoint.hello { XCTAssertEqual($0, 1) }
        endpoint.trustSnapshot { snapshot in
            XCTAssertNotNil(snapshot); replies.increment()
            endpoint.validatePeer(bytes) { allowed in
                XCTAssertTrue(allowed); replies.increment()
                endpoint.trustSnapshot { next in XCTAssertNotNil(next); replies.increment() }
            }
        }
        XCTAssertEqual(reads.value, 2); XCTAssertEqual(validations.value, 1)
        XCTAssertEqual(replies.value, 3); XCTAssertEqual(closures.value, 0)
    }
    func testHandshakeNotifiesOwnerOnceBeforeReply() throws {
        let handshakes = Counter(), trust = trust()
        let endpoint = try AuthorityXPCEndpoint(macID: mac, accountID: account, budget: AuthorityXPCWorkBudget(),
            verify: {}, invalidate: {}, onHandshake: { handshakes.increment() }, snapshot: { trust }, validate: { _ in false })
        endpoint.hello { XCTAssertEqual($0, 1); XCTAssertEqual(handshakes.value, 1) }
        endpoint.hello { XCTAssertEqual($0, 0) }
        XCTAssertEqual(handshakes.value, 1)
    }
    func testMissingHandshakeAndFailedIdentityNeverReadJournal() throws {
        for failedIdentity in [false, true] {
            let reads = Counter(), closures = Counter(), trust = trust()
            let endpoint = try AuthorityXPCEndpoint(macID: mac, accountID: account, budget: AuthorityXPCWorkBudget(),
                verify: { if failedIdentity { throw XPCPeerPolicyError.wrongPeer } }, invalidate: { closures.increment() },
                snapshot: { reads.increment(); return trust }, validate: { _ in reads.increment(); return true })
            if failedIdentity { endpoint.hello { XCTAssertEqual($0, 0) } }
            endpoint.trustSnapshot { XCTAssertNil($0) }
            endpoint.validatePeer(try binding()) { XCTAssertFalse($0) }
            XCTAssertEqual(reads.value, 0); XCTAssertEqual(closures.value, 1)
        }
    }
    func testChangedIdentityAfterHelloPreventsJournalAccess() throws {
        let checks = Counter(), reads = Counter(), trust = trust()
        let endpoint = try AuthorityXPCEndpoint(macID: mac, accountID: account, budget: AuthorityXPCWorkBudget(),
            verify: { checks.increment(); if checks.value > 1 { throw XPCPeerPolicyError.wrongPeer } }, invalidate: {},
            snapshot: { reads.increment(); return trust }, validate: { _ in reads.increment(); return true })
        endpoint.hello { XCTAssertEqual($0, 1) }
        endpoint.trustSnapshot { XCTAssertNil($0) }
        XCTAssertEqual(reads.value, 0)
    }
    func testMalformedBindingAndWrongSnapshotScopeCloseConnection() throws {
        let calls = Counter(), closures = Counter(), wrong = DirectApprovalTrust(macID: account, accountID: account, revision: UUID(), peers: [])
        let endpoint = try AuthorityXPCEndpoint(macID: mac, accountID: account, budget: AuthorityXPCWorkBudget(), verify: {},
            invalidate: { closures.increment() }, snapshot: { wrong }, validate: { _ in calls.increment(); return true })
        endpoint.hello { XCTAssertEqual($0, 1) }
        endpoint.validatePeer(Data(count: AuthorityXPCChannel.maximumBindingBytes + 1)) { XCTAssertFalse($0) }
        XCTAssertEqual(calls.value, 0); XCTAssertEqual(closures.value, 1)
        let other = try AuthorityXPCEndpoint(macID: mac, accountID: account, budget: AuthorityXPCWorkBudget(), verify: {},
            invalidate: { closures.increment() }, snapshot: { wrong }, validate: { _ in true })
        other.hello { XCTAssertEqual($0, 1) }; other.trustSnapshot { XCTAssertNil($0) }
        XCTAssertEqual(closures.value, 2)
    }
    func testBudgetRejectsWithoutQueuingAndReleasesAfterFailure() throws {
        let budget = try AuthorityXPCWorkBudget(maximum: 1), calls = Counter(), trust = trust()
        XCTAssertThrowsError(try AuthorityXPCWorkBudget(maximum: 0))
        let denied = AuthorityXPCEndpoint(macID: mac, accountID: account, budget: budget, verify: {}, invalidate: {},
            snapshot: { calls.increment(); return trust }, validate: { _ in true })
        denied.hello { XCTAssertEqual($0, 1) }
        XCTAssertTrue(budget.acquire())
        denied.trustSnapshot { XCTAssertNil($0) }
        XCTAssertEqual(calls.value, 0); budget.release()
        let failed = AuthorityXPCEndpoint(macID: mac, accountID: account, budget: budget, verify: {}, invalidate: {},
            snapshot: { throw AuthorityXPCEndpointError.unavailable }, validate: { _ in true })
        failed.hello { XCTAssertEqual($0, 1) }; failed.trustSnapshot { XCTAssertNil($0) }
        XCTAssertTrue(budget.acquire()); budget.release()
    }
    func testPolicyReadsUseBudgetForHandshakeAndOperationsAndReleaseItOnFailure() throws {
        let budget = try AuthorityXPCWorkBudget(maximum: 1), reads = Counter(), handlers = Counter(), trust = trust()
        XCTAssertTrue(budget.acquire())
        let denied = AuthorityXPCEndpoint(macID: mac, accountID: account, budget: budget, verify: {},
            verifyHandshakePolicy: { reads.increment() }, invalidate: {}, snapshot: { handlers.increment(); return trust }, validate: { _ in true })
        denied.hello { XCTAssertEqual($0, 0) }
        XCTAssertEqual(reads.value, 0)
        budget.release()
        let changed = AuthorityXPCEndpoint(macID: mac, accountID: account, budget: budget, verify: {},
            verifyHandshakePolicy: { reads.increment() }, invalidate: {},
            snapshot: { reads.increment(); throw AuthorityTransportAccessError.policyMismatch }, validate: { _ in true })
        changed.hello { XCTAssertEqual($0, 1) }
        XCTAssertEqual(reads.value, 1)
        changed.trustSnapshot { XCTAssertNil($0) }
        XCTAssertEqual(reads.value, 2)
        XCTAssertEqual(handlers.value, 0)
        XCTAssertTrue(budget.acquire()); budget.release()
        changed.hello { XCTAssertEqual($0, 0) }
        XCTAssertEqual(reads.value, 2)
    }

    func testCloseSuppressesLateSuccessfulReplyAndKeepsWorkSlotUntilReturn() throws {
        let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0), done = DispatchSemaphore(value: 0)
        let budget = try AuthorityXPCWorkBudget(maximum: 1), replies = Counter(), trust = trust()
        let endpoint = AuthorityXPCEndpoint(macID: mac, accountID: account, budget: budget, verify: {}, invalidate: {},
            snapshot: { entered.signal(); _ = release.wait(timeout: .now() + 5); return trust }, validate: { _ in true })
        endpoint.hello { XCTAssertEqual($0, 1) }
        DispatchQueue.global().async { endpoint.trustSnapshot { _ in replies.increment() }; done.signal() }
        XCTAssertEqual(entered.wait(timeout: .now() + 2), .success)
        endpoint.close(); XCTAssertFalse(budget.acquire())
        release.signal(); XCTAssertEqual(done.wait(timeout: .now() + 2), .success)
        XCTAssertEqual(replies.value, 0); XCTAssertTrue(budget.acquire()); budget.release()
    }
}
