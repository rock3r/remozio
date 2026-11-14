import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class SetupRetainedInvocationTests: XCTestCase {
    private enum Failure: Error { case rights, work, reply, cleanup }
    private typealias Invocation = SetupRetainedInvocation
    private typealias Fixture = RetainedMaterialWriterFixture
    private func values(_ f: Fixture) throws -> (SetupRetainedCallerBinding, XPCPeerPolicy) {
        let machine = try f.machine(), state = try machine.retainedSetupCallerState(candidate: f.candidate)
        let entry = try machine.retainedSetupInitialRuntimeEntry(owner: f.owner, candidate: f.candidate)
        let member = try XCTUnwrap(state.source.actual.inventory.accounts.first)
        let (_, host) = try MachineUpdateRetainedSetupPolicyNativeEntry.publishedAuthority(runtime: entry.runtime, accountID: member.accountID)
        let app = try XCTUnwrap(host.codePolicy.entries.first { $0.role == .app && $0.active })
        let peer = XPCPeerCredentials(processID: getpid(), userID: member.ownerUID, auditSessionID: 1)
        let policy = try XPCPeerPolicy(teamID: app.teamID, componentIdentifier: app.identifier,
            approvedCodeDirectoryHashes: [app.codeDirectoryHash], expectedUserID: peer.userID)
        let binding = try SetupRetainedCallerBinding.resolve(state: state, peer: peer, incarnation: UUID(),
            accepted: policy, entry: entry, lookup: { uid in
                let account = try XCTUnwrap(state.source.preparations.first { $0.ownerUID == uid })
                return .init(uid: uid, primaryGroupID: getgid(), directoryID: account.directoryID)
            })
        return (binding, policy)
    }
    private func owner(_ f: Fixture, activity: ReleaseActivityBarrier? = nil) throws -> SetupAccountOwner {
        try .init(machine: f.machine(), expectedReleaseDigest: InstallationInventory.digest(f.candidate),
            resume: { _, value in value }, releaseActivity: activity)
    }
    func testReservationAndSharedActivitySurviveWorkAndReplyUntilClose() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let activity = try ReleaseActivityFixture(), barrier = try activity.open(), installer = try activity.open()
            let owner = try owner(f, activity: barrier); defer { try? owner.close() }
            let (binding, policy) = try values(f)
            var checks = 0, closes = 0, replies = 0
            let invocation = try Invocation.openOwned(owner: owner, binding: binding, policy: policy,
                verifyRights: { checks += 1 }, closeRights: { closes += 1 })
            XCTAssertEqual(invocation.incarnation, binding.incarnation)
            XCTAssertEqual(invocation.acceptedPolicy.requirement, policy.requirement)
            XCTAssertEqual(invocation.peer, binding.peer)
            XCTAssertThrowsError(try owner.verifyCurrent()); XCTAssertThrowsError(try owner.acquireSetupReplyAdmission())
            XCTAssertThrowsError(try installer.acquireExclusive())
            try invocation.run(work: {
                XCTAssertThrowsError(try invocation.run(work: {}, reply: { _, _ in XCTFail("Reentry") }))
                XCTAssertThrowsError(try invocation.close())
                return 17
            }, reply: { value, state in
                XCTAssertEqual(value, 17); XCTAssertEqual(state, .init(cancelled: false, expired: false)); replies += 1
                XCTAssertThrowsError(try invocation.close()); XCTAssertThrowsError(try owner.acquireSetupReplyAdmission())
                XCTAssertThrowsError(try installer.acquireExclusive())
            })
            XCTAssertEqual(replies, 1); XCTAssertGreaterThan(checks, 2); XCTAssertEqual(closes, 0)
            XCTAssertThrowsError(try invocation.run(work: {}, reply: { _, _ in XCTFail("Replay") }))
            XCTAssertThrowsError(try owner.verifyCurrent()); XCTAssertThrowsError(try installer.acquireExclusive())
            try invocation.close(); try invocation.close(); XCTAssertEqual(closes, 1)
            let update = try installer.acquireExclusive(); update.close()
            let reply = try owner.acquireSetupReplyAdmission(); reply.close(); try owner.verifyCurrent()
            XCTAssertThrowsError(try invocation.validateLifetime())
        }
    }
    func testExpiryAndConnectionCancellationStopStagesWithoutReleasingAdmission() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let owner = try owner(f); defer { try? owner.close() }; let (binding, policy) = try values(f)
            var valid = true, closes = 0
            let expired = try Invocation.openOwned(owner: owner, binding: binding, policy: policy,
                verifyRights: { if !valid { throw Failure.rights } }, closeRights: { closes += 1 })
            valid = false
            XCTAssertThrowsError(try expired.run(work: { XCTFail("Expired work") }, reply: { _, _ in XCTFail("Expired reply") }))
            XCTAssertThrowsError(try owner.verifyCurrent()); try expired.close(); XCTAssertEqual(closes, 1)
            let cancelled = try Invocation.openOwned(owner: owner, binding: binding, policy: policy, verifyRights: {})
            cancelled.cancel(incarnation: UUID()); try cancelled.validateLifetime()
            var replies = 0
            try cancelled.run(work: {
                cancelled.cancel(incarnation: binding.incarnation); return "committed"
            }, reply: { value, state in
                XCTAssertEqual(value, "committed"); XCTAssertEqual(state, .init(cancelled: true, expired: false)); replies += 1
            })
            XCTAssertEqual(replies, 1)
            XCTAssertThrowsError(try cancelled.run(work: {}, reply: { _, _ in XCTFail("Cancelled replay") }))
            XCTAssertThrowsError(try owner.acquireSetupReplyAdmission()); try cancelled.close(); try owner.verifyCurrent()
        }
    }
    func testConstructionFailureDoesNotStealAnotherReservationOrLeakRights() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let owner = try owner(f); defer { try? owner.close() }; let (binding, policy) = try values(f)
            var closes = 0
            XCTAssertThrowsError(try Invocation.openOwned(owner: owner, binding: binding, policy: policy,
                verifyRights: { throw Failure.rights }, closeRights: { closes += 1 }))
            XCTAssertEqual(closes, 1); try owner.verifyCurrent()
            let first = try Invocation.openOwned(owner: owner, binding: binding, policy: policy, verifyRights: {})
            XCTAssertThrowsError(try Invocation.openOwned(owner: owner, binding: binding, policy: policy,
                verifyRights: {}, closeRights: { closes += 1 }))
            XCTAssertEqual(closes, 2); try first.validateLifetime(); try first.close(); try owner.verifyCurrent()
            var checks = 0
            XCTAssertThrowsError(try Invocation.openOwned(owner: owner, binding: binding, policy: policy,
                verifyRights: { checks += 1; if checks == 2 { throw Failure.rights } }, closeRights: { closes += 1 }))
            XCTAssertEqual(closes, 3); try owner.verifyCurrent()
        }
    }
    func testWorkReplyAndCleanupFailuresKeepOwnershipUntilExplicitSettlement() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let owner = try owner(f); defer { try? owner.close() }; let (binding, policy) = try values(f)
            for failReply in [false, true] {
                var closes = 0
                let invocation = try Invocation.openOwned(owner: owner, binding: binding, policy: policy,
                    verifyRights: {}, closeRights: { closes += 1 })
                XCTAssertThrowsError(try invocation.run(work: {
                    if !failReply { throw Failure.work }; return 1
                }, reply: { _, _ in throw Failure.reply }))
                func cleanup(_ fail: Bool) throws { if fail { throw Failure.cleanup }; try invocation.close() }
                XCTAssertThrowsError(try cleanup(true)); XCTAssertEqual(closes, 0)
                XCTAssertThrowsError(try owner.verifyCurrent()); XCTAssertThrowsError(try owner.acquireSetupReplyAdmission())
                XCTAssertThrowsError(try invocation.run(work: {}, reply: { _, _ in XCTFail("Failed work replay") }))
                try cleanup(false); XCTAssertEqual(closes, 1); try owner.verifyCurrent()
            }
            let shutdown = try Invocation.openOwned(owner: owner, binding: binding, policy: policy, verifyRights: {})
            XCTAssertThrowsError(try owner.close()); XCTAssertThrowsError(try shutdown.validateLifetime())
            try shutdown.close(); try owner.close()
        }
    }
    func testNativeFactoryRefusesOrdinaryIdentityAndExplicitCloseReleasesOnce() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let owner = try owner(f); defer { try? owner.close() }; let (binding, policy) = try values(f)
            let connection = NSXPCConnection(machServiceName: AdministrativeSetupConfiguration.serviceName)
            defer { connection.invalidate() }; let guardValue = XPCInvocationGuard(connection: connection, policy: policy)
            XCTAssertThrowsError(try Invocation.open(owner: owner, invocation: guardValue, externalForm: Data())) {
                XCTAssertEqual($0 as? SetupAdministratorAuthorizationError, .wrongProcess)
            }
            var closes = 0
            do {
                let value = try Invocation.openOwned(owner: owner, binding: binding, policy: policy,
                    verifyRights: {}, closeRights: { closes += 1 })
                XCTAssertThrowsError(try value.callerBinding(invocation: guardValue, candidate: f.candidate)) {
                    if case XPCPeerPolicyError.wrongConnection = $0 {} else { XCTFail("Unexpected failure: \($0)") }
                }
                XCTAssertThrowsError(try owner.verifyCurrent())
                XCTAssertEqual(value.description, "SetupRetainedInvocation(redacted)")
                XCTAssertTrue(value.customMirror.children.isEmpty)
                try value.close(); try value.close(); XCTAssertEqual(closes, 1)
            }
            XCTAssertEqual(closes, 1); try owner.verifyCurrent()
        }
    }
    func testLostInvocationClosesRightsButKeepsAdmissionsAndSharedActivity() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let activity = try ReleaseActivityFixture(), installer = try activity.open()
            var setup: SetupAccountOwner? = try owner(f, activity: activity.open())
            let (binding, policy) = try values(f); var closes = 0
            var dropped: Invocation? = try Invocation.openOwned(owner: XCTUnwrap(setup), binding: binding, policy: policy,
                verifyRights: {}, closeRights: { closes += 1 })
            weak var weakInvocation = dropped; weak var weakOwner = setup
            XCTAssertNotNil(weakInvocation); dropped = nil
            XCTAssertNil(weakInvocation); XCTAssertEqual(closes, 1)
            XCTAssertThrowsError(try XCTUnwrap(setup).verifyCurrent())
            XCTAssertThrowsError(try XCTUnwrap(setup).acquireSetupReplyAdmission())
            XCTAssertThrowsError(try installer.acquireExclusive())
            XCTAssertThrowsError(try Invocation.openOwned(owner: XCTUnwrap(setup), binding: binding, policy: policy,
                verifyRights: {}, closeRights: { closes += 1 }))
            XCTAssertEqual(closes, 2); XCTAssertThrowsError(try XCTUnwrap(setup).close())
            setup = nil; XCTAssertNil(weakOwner)
            let released = try installer.acquireExclusive(); released.close()
        }
    }
    func testLateRightsChangesPreserveTheValueAndNeverPermitReplay() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let owner = try owner(f); defer { try? owner.close() }; let (binding, policy) = try values(f)
            let changesToCheck: [(cancelled: Bool, expired: Bool)] = [(false, true), (true, true), (false, false)]
            for changes in changesToCheck {
                var valid = true, replies = 0, works = 0
                let invocation = try Invocation.openOwned(owner: owner, binding: binding, policy: policy,
                    verifyRights: { if !valid { throw Failure.rights } })
                try invocation.run(work: {
                    works += 1
                    if changes.cancelled { invocation.cancel(incarnation: binding.incarnation) }
                    valid = !changes.expired
                    return "committed"
                }, reply: { value, state in
                    XCTAssertEqual(value, "committed")
                    XCTAssertEqual(state, .init(cancelled: changes.cancelled, expired: changes.expired)); replies += 1
                    XCTAssertThrowsError(try invocation.close())
                    XCTAssertThrowsError(try owner.acquireSetupReplyAdmission())
                })
                XCTAssertEqual(works, 1); XCTAssertEqual(replies, 1)
                XCTAssertThrowsError(try invocation.run(work: { works += 1 }, reply: { _, _ in XCTFail("Replay") }))
                XCTAssertEqual(works, 1); try invocation.close(); try owner.verifyCurrent()
            }
            let shutdown = try Invocation.openOwned(owner: owner, binding: binding, policy: policy, verifyRights: {})
            var replies = 0
            try shutdown.run(work: { XCTAssertThrowsError(try owner.close()); return "committed" }, reply: { value, state in
                XCTAssertEqual(value, "committed"); XCTAssertEqual(state, .init(cancelled: false, expired: false)); replies += 1
            })
            XCTAssertEqual(replies, 1); try shutdown.close(); try owner.close()
        }
    }
}
