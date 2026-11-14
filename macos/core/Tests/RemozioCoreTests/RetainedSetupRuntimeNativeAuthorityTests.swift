import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Owned pairs prove read-only scope and expiry. Installed Root code and native approval remain attended checks.
final class RetainedSetupRuntimeNativeAuthorityTests: XCTestCase {
    private typealias Native = MachineUpdateRetainedSetupRuntimeNativeAuthority
    private typealias Context = MachineUpdateRetainedSetupRuntimeNativeContext
    private typealias Entry = MachineUpdateRetainedSetupPolicyNativeEntry
    private typealias Support = MachineUpdateRetainedSetupPromotionNativeSupport
    private typealias Fixture = RetainedPolicyWriterFixture
    private enum Fault: Error { case injected }
    private func initial(_ f: Fixture, account: Data) throws -> AuthorityInitializationIntent {
        try XCTUnwrap(f.source.runtime.setup.source.accounts.first(where: { $0.accountID == account })?.initialization)
    }
    private func open(_ f: Fixture, initial: AuthorityInitializationIntent) throws -> sending AuthorityStorage {
        let journal = f.openJournalLease, continuity = f.openContinuityLease, account = initial.accountID
        return try Support.openExistingStorage(initial: initial, openJournalLease: { try journal(account) },
            openContinuityLease: { try continuity(account, $0) })
    }
    private func read(_ f: Fixture, initial: AuthorityInitializationIntent) throws -> Native.Boundary {
        let journal = try AuthorityJournal(updateHealthStorage: open(f, initial: initial), validateSelf: { _ in })
        defer { try? journal.close() }
        let pair = try journal.captureRetainedSetupPolicyBoundary(expected: initial)
        XCTAssertThrowsError(try journal.prepareRequests(clockEpoch: UUID(), maximumPayloadBytes: 1024)) {
            XCTAssertEqual($0 as? JournalDatabaseError, .readOnly)
        }
        try journal.close(); return pair
    }
    private func bytes(_ initial: AuthorityInitializationIntent) throws -> [Data] {
        try [initial.journalPath, initial.continuityPath].map { try Data(contentsOf: URL(fileURLWithPath: $0)) }
    }
    func testApprovalLoanExpiresOnNormalReturnAndThrow() throws {
        for bodyThrows in [false, true] {
            let expired = try Context.expiredApprovalForTesting(bodyThrows: bodyThrows)
            for _ in 0..<2 {
                XCTAssertThrowsError(try expired.verifyCode()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            }
        }
    }
    func testActualMissingMaterialCanSelectAuthorityButOrdinaryIdentityCannotEnterNativeScope() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let machine = try f.machine(), entry = try machine.retainedSetupInitialRuntimeEntry(owner: f.owner, candidate: f.candidate)
            XCTAssertNil(entry.runtime.state.reference)
            XCTAssertFalse(entry.runtime.state.configurationPublished)
            let inputs = try MachineUpdateRetainedSetupRuntimeInputs.capture(expected: entry.runtime, journal: nil,
                verifyCurrent: {}, readRelay: { _ in try .init(plan: nil, snapshot: nil) })
            let available = entry.runtime.setup.source.actual.inventory.accounts.compactMap { member in
                try? Entry.publishedAuthority(runtime: entry.runtime, accountID: member.accountID)
            }
            XCTAssertFalse(available.isEmpty)
            for (initial, host) in available {
                XCTAssertNotEqual(initial.accountID, entry.runtime.preparation.accountID)
                XCTAssertEqual(initial.accountID, host.command.accountID); XCTAssertTrue(initial.complete)
            }
            let current = try XCTUnwrap(available.first).0
            var reads = 0; machine.observeStoreRead = { _ in reads += 1 }; defer { machine.observeStoreRead = nil }
            XCTAssertNotEqual(getuid(), 0)
            XCTAssertThrowsError(try Native.withNativeScope(expected: (entry, inputs), candidate: f.candidate,
                currentAuthorityAccountID: current.accountID) { _, _ in XCTFail("An ordinary identity entered native scope") }) {
                XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
            }
            XCTAssertEqual(reads, 0)
        }
    }
    func testOwnedCurrentAuthorityPairPinsPolicyAndExpiresWithoutChangingEitherAccount() throws {
        try MachineUpdateReplacementTests.withRetainedPolicyWriterFixture { f in
            let runtime = f.source.runtime, account = f.currentAuthorityAccountID
            let snapshot = try f.machine().retainedSetupPolicySnapshot(owner: runtime.setup.owner, candidate: f.candidate)
            let (selected, host) = try Entry.publishedAuthority(runtime: runtime, accountID: account)
            let old = try Entry.publishedAuthority(expected: snapshot, accountID: account)
            XCTAssertEqual(selected, old.0); XCTAssertEqual(try host.canonicalBytes, try old.1.canonicalBytes)
            let target = try initial(f, account: runtime.preparation.accountID)
            let originalCurrent = try read(f, initial: selected), originalTarget = try read(f, initial: target)
            let currentBytes = try bytes(selected), targetBytes = try bytes(target)
            XCTAssertNotEqual(selected.accountID, target.accountID)
            for rejected in [target.accountID, Data(repeating: 221, count: 16)] {
                XCTAssertThrowsError(try Entry.publishedAuthority(runtime: runtime, accountID: rejected)) {
                    XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
                }
            }
            try MachineUpdateRetainedSetupPolicyNativeContext.requireRelease(f.candidate, approvedRuntime: runtime,
                candidate: f.candidate, currentCodePolicy: originalCurrent.policy.policy)
            var callback: Native.Verify?, checks = 0, opens = 0, failed = false
            func verify() throws { checks += 1; if failed { throw Fault.injected } }
            func storage() throws -> sending AuthorityStorage {
                XCTAssertGreaterThan(checks, 0); opens += 1
                let storage = try open(f, initial: selected)
                XCTAssertTrue(storage.journal.readOnlyForCutover); XCTAssertTrue(storage.continuity.readOnlyForCutover)
                XCTAssertThrowsError(try storage.journal.write { _ in }) { XCTAssertEqual($0 as? JournalDatabaseError, .readOnly) }
                XCTAssertThrowsError(try storage.continuity.requireRecovery()); return storage
            }
            for outcome in 0..<3 {
                failed = false
                func run() throws {
                    try Native.withAuthorityPair(initial: selected, verifyCurrent: verify, openStorage: storage) { policy, current in
                        callback = current; XCTAssertEqual(policy, originalCurrent.policy.policy); try current()
                        XCTAssertEqual(try read(f, initial: target), originalTarget)
                        if outcome == 1 { throw Fault.injected }
                        if outcome == 2 { failed = true; try current() }
                    }
                }
                if outcome == 0 { try run() }
                else { XCTAssertThrowsError(try run()) { XCTAssertTrue($0 is Fault) } }
                let stoppedAt = checks
                XCTAssertThrowsError(try XCTUnwrap(callback)()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
                XCTAssertEqual(checks, stoppedAt); failed = false
                XCTAssertEqual(try read(f, initial: selected), originalCurrent)
                XCTAssertEqual(try read(f, initial: target), originalTarget)
            }
            XCTAssertEqual(opens, 3)
            XCTAssertThrowsError(try Native.withAuthorityPair(initial: target, verifyCurrent: {},
                openStorage: { try self.open(f, initial: selected) }) { _, _ in XCTFail("A different pair entered the scope") })
            XCTAssertEqual(try bytes(selected), currentBytes); XCTAssertEqual(try bytes(target), targetBytes)
            try f.verifyPair()
        }
    }
}
