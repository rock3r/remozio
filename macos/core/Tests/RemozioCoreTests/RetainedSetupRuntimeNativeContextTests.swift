import Darwin
import Dispatch
import Foundation
import XCTest
@testable import RemozioCore

/// Owned metadata and journal values prove comparisons and expiry. The production constructor remains A11c.
final class RetainedSetupRuntimeNativeContextTests: XCTestCase {
    private typealias Native = MachineUpdateRetainedSetupRuntimeNativeContext
    private typealias Entry = Native.Entry
    private typealias Frame = Native.Frame
    private typealias Material = Native.Material
    private typealias Inputs = MachineUpdateRetainedSetupRuntimeInputs
    private typealias Read = PreparationIntentStore.InitialRuntimeRead
    private enum Fault: Error { case injected }
    private final class Trace {
        var events: [String] = []
        var phases: [MachineUpdateRetainedSetupPolicyIntentRecord.Phase?] = []
        var fail: String?
        var owner: LocalAccountIdentity?
        var services: (() throws -> Void)?
        func event(_ name: String) throws { events.append(name); if fail == name { throw Fault.injected } }
    }
    private final class ThreadUse: @unchecked Sendable {
        let context: Native.Context, entry: Entry
        var error: Error?
        init(_ context: Native.Context, _ entry: Entry) { self.context = context; self.entry = entry }
    }
    private let metadata = ["custody", "release", "custody", "code", "custody", "owner", "custody", "services", "custody"]
    private func controls(_ owner: LocalAccountIdentity, _ trace: Trace) -> Native.Controls {
        .init(validateCustody: { try trace.event("custody") }, validateRelease: { actual in
            try trace.event("release"); trace.phases.append(actual.intent?.phase)
        }, validateExecutingCode: { try trace.event("code") }, lookupOwner: { uid in
            try trace.event("owner"); XCTAssertEqual(uid, owner.uid); return trace.owner ?? owner
        }, validateServices: { plan in
            try trace.event("services"); XCTAssertEqual(plan.ownerUID, owner.uid); try trace.services?()
        })
    }
    private func inputs(_ entry: Entry, journal: SharedSetupImportJournal? = nil) throws -> Inputs {
        try Inputs.capture(expected: entry.runtime, journal: journal, verifyCurrent: {},
            readRelay: { _ in try .init(plan: nil, snapshot: nil) })
    }
    private func checked(_ reads: () -> Int, _ body: () throws -> Void) throws {
        let before = reads(); defer { XCTAssertEqual(reads(), before, "Host verification queried the machine") }; try body()
    }
    private func ordered(_ trace: Trace) {
        XCTAssertFalse(trace.events.isEmpty); XCTAssertEqual(trace.events.count % metadata.count, 0)
        for offset in stride(from: 0, to: trace.events.count, by: metadata.count) {
            XCTAssertEqual(Array(trace.events[offset..<(offset + metadata.count)]), metadata)
        }
    }
    private func entry(_ policy: Native.Policy, _ candidate: SignedReleaseEvidence) throws -> Entry {
        try .init(runtime: policy.activation.runtime, activation: policy.activation.state, intent: policy.intent, candidate: candidate)
    }
    private func withJournal(_ entry: Entry, _ body: (SharedSetupImportJournal, SharedSetupImportIntent) throws -> Void) throws {
        let runtime = entry.runtime, account = runtime.preparation
        let inventory = try runtime.setup.source.provisioningInventory(accountID: account.accountID,
            ownerUID: account.ownerUID, releaseDigest: account.releaseDigest)
        let defaults = try SharedSetupDefaults(presence: .init(idleMilliseconds: 540_000,
            observationLifetimeMilliseconds: 7000, unavailableGraceMilliseconds: 45_000), gateway: GatewaySetupForm().settingsSelection())
        let intent = try SharedSetupImportIntent(scope: .init(account: account, inventory: inventory), proposal: .init(defaults: defaults))
        let root = URL(fileURLWithPath: "/private/tmp/remozio-runtime-context-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { XCTAssertNoThrow(try FileManager.default.removeItem(at: root)) }
        let directory = try ProtectedSetupDirectory(anchor: root.path, relativePath: "Import", owner: getuid())
        defer { directory.close() }; _ = try SetupDatabaseFileProvisioning.prepare(directory: directory, kind: .sharedSetupImport, owner: getuid())
        let journal = try SharedSetupImportJournal(lease: .init(anchor: root.path, relativeDirectory: "Import", owner: getuid(),
            ancestorOwner: getuid(), databaseName: "setup-import.sqlite"), owner: getuid(), macID: account.macID,
            installationID: account.installationID, initialize: true)
        defer { XCTAssertNoThrow(try journal.close()) }; try journal.begin(intent); try body(journal, intent)
    }
    func testOwnedMaterialFramesEnforceMetadataOrderFailurePoisoningAndLoanLifetimeWithoutQueries() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let machine = try f.machine()
            let before = try machine.retainedSetupInitialRuntimeEntry(owner: f.owner, candidate: f.candidate)
            let frame: Frame = (before, try inputs(before)), material = try Material(runtime: before.runtime, activation: before.activation)
            var reads = 0; machine.observeStoreRead = { _ in reads += 1 }; defer { machine.observeStoreRead = nil }
            for failed in ["custody", "release", "code", "owner", "services"] {
                let trace = Trace(); trace.fail = failed
                XCTAssertThrowsError(try Native.withOwnedContext(expected: frame, candidate: f.candidate, controls: controls(f.owner, trace)) { _ in
                    XCTFail("A failed host check entered the body")
                }) { XCTAssertTrue($0 is Fault) }
                let end = try XCTUnwrap(metadata.firstIndex(of: failed)); XCTAssertEqual(trace.events, Array(metadata[...end]))
            }
            XCTAssertEqual(reads, 0)
            let wrong = Trace(); wrong.owner = .init(uid: f.owner.uid, primaryGroupID: f.owner.primaryGroupID, directoryID: UUID())
            XCTAssertThrowsError(try Native.withOwnedContext(expected: frame, candidate: f.candidate, controls: controls(f.owner, wrong)) { _ in XCTFail("Wrong owner") })
            var escaped: Native.Context?
            let trace = Trace()
            try Native.withOwnedContext(expected: frame, candidate: f.candidate, controls: controls(f.owner, trace)) { context in
                escaped = context
                try checked({ reads }) { try context.verifyEntry(before); try context.verifyFrame(frame); try context.verifyMaterial(material) }
                let count = trace.events.count, use = ThreadUse(context, before), done = DispatchSemaphore(value: 0)
                Thread.detachNewThread { do { try use.context.verifyEntry(use.entry) } catch { use.error = error }; done.signal() }
                XCTAssertEqual(done.wait(timeout: .now() + 5), .success)
                XCTAssertEqual(use.error as? JournalLeaseError, .invalidated); XCTAssertEqual(trace.events.count, count)
                try checked({ reads }) { try context.verifyEntry(before) }
            }
            ordered(trace); XCTAssertEqual(reads, 0)
            XCTAssertThrowsError(try XCTUnwrap(escaped).verifyFrame(frame)) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            XCTAssertThrowsError(try XCTUnwrap(escaped).verifyMaterial(material)) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            XCTAssertThrowsError(try Native.withOwnedContext(expected: frame, candidate: f.candidate, controls: controls(f.owner, Trace())) { context in
                escaped = context; throw Fault.injected
            }) { XCTAssertTrue($0 is Fault) }
            XCTAssertThrowsError(try XCTUnwrap(escaped).verifyEntry(before)) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            let failed = Trace()
            XCTAssertThrowsError(try Native.withOwnedContext(expected: frame, candidate: f.candidate, controls: controls(f.owner, failed)) { context in
                failed.fail = "code"
                XCTAssertThrowsError(try context.verifyMaterial(material)) { XCTAssertTrue($0 is Fault) }
                failed.fail = nil
                XCTAssertThrowsError(try context.verifyEntry(before)) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            }) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            let recursive = Trace()
            XCTAssertThrowsError(try Native.withOwnedContext(expected: frame, candidate: f.candidate, controls: controls(f.owner, recursive)) { context in
                recursive.services = {
                    XCTAssertThrowsError(try context.verifyEntry(before)) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
                }
                try context.verifyMaterial(material)
            }) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            XCTAssertEqual(reads, 0)
            let retaining = Trace(); var stages: [PreparationIntentStore.CompletionIntentStorageStage] = []
            try Native.withOwnedContext(expected: frame, candidate: f.candidate, controls: controls(f.owner, retaining)) { context in
                _ = try machine.retainRetainedSetupRuntimeMaterial(f.material.reference, expected: material, candidate: f.candidate,
                    directory: f.directory, admission: f.admission, fileCustodyAccepted: true, verifyScoped: { stage, actual in
                        stages.append(stage); try self.checked({ reads }) { try context.verifyMaterial(actual) }
                    })
                let after = try machine.retainedSetupInitialRuntimeEntry(owner: f.owner, candidate: f.candidate)
                try checked({ reads }) { try context.verifyEntry(after); try context.verifyFrame((after, frame.inputs)) }
                XCTAssertEqual(after.runtime.state.reference, try f.material.reference)
            }
            ordered(retaining); XCTAssertEqual(stages, [.beforeTransaction, .inTransaction, .afterMutation, .afterCommit])
        }
    }
    func testOwnedPolicyPublicationAndAcknowledgementAdaptersKeepExactFramesAndNeverQueryTransactions() throws {
        try MachineUpdateReplacementTests.withRetainedPolicyWriterFixture(sharedImportFormats: true) { f in
            let owner = f.source.runtime.setup.owner
            let before = try f.machine().retainedSetupInitialRuntimeEntry(owner: owner, candidate: f.candidate)
            let initial: Frame = (before, try inputs(before)), trace = Trace()
            var reads = 0; var stages: [PreparationIntentStore.CompletionIntentStorageStage] = []
            func useMachine<Value>(_ body: (PreparationIntentStore) throws -> Value) throws -> Value {
                try f.reopen(nil); let machine = f.machine(); machine.observeStoreRead = { _ in reads += 1 }
                defer { machine.observeStoreRead = nil; try? machine.close() }; return try body(machine)
            }
            var recorded: Native.Policy?, published: Native.Policy?
            try Native.withOwnedContext(expected: initial, candidate: f.candidate, controls: controls(owner, trace)) { context in
                recorded = try MachineUpdateRetainedSetupPolicyOwner.resume(expected: XCTUnwrap(before.policy), candidate: f.candidate,
                    directory: f.directory, admission: f.admission, useMachine: { body in try useMachine(body) },
                    openJournal: { try f.openPolicyJournal($0 == .readOnly ? .readOnly : .startup) },
                    verifySnapshot: { actual in try self.checked({ reads }) { try context.verifyPolicy(actual) } })
                let actual = try XCTUnwrap(recorded)
                try checked({ reads }) { try context.verifyEntry(entry(actual, f.candidate)) }
                published = try useMachine { machine in
                    try machine.completeRetainedSetupRuntimePublication(f.material.reference, expected: actual.activation.runtime,
                        policy: XCTUnwrap(actual.intent), candidate: f.candidate, directory: f.directory, admission: f.admission,
                        fileCustodyAccepted: true, verifyScoped: { stage, value in
                            stages.append(stage); try self.checked({ reads }) { try context.verifyPublication(value) }
                        })
                }
                try checked({ reads }) { try context.verifyPublication(XCTUnwrap(published)) }
            }
            ordered(trace); XCTAssertTrue(trace.phases.contains(.prepared)); XCTAssertTrue(trace.phases.contains(.writing)); XCTAssertTrue(trace.phases.contains(.recorded))
            XCTAssertEqual(stages, [.beforeTransaction, .inTransaction, .afterMutation, .afterCommit])
            let recordedEntry = try entry(XCTUnwrap(recorded), f.candidate), publishedEntry = try entry(XCTUnwrap(published), f.candidate)
            for skip in [false, true] {
                let refused = Trace()
                XCTAssertThrowsError(try Native.withOwnedContext(expected: initial, candidate: f.candidate, controls: controls(owner, refused)) { context in
                    let count = refused.events.count
                    if skip { XCTAssertThrowsError(try context.verifyEntry(publishedEntry)) }
                    else { XCTAssertThrowsError(try context.verifyPolicy(XCTUnwrap(recorded))) }
                    XCTAssertEqual(refused.events.count, count)
                    XCTAssertThrowsError(try context.verifyEntry(before)) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
                }) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            }
            let recordedFrame: Frame = (recordedEntry, initial.inputs), wrongAdapter = Trace()
            XCTAssertThrowsError(try Native.withOwnedContext(expected: recordedFrame, candidate: f.candidate, controls: controls(owner, wrongAdapter)) { context in
                let count = wrongAdapter.events.count
                XCTAssertThrowsError(try context.verifyPolicy(XCTUnwrap(published)))
                XCTAssertEqual(wrongAdapter.events.count, count)
            }) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            // This journal supplies comparison values only. A10b owns the machine lock and the real ACK interval.
            try withJournal(publishedEntry) { journal, intent in
                let previous: Frame = (publishedEntry, try inputs(publishedEntry, journal: journal))
                let committed = try journal.advance(intent, to: .runtimePublished)
                let after: Frame = (publishedEntry, try inputs(publishedEntry, journal: journal))
                XCTAssertEqual(after.inputs.intent, committed)
                let ack = Trace()
                try Native.withOwnedContext(expected: previous, candidate: f.candidate, controls: controls(owner, ack)) { context in
                    try checked({ reads }) { try context.verifyAcknowledgement(previous); try context.verifyAcknowledgement(after) }
                    try checked({ reads }) { try context.verifyAcknowledgement(after); try context.verifyFrame(after); try context.verifyEntry(after.entry) }
                }
                ordered(ack)
                let replay = Trace()
                XCTAssertThrowsError(try Native.withOwnedContext(expected: after, candidate: f.candidate, controls: controls(owner, replay)) { context in
                    let count = replay.events.count
                    XCTAssertThrowsError(try context.verifyAcknowledgement(previous))
                    XCTAssertEqual(replay.events.count, count)
                }) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
                let strict = Trace()
                XCTAssertThrowsError(try Native.withOwnedContext(expected: previous, candidate: f.candidate, controls: controls(owner, strict)) { context in
                    let count = strict.events.count
                    XCTAssertThrowsError(try context.verifyFrame(after))
                    XCTAssertEqual(strict.events.count, count)
                }) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            }
            try f.reopen(nil)
            try f.machine().retainedSetupInitialRuntimeEntry(owner: owner, candidate: f.candidate).requireSame(as: publishedEntry)
            try f.machine().close()
        }
    }
}
