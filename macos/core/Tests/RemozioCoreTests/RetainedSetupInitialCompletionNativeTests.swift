import Darwin
import Foundation
import XCTest
@testable import RemozioCore

/// Owned files and transactions prove D2 wiring. Root, installed service and native approval behavior remain unexecuted.
final class RetainedSetupInitialCompletionNativeTests: XCTestCase {
    private typealias Facade = MachineUpdateRetainedSetupInitialCompletionNative
    private typealias Context = MachineUpdateRetainedSetupRuntimeNativeContext
    private typealias Files = RetainedSetupInitialPublicationNativeTests.Files
    private typealias Artifact = RuntimePublishedArtifactValidation.Artifact
    private enum Fault: Error { case acknowledgement }
    private final class Counts {
        var opens = 0, commits = 0, pairs = 0, hosts = 0, services = 0, material = 0, activity = 0, artifacts = 0
        var callbackDepth = 0, callbackQueries = 0
        var machine: PreparationIntentStore?
        var stages: [PreparationIntentStore.CompletionIntentStorageStage] = []
        var scopes: [MachineUpdateRetainedSetupInitialCompletion.Scope] = []
        func loan<Value>(_ scope: MachineUpdateRetainedSetupInitialObservation.Scope,
            _ body: () throws -> Value) throws -> Value {
            callbackDepth += 1; defer { callbackDepth -= 1 }; return try scope.withActive(body)
        }
    }
    private func artifacts(_ f: RetainedPolicyWriterFixture, expected: Facade.Snapshot,
        current: Facade.Boundary) throws -> [Artifact] {
        let bundle = try RuntimeConfigurationBundle.retainedSetupInitial(snapshot: expected, current: current,
            candidate: f.candidate, currentCodePolicy: current.policy.policy)
        return try RuntimePublishedArtifactValidation.artifacts(bundle: bundle, material: f.material)
    }
    private func run(_ f: RetainedPolicyWriterFixture, expected: Facade.Snapshot, files: Files, counts: Counts,
        failAcknowledgement: Bool = false) throws -> Facade.Snapshot {
        try f.machine().close()
        return try Context.withOpenedMachine(open: {
            counts.opens += 1
            let directory = URL(fileURLWithPath: f.directory.path)
            let lease = try InstallationStorageLease(anchor: directory.deletingLastPathComponent().path,
                relativeDirectory: directory.lastPathComponent, owner: getuid())
            let machine = try PreparationIntentStore(lease: lease,
                macID: expected.activation.runtime.preparation.macID, maximumRecords: 64, initialize: false,
                didCommit: { counts.commits += 1; if failAcknowledgement { throw Fault.acknowledgement } }, opening: .mutable)
            machine.observeStoreRead = { [weak counts] _ in
                if let counts, counts.callbackDepth > 0 { counts.callbackQueries += 1 }
            }; counts.machine = machine; return machine
        }) { machine in
            try Facade.withD2(machine: machine, expected: expected, candidate: f.candidate,
                directory: f.directory, admission: f.admission, readPolicyBoundary: {
                    counts.pairs += 1
                    let journal = try f.openPolicyJournal(.readOnly); defer { try? journal.close() }
                    return try journal.captureRetainedSetupPolicyBoundary(expected: XCTUnwrap(expected.activation.runtime.setup.account?.initialization))
                }, callbacks: Facade.Callbacks(verifyCurrent: { actual in
                    counts.hosts += 1
                    if actual.activation.runtime.state.configurationPublished && !expected.activation.runtime.state.configurationPublished {
                        try actual.requirePublication(from: expected, reference: XCTUnwrap(expected.activation.runtime.state.reference))
                    } else { try actual.requireSame(as: expected) }
                }, verifyServices: { plan in
                    counts.services += 1; XCTAssertEqual(plan, expected.activation.runtime.plan)
                }, readMaterial: { scope in try counts.loan(scope) { counts.material += 1; return f.material } },
                verifyActivity: { activity, scope in try counts.loan(scope) {
                    counts.activity += 1; XCTAssertEqual(activity, f.material.serviceActivity)
                } }, readArtifact: { artifact, scope in try counts.loan(scope) {
                    counts.artifacts += 1
                    let material = try XCTUnwrap(scope.material), bundle = try XCTUnwrap(scope.bundle)
                    XCTAssertEqual(try material.reference, try f.material.reference)
                    return try MachineUpdateRetainedSetupRuntimeNativeFiles.readCheckedArtifact(artifact, bundle: bundle,
                        material: material, runtime: scope.snapshot.activation.runtime, verifyCurrent: scope.requireActive) { selected, _ in
                            try files.read(selected)
                        }
                } }, didStorageStage: { stage, scope in
                    counts.callbackDepth += 1; defer { counts.callbackDepth -= 1 }
                    for old in counts.scopes { XCTAssertThrowsError(try old.read()) }
                    counts.scopes.append(scope); counts.stages.append(stage)
                    let frame = try scope.read(); try scope.requireActive(); try frame.inputs.requireSource(frame.snapshot.activation.runtime)
                    XCTAssertEqual(try frame.material.reference, try f.material.reference)
                    if !expected.activation.runtime.state.configurationPublished {
                        XCTAssertEqual(frame.snapshot.activation.runtime.state.configurationPublished,
                            stage == .afterMutation || stage == .afterCommit)
                    }
                }))
        }
    }
    private func assertBudget(_ counts: Counts, observations: Int, stages: Int, commits: Int) {
        XCTAssertEqual(counts.opens, 1); XCTAssertEqual(counts.commits, commits)
        XCTAssertEqual(counts.pairs, 2 * observations); XCTAssertEqual(counts.hosts, 2 * observations)
        XCTAssertEqual(counts.services, 2 * observations); XCTAssertEqual(counts.material, 2 * observations)
        XCTAssertEqual(counts.activity, 2 * observations); XCTAssertEqual(counts.artifacts, 8 * observations)
        XCTAssertEqual(counts.stages.count, stages); XCTAssertEqual(counts.callbackQueries, 0)
        for scope in counts.scopes { XCTAssertThrowsError(try scope.read()) }
        XCTAssertThrowsError(try XCTUnwrap(counts.machine).validateStorageLease())
    }
    func testExactFilesCompleteOnceAndFreshPublishedRecoveryWritesNoFileOrMarker() throws {
        try RetainedSetupInitialCompletionTests.withRecordedCompletionFixture { f, before, current in
            let files = try Files(owner: before.activation.runtime.preparation.ownerUID)
            defer { XCTAssertNoThrow(try files.close()) }; let artifacts = try artifacts(f, expected: before, current: current)
            for artifact in artifacts { XCTAssertEqual(try files.publish(artifact), .created) }
            let stamps = try artifacts.map { try files.stamp($0) }, first = Counts()
            let published = try run(f, expected: before, files: files, counts: first)
            assertBudget(first, observations: 10, stages: 4, commits: 1)
            XCTAssertEqual(first.stages, [.beforeTransaction, .inTransaction, .afterMutation, .afterCommit])
            try f.reopen(nil)
            let actual = try f.machine().retainedSetupPolicySnapshot(owner: before.activation.runtime.setup.owner, candidate: f.candidate)
            try actual.requireSame(as: published); XCTAssertTrue(actual.activation.runtime.state.configurationPublished)
            let second = Counts(), recovered = try run(f, expected: actual, files: files, counts: second)
            assertBudget(second, observations: 4, stages: 1, commits: 0)
            try recovered.requireSame(as: actual); XCTAssertEqual(try artifacts.map { try files.stamp($0) }, stamps)
            for artifact in artifacts { XCTAssertEqual(try files.read(artifact), artifact.bytes) }
            XCTAssertFalse(recovered.activation.state.jobsRegistered); XCTAssertNil(recovered.activation.state.plan)
            try f.reopen(nil)
        }
    }
    func testMissingAndConflictingFilesRefuseBeforeCommitWithoutRepair() throws {
        try RetainedSetupInitialCompletionTests.withRecordedCompletionFixture { f, before, current in
            let files = try Files(owner: before.activation.runtime.preparation.ownerUID)
            defer { XCTAssertNoThrow(try files.close()) }; let artifacts = try artifacts(f, expected: before, current: current)
            for artifact in artifacts { XCTAssertEqual(try files.publish(artifact), .created) }
            let selected = try XCTUnwrap(artifacts.first), path = files.directory.path + "/" + (try files.file(selected).name)
            XCTAssertEqual(unlink(path), 0)
            for bytes: Data? in [nil, Data([0])] {
                if let bytes { try bytes.write(to: URL(fileURLWithPath: path)); XCTAssertEqual(chmod(path, try files.file(selected).mode), 0) }
                let counts = Counts()
                XCTAssertThrowsError(try run(f, expected: before, files: files, counts: counts))
                XCTAssertEqual(counts.opens, 1); XCTAssertEqual(counts.commits, 0); XCTAssertEqual(counts.stages.count, 0)
                XCTAssertEqual(counts.artifacts, 1); XCTAssertEqual(counts.callbackQueries, 0)
                XCTAssertThrowsError(try XCTUnwrap(counts.machine).validateStorageLease())
                if let bytes { XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: path)), bytes) }
                else { XCTAssertFalse(FileManager.default.fileExists(atPath: path)) }
                try f.reopen(nil)
                try f.machine().retainedSetupPolicySnapshot(owner: before.activation.runtime.setup.owner, candidate: f.candidate).requireSame(as: before)
            }
        }
    }
    func testLostCommitAcknowledgementStopsAndRecoveryUsesFreshPublishedState() throws {
        try RetainedSetupInitialCompletionTests.withRecordedCompletionFixture { f, before, current in
            let files = try Files(owner: before.activation.runtime.preparation.ownerUID)
            defer { XCTAssertNoThrow(try files.close()) }; let artifacts = try artifacts(f, expected: before, current: current)
            for artifact in artifacts { XCTAssertEqual(try files.publish(artifact), .created) }
            let stamps = try artifacts.map { try files.stamp($0) }, failed = Counts()
            XCTAssertThrowsError(try run(f, expected: before, files: files, counts: failed, failAcknowledgement: true))
            XCTAssertEqual(failed.opens, 1); XCTAssertEqual(failed.commits, 1); XCTAssertEqual(failed.callbackQueries, 0)
            XCTAssertThrowsError(try XCTUnwrap(failed.machine).validateStorageLease())
            for scope in failed.scopes { XCTAssertThrowsError(try scope.read()) }
            try f.reopen(nil)
            let actual = try f.machine().retainedSetupPolicySnapshot(owner: before.activation.runtime.setup.owner, candidate: f.candidate)
            XCTAssertTrue(actual.activation.runtime.state.configurationPublished)
            let recovery = Counts(), result = try run(f, expected: actual, files: files, counts: recovery)
            assertBudget(recovery, observations: 4, stages: 1, commits: 0); try result.requireSame(as: actual)
            XCTAssertEqual(try artifacts.map { try files.stamp($0) }, stamps)
            try f.reopen(nil)
        }
    }
}
