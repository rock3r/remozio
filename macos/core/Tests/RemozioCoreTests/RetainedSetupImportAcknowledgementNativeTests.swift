import Darwin
import Dispatch
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

/// Owned files and journals exercise the ACK adapter. Root, installed services, code custody and physical contention remain unexecuted.
final class RetainedSetupImportAcknowledgementNativeTests: XCTestCase {
    private typealias Facade = MachineUpdateRetainedSetupImportAcknowledgementNative
    private typealias Owner = MachineUpdateRetainedSetupImportAcknowledgement
    private typealias Context = MachineUpdateRetainedSetupRuntimeNativeContext
    private typealias Files = RetainedSetupInitialPublicationNativeTests.Files
    private typealias Frame = PreparationIntentStore.RetainedImportFrame
    private typealias Inputs = MachineUpdateRetainedSetupRuntimeInputs
    private typealias Artifact = RuntimePublishedArtifactValidation.Artifact
    private typealias Read = PreparationIntentStore.InitialRuntimeRead
    private enum Fault: Error { case afterCommit }
    private final class SharedScope: @unchecked Sendable {
        let scope: Owner.Scope
        init(_ scope: Owner.Scope) { self.scope = scope }
    }
    private final class Counts {
        var opens = 0, machineCommits = 0, pairs = 0, hosts = 0, services = 0, materials = 0, activities = 0, artifacts = 0
        var callbackDepth = 0, callbackQueries = 0, lockRefusals = 0, transaction = 0
        var retainedHostChecks = 0, publishedHostChecks = 0
        var transactions: Set<Int> = [], reads: [Read: Int] = [:], scopes: [Owner.Scope] = []
        var machine: PreparationIntentStore?
        var failAfterCommit = false
        var onMaterial: ((Owner.Scope) throws -> Void)?
        func callback<Value>(_ scope: Owner.Scope, _ body: () throws -> Value) throws -> Value {
            callbackDepth += 1; defer { callbackDepth -= 1 }; scopes.append(scope)
            return try scope.withActive(body)
        }
    }
    private func lease(_ f: RetainedPolicyWriterFixture) throws -> InstallationStorageLease {
        let path = URL(fileURLWithPath: f.directory.path)
        return try InstallationStorageLease(anchor: path.deletingLastPathComponent().path,
            relativeDirectory: path.lastPathComponent, owner: getuid())
    }
    private func capture(_ f: RetainedPolicyWriterFixture) throws -> Frame {
        let machine = f.machine()
        return try machine.withSharedImportJournal { journal in
            let journal = try XCTUnwrap(journal)
            return try machine.withSharedImportSnapshot(journal: journal) { directory, owner in
                let entry = try machine.retainedSetupInitialRuntimeEntry(owner: f.source.runtime.setup.owner, candidate: f.candidate)
                let inputs = try Inputs.capture(expected: entry.runtime, journal: journal,
                    verifyCurrent: { try machine.validateStorageLease() }, readRelay: { try .read($0, directory: directory, owner: owner) })
                return (entry, inputs)
            }
        }
    }
    private func run(_ f: RetainedPolicyWriterFixture, _ expected: Frame, _ files: Files,
        _ counts: Counts) throws -> Facade.Result {
        try f.machine().close()
        return try Context.withOpenedMachine(open: {
            counts.opens += 1
            let machine = try PreparationIntentStore(lease: self.lease(f), macID: expected.entry.runtime.preparation.macID,
                maximumRecords: 64, initialize: false, didCommit: { counts.machineCommits += 1 }, opening: .mutable)
            counts.machine = machine
            machine.observeStoreRead = { kind in
                counts.reads[kind, default: 0] += 1
                if kind == .readTransaction { counts.transaction += 1 }
                if counts.callbackDepth > 0 { counts.callbackQueries += 1 }
            }
            return machine
        }) { machine in
            try Facade.withA10c(machine: machine, expected: expected.entry, candidate: f.candidate,
                directory: f.directory, admission: f.admission, readPolicyBoundary: {
                    counts.pairs += 1
                    let journal = try f.openPolicyJournal(.readOnly); defer { try? journal.close() }
                    return try journal.captureRetainedSetupPolicyBoundary(expected: XCTUnwrap(expected.entry.runtime.setup.account?.initialization))
                }, callbacks: .init(verifyCurrent: { scope in try counts.callback(scope) {
                    counts.hosts += 1; counts.transactions.insert(counts.transaction)
                    let actual = try scope.read()
                    if actual.inputs == expected.inputs { try actual.entry.requireSame(as: expected.entry) }
                    else { try actual.entry.requireAcknowledgement(inputs: actual.inputs,
                        from: expected.entry, previousInputs: expected.inputs) }
                    if actual.inputs.intent?.phase == .retained { counts.retainedHostChecks += 1 }
                    if actual.inputs.intent?.phase == .runtimePublished { counts.publishedHostChecks += 1 }
                    XCTAssertThrowsError(try machine.requireClosedForRetainedSetupPolicyWrite()) {
                        XCTAssertEqual($0 as? PreparationStoreError, .transactionActive)
                    }
                    XCTAssertThrowsError(try self.lease(f)) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
                    counts.lockRefusals += 1; _ = try scope.read(); try scope.requireActive()
                } }, verifyServices: { plan in counts.services += 1; XCTAssertEqual(plan, expected.entry.runtime.plan) },
                readMaterial: { scope in try counts.callback(scope) {
                    counts.materials += 1; try counts.onMaterial?(scope); return f.material
                } }, verifyActivity: { activity, scope in try counts.callback(scope) {
                    counts.activities += 1; XCTAssertEqual(activity, f.material.serviceActivity)
                } }, readArtifact: { artifact, scope in try counts.callback(scope) {
                    counts.artifacts += 1; let actual = try scope.read()
                    if counts.failAfterCommit && actual.inputs.intent?.phase == .runtimePublished { throw Fault.afterCommit }
                    let bundle = try XCTUnwrap(scope.bundle), material = try XCTUnwrap(scope.material)
                    XCTAssertEqual(bundle.command.presence.presence.policy.idleMilliseconds, 123_000)
                    XCTAssertEqual(bundle.transport.relayPort, 45678)
                    return try MachineUpdateRetainedSetupRuntimeNativeFiles.readCheckedArtifact(artifact, bundle: bundle,
                        material: material, runtime: actual.entry.runtime, verifyCurrent: scope.requireActive) { selected, requirement in
                            XCTAssertEqual(requirement, .required); return try files.read(selected)
                        }
                } }))
        }
    }
    private func budget(_ f: RetainedPolicyWriterFixture, _ counts: Counts) throws {
        XCTAssertEqual(counts.opens, 1); XCTAssertEqual(counts.machineCommits, 0)
        XCTAssertEqual(counts.pairs, 4); XCTAssertEqual(counts.hosts, 4); XCTAssertEqual(counts.services, 4)
        XCTAssertEqual(counts.materials, 4); XCTAssertEqual(counts.activities, 4); XCTAssertEqual(counts.artifacts, 16)
        XCTAssertEqual(counts.transactions.count, 2); XCTAssertEqual(counts.lockRefusals, 4)
        XCTAssertEqual(counts.reads[.writeTransaction, default: 0], 0); XCTAssertEqual(counts.reads[.importInputs], 2)
        XCTAssertEqual(counts.callbackQueries, 0)
        XCTAssertNoThrow(try XCTUnwrap(counts.machine).requireClosedForRetainedSetupPolicyWrite())
        for scope in counts.scopes { XCTAssertThrowsError(try scope.read()) }
        let released = try lease(f); try released.validate(); released.close()
    }
    private func seed(_ files: Files, _ artifacts: [Artifact]) throws {
        for artifact in artifacts { XCTAssertEqual(try files.publish(artifact), .created) }
    }
    func testOneHeldMachineAdvancesOnceAndFreshRecoveryKeepsAllFilesAndScopesExact() throws {
        try RetainedSetupImportAcknowledgementOwnerTests.withNativeAcknowledgementFixture { f, before, artifacts in
            let files = try Files(owner: before.entry.runtime.preparation.ownerUID)
            defer { XCTAssertNoThrow(try files.close()) }; try seed(files, artifacts)
            let stamps = try artifacts.map { try files.stamp($0) }, first = Counts()
            let result = try run(f, before, files, first); try budget(f, first)
            XCTAssertTrue(result.advanced); XCTAssertEqual(result.frame.inputs.intent?.phase, .runtimePublished)
            XCTAssertEqual(first.retainedHostChecks, 2); XCTAssertEqual(first.publishedHostChecks, 2)
            try f.reopen(nil); let actual = try capture(f)
            try actual.entry.requireSame(as: result.frame.entry); try actual.inputs.requireSame(as: result.frame.inputs)
            let second = Counts(), recovered = try run(f, actual, files, second); try budget(f, second)
            XCTAssertFalse(recovered.advanced); XCTAssertEqual(second.retainedHostChecks, 0); XCTAssertEqual(second.publishedHostChecks, 4)
            try recovered.frame.entry.requireSame(as: actual.entry); try recovered.frame.inputs.requireSame(as: actual.inputs)
            XCTAssertEqual(try artifacts.map { try files.stamp($0) }, stamps)
            try f.reopen(nil)
        }
    }
    func testMissingAndConflictingArtifactsRefuseBeforeAdvanceWithoutRepair() throws {
        try RetainedSetupImportAcknowledgementOwnerTests.withNativeAcknowledgementFixture { f, before, artifacts in
            let files = try Files(owner: before.entry.runtime.preparation.ownerUID)
            defer { XCTAssertNoThrow(try files.close()) }; try seed(files, artifacts)
            let selected = try XCTUnwrap(artifacts.first), path = files.directory.path + "/" + (try files.file(selected).name)
            XCTAssertEqual(unlink(path), 0)
            for bytes: Data? in [nil, Data([0])] {
                if let bytes { try bytes.write(to: URL(fileURLWithPath: path)); XCTAssertEqual(chmod(path, try files.file(selected).mode), 0) }
                let counts = Counts(); XCTAssertThrowsError(try run(f, before, files, counts))
                XCTAssertEqual(counts.opens, 1); XCTAssertEqual(counts.machineCommits, 0); XCTAssertEqual(counts.artifacts, 1)
                XCTAssertEqual(counts.callbackQueries, 0)
                XCTAssertNoThrow(try XCTUnwrap(counts.machine).requireClosedForRetainedSetupPolicyWrite())
                if let bytes { XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: path)), bytes) }
                else { XCTAssertFalse(FileManager.default.fileExists(atPath: path)) }
                try f.reopen(nil); let actual = try capture(f)
                try actual.entry.requireSame(as: before.entry); try actual.inputs.requireSame(as: before.inputs)
            }
        }
    }
    func testPostCommitVerifierFailureStopsAndFreshActualRecoveryDoesNotReplay() throws {
        try RetainedSetupImportAcknowledgementOwnerTests.withNativeAcknowledgementFixture { f, before, artifacts in
            let files = try Files(owner: before.entry.runtime.preparation.ownerUID)
            defer { XCTAssertNoThrow(try files.close()) }; try seed(files, artifacts)
            let stamps = try artifacts.map { try files.stamp($0) }, failed = Counts(); failed.failAfterCommit = true
            XCTAssertThrowsError(try run(f, before, files, failed)) { XCTAssertTrue($0 is Fault) }
            XCTAssertEqual(failed.opens, 1); XCTAssertEqual(failed.machineCommits, 0); XCTAssertEqual(failed.callbackQueries, 0)
            XCTAssertGreaterThan(failed.publishedHostChecks, 0)
            XCTAssertNoThrow(try XCTUnwrap(failed.machine).requireClosedForRetainedSetupPolicyWrite())
            for scope in failed.scopes { XCTAssertThrowsError(try scope.read()) }
            try f.reopen(nil); let actual = try capture(f)
            XCTAssertEqual(actual.inputs.intent?.phase, .runtimePublished)
            let recovery = Counts(), result = try run(f, actual, files, recovery); try budget(f, recovery)
            XCTAssertFalse(result.advanced); try result.frame.entry.requireSame(as: actual.entry); try result.frame.inputs.requireSame(as: actual.inputs)
            XCTAssertEqual(try artifacts.map { try files.stamp($0) }, stamps); try f.reopen(nil)
        }
    }
    func testForeignAndRecursiveLoansRefuseWithoutAdvancingTheRetainedIntent() throws {
        try RetainedSetupImportAcknowledgementOwnerTests.withNativeAcknowledgementFixture { f, before, artifacts in
            let files = try Files(owner: before.entry.runtime.preparation.ownerUID)
            defer { XCTAssertNoThrow(try files.close()) }; try seed(files, artifacts)
            let counts = Counts()
            counts.onMaterial = { scope in
                let shared = SharedScope(scope), rejected = Mutex(false), done = DispatchSemaphore(value: 0)
                DispatchQueue.global().async {
                    defer { done.signal() }
                    do { _ = try shared.scope.read() } catch { rejected.withLock { $0 = error as? JournalLeaseError == .invalidated } }
                }
                XCTAssertEqual(done.wait(timeout: .now() + 2), .success); XCTAssertTrue(rejected.withLock { $0 })
                XCTAssertThrowsError(try scope.withActive {}) { XCTAssertEqual($0 as? PreparationStoreError, .transactionActive) }
            }
            XCTAssertThrowsError(try run(f, before, files, counts))
            XCTAssertEqual(counts.opens, 1); XCTAssertEqual(counts.machineCommits, 0); XCTAssertEqual(counts.artifacts, 0)
            XCTAssertEqual(counts.callbackQueries, 0)
            XCTAssertNoThrow(try XCTUnwrap(counts.machine).requireClosedForRetainedSetupPolicyWrite())
            for scope in counts.scopes { XCTAssertThrowsError(try scope.read()) }
            try f.reopen(nil); let actual = try capture(f)
            try actual.entry.requireSame(as: before.entry); try actual.inputs.requireSame(as: before.inputs)
        }
    }
}
