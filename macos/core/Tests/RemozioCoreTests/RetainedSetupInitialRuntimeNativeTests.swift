import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Owned owners, files and pairs exercise the provider. Native Root, code, service and installed custody checks remain unexecuted.
final class RetainedSetupInitialRuntimeNativeTests: XCTestCase {
    private typealias Facade = MachineUpdateRetainedSetupInitialRuntimeNative
    private typealias Context = MachineUpdateRetainedSetupRuntimeNativeContext
    private typealias Publication = MachineUpdateRetainedSetupInitialPublicationNative
    private typealias Completion = MachineUpdateRetainedSetupInitialCompletionNative
    private typealias Support = MachineUpdateRetainedSetupPromotionNativeSupport
    private typealias Files = RetainedSetupInitialPublicationNativeTests.Files
    private typealias Snapshot = Facade.Snapshot
    private typealias Artifact = RuntimePublishedArtifactValidation.Artifact
    private enum Fault: Error { case pair, acknowledgement }
    private final class Counts {
        var opens = 0, commits = 0, pairs = 0, pairOpens = 0, outerPairChecks = 0
        var materials = 0, activities = 0, artifacts = 0, publishes = 0, creates = 0, stages = 0
        var callbackDepth = 0, callbackQueries = 0, importedArtifacts = 0
        var stopAtPair = false, loseAcknowledgement = false
        var atPairOpen: (() throws -> Void)?
        var machines: [PreparationIntentStore] = []
        var publications: [MachineUpdateRetainedSetupInitialPublication.Scope] = []
        var observations: [MachineUpdateRetainedSetupInitialObservation.Scope] = []
        var completions: [MachineUpdateRetainedSetupInitialCompletion.Scope] = []
        var escapedRead: (() throws -> Facade.Boundary)?
        func callback<Value>(_ body: () throws -> Value) throws -> Value {
            callbackDepth += 1; defer { callbackDepth -= 1 }; return try body()
        }
    }
    private func pair(_ f: RetainedPolicyWriterFixture, _ expected: Snapshot) throws -> Facade.Boundary {
        let journal = try f.openPolicyJournal(.readOnly); defer { try? journal.close() }
        return try journal.captureRetainedSetupPolicyBoundary(expected: XCTUnwrap(expected.activation.runtime.setup.account?.initialization))
    }
    private func open(_ f: RetainedPolicyWriterFixture, _ initial: AuthorityInitializationIntent) throws -> sending AuthorityStorage {
        let journal = f.openJournalLease, continuity = f.openContinuityLease, account = initial.accountID
        return try Support.openExistingStorage(initial: initial, openJournalLease: { try journal(account) },
            openContinuityLease: { try continuity(account, $0) })
    }
    private func artifacts(_ f: RetainedPolicyWriterFixture, _ expected: Snapshot,
        _ current: Facade.Boundary) throws -> [Artifact] {
        let bundle = try RuntimeConfigurationBundle.retainedSetupInitial(snapshot: expected, current: current,
            candidate: f.candidate, currentCodePolicy: current.policy.policy)
        return try RuntimePublishedArtifactValidation.artifacts(bundle: bundle, material: f.material)
    }
    private func run(_ f: RetainedPolicyWriterFixture, _ expected: Snapshot, _ files: Files,
        _ counts: Counts) throws -> Snapshot {
        let host: (Snapshot) throws -> Void = { actual in
            if actual.activation.runtime.state.configurationPublished && !expected.activation.runtime.state.configurationPublished {
                try actual.requirePublication(from: expected, reference: XCTUnwrap(expected.activation.runtime.state.reference))
            } else { try actual.requireSame(as: expected) }
        }
        let publication = Publication.Callbacks(verifyCurrent: host,
            verifyServices: { XCTAssertEqual($0, expected.activation.runtime.plan) }, readMaterial: { scope in
                try counts.callback { try scope.withActive {
                    counts.publications.append(scope); counts.materials += 1; return f.material
                } }
            }, verifyActivity: { activity, scope in try counts.callback { try scope.withActive {
                counts.publications.append(scope); counts.activities += 1; XCTAssertEqual(activity, f.material.serviceActivity)
            } } }, readArtifact: { artifact, scope in try counts.callback { try scope.withActive {
                counts.publications.append(scope); counts.artifacts += 1
                let bundle = scope.selection.configuration.bundle
                if scope.selection.inputs.intent != nil {
                    XCTAssertEqual(bundle.command.presence.presence.policy.idleMilliseconds, 123_000)
                    XCTAssertEqual(bundle.transport.relayPort, 45678); counts.importedArtifacts += 1
                }
                return try MachineUpdateRetainedSetupRuntimeNativeFiles.readCheckedArtifact(artifact, bundle: bundle,
                    material: XCTUnwrap(scope.material), runtime: expected.activation.runtime,
                    verifyCurrent: scope.requireActive) { selected, _ in try files.read(selected) }
            } } }, publish: { scope in try counts.callback { try scope.withActive {
                counts.publications.append(scope); counts.publishes += 1
                let artifact = try XCTUnwrap(scope.artifact)
                if try files.publish(artifact, verify: scope.requireActive) == .created { counts.creates += 1 }
            } } })
        let completion = Completion.Callbacks(verifyCurrent: host,
            verifyServices: { XCTAssertEqual($0, expected.activation.runtime.plan) }, readMaterial: { scope in
                try counts.callback { try scope.withActive {
                    counts.observations.append(scope); counts.materials += 1; return f.material
                } }
            }, verifyActivity: { activity, scope in try counts.callback { try scope.withActive {
                counts.observations.append(scope); counts.activities += 1; XCTAssertEqual(activity, f.material.serviceActivity)
            } } }, readArtifact: { artifact, scope in try counts.callback { try scope.withActive {
                counts.observations.append(scope); counts.artifacts += 1
                return try MachineUpdateRetainedSetupRuntimeNativeFiles.readCheckedArtifact(artifact,
                    bundle: XCTUnwrap(scope.bundle), material: XCTUnwrap(scope.material), runtime: scope.snapshot.activation.runtime,
                    verifyCurrent: scope.requireActive) { selected, _ in try files.read(selected) }
            } } }, didStorageStage: { _, scope in try counts.callback {
                counts.stages += 1; counts.completions.append(scope)
                for old in counts.publications { XCTAssertThrowsError(try old.requireActive()) }
                let actual = try scope.read(); try host(actual.snapshot)
                try actual.inputs.requireSource(actual.snapshot.activation.runtime)
                XCTAssertEqual(try actual.material.reference, try f.material.reference)
            } })
        return try Facade.withA10d(expected: expected, candidate: f.candidate, directory: f.directory,
            admission: f.admission, withTargetPair: { body in
                counts.pairOpens += 1; try counts.atPairOpen?()
                let initial = try XCTUnwrap(expected.activation.runtime.setup.account?.initialization)
                return try Support.withReadOnlyPair(initial: initial, verifyCurrent: {}, openStorage: { try self.open(f, initial) }) { journal, active in
                    func read() throws -> Facade.Boundary {
                        try active()
                        let actual = try journal.captureRetainedSetupPolicyBoundary(expected: initial)
                        try XCTUnwrap(expected.intent).requireRecorded(actual); try active(); return actual
                    }
                    counts.escapedRead = read
                    _ = try read(); counts.outerPairChecks += 1
                    if counts.stopAtPair { throw Fault.pair }
                    let actual = try body { try active(); counts.pairs += 1; return try read() }
                    _ = try read(); counts.outerPairChecks += 1; return actual
                }
            }, useMachine: { body in
                try Context.withOpenedMachine(open: {
                    try f.reopen { counts.commits += 1; if counts.loseAcknowledgement { throw Fault.acknowledgement } }
                    let machine = f.machine(); counts.opens += 1; counts.machines.append(machine)
                    machine.observeStoreRead = { _ in if counts.callbackDepth > 0 { counts.callbackQueries += 1 } }
                    return machine
                }, closing: .owner, perform: body)
            }, publication: publication, completion: completion)
    }
    private func budget(_ counts: Counts, published: Bool) {
        XCTAssertEqual(counts.opens, published ? 3 : 5); XCTAssertEqual(counts.commits, published ? 0 : 1)
        XCTAssertEqual(counts.pairOpens, 1); XCTAssertEqual(counts.outerPairChecks, 2)
        XCTAssertEqual(counts.pairs, published ? 8 : 63)
        XCTAssertEqual(counts.materials, published ? 8 : 38); XCTAssertEqual(counts.activities, published ? 8 : 38)
        XCTAssertEqual(counts.artifacts, published ? 32 : 104); XCTAssertEqual(counts.publishes, published ? 0 : 8)
        XCTAssertEqual(counts.stages, published ? 1 : 4); XCTAssertEqual(counts.callbackQueries, 0)
        for machine in counts.machines { XCTAssertNoThrow(try machine.requireClosedForRetainedSetupPolicyWrite()) }
        for scope in counts.publications { XCTAssertThrowsError(try scope.requireActive()) }
        for scope in counts.observations { XCTAssertThrowsError(try scope.requireActive()) }
        for scope in counts.completions { XCTAssertThrowsError(try scope.read()) }
        let old = counts.pairs
        XCTAssertThrowsError(try XCTUnwrap(counts.escapedRead)()); XCTAssertEqual(counts.pairs, old)
    }
    func testOriginalC2ScopeCarriesActualImportedChoicesThroughPublicationAndCompletion() throws {
        try RetainedSetupRuntimeSequenceTests.withImportedPublicationFixture { f, before, _ in
            let files = try Files(owner: before.activation.runtime.preparation.ownerUID)
            defer { XCTAssertNoThrow(try files.close()) }
            let counts = Counts(), actual = try run(f, before, files, counts)
            budget(counts, published: false); XCTAssertEqual(counts.creates, 8); XCTAssertEqual(counts.importedArtifacts, 24)
            XCTAssertTrue(actual.activation.runtime.state.configurationPublished)
            XCTAssertFalse(actual.activation.state.jobsRegistered); XCTAssertNil(actual.activation.state.plan)
            try f.reopen(nil)
            try f.machine().withSharedImportJournal { journal in
                let journal = try XCTUnwrap(journal), account = actual.activation.runtime.preparation
                let inventory = try actual.activation.runtime.setup.source.provisioningInventory(accountID: account.accountID,
                    ownerUID: account.ownerUID, releaseDigest: account.releaseDigest)
                XCTAssertEqual(try journal.current(scope: .init(account: account, inventory: inventory))?.phase, .retained)
            }
        }
    }
    func testPublishedRecoveryUsesOnlyActualObservationScopesAndKeepsAllFileIdentities() throws {
        try RetainedSetupInitialCompletionTests.withRecordedCompletionFixture { f, before, current in
            let files = try Files(owner: before.activation.runtime.preparation.ownerUID)
            defer { XCTAssertNoThrow(try files.close()) }; let all = try artifacts(f, before, current)
            for artifact in all { XCTAssertEqual(try files.publish(artifact), .created) }
            let stamps = try all.map { try files.stamp($0) }
            let published = try f.machine().completeRetainedSetupRuntimePublication(XCTUnwrap(before.activation.runtime.state.reference),
                expected: before.activation.runtime, policy: XCTUnwrap(before.intent), candidate: f.candidate,
                directory: f.directory, admission: f.admission, fileCustodyAccepted: true,
                verifyScoped: { _, _ in try XCTUnwrap(before.intent).requireRecorded(self.pair(f, before)) })
            let counts = Counts(); try run(f, published, files, counts).requireSame(as: published)
            budget(counts, published: true); XCTAssertTrue(counts.publications.isEmpty)
            XCTAssertEqual(try all.map { try files.stamp($0) }, stamps); try f.reopen(nil)
        }
    }
    func testLostCompletionAcknowledgementStopsBeforeAnyProviderRetry() throws {
        try RetainedSetupInitialCompletionTests.withRecordedCompletionFixture { f, before, current in
            let files = try Files(owner: before.activation.runtime.preparation.ownerUID)
            defer { XCTAssertNoThrow(try files.close()) }; let all = try artifacts(f, before, current)
            let failed = Counts(); failed.loseAcknowledgement = true
            XCTAssertThrowsError(try run(f, before, files, failed)) { XCTAssertTrue($0 is Fault) }
            XCTAssertEqual(failed.opens, 4); XCTAssertEqual(failed.commits, 1); XCTAssertEqual(failed.publishes, 8)
            for machine in failed.machines { XCTAssertNoThrow(try machine.requireClosedForRetainedSetupPolicyWrite()) }
            for scope in failed.publications { XCTAssertThrowsError(try scope.requireActive()) }
            try f.reopen(nil)
            let actual = try f.machine().retainedSetupPolicySnapshot(owner: before.activation.runtime.setup.owner, candidate: f.candidate)
            XCTAssertTrue(actual.activation.runtime.state.configurationPublished)
            let stamps = try all.map { try files.stamp($0) }, recovered = Counts()
            try run(f, actual, files, recovered).requireSame(as: actual); budget(recovered, published: true)
            XCTAssertEqual(try all.map { try files.stamp($0) }, stamps); try f.reopen(nil)
        }
    }
    func testTargetPairCannotOpenDuringP04AndOpensAfterItsActualWriterCloses() throws {
        try MachineUpdateReplacementTests.withRetainedPolicyWriterFixture { f in
            let before = try f.machine().retainedSetupPolicySnapshot(owner: f.source.runtime.setup.owner, candidate: f.candidate)
            let files = try Files(owner: before.activation.runtime.preparation.ownerUID)
            defer { XCTAssertNoThrow(try files.close()) }
            let refused = Counts(), accepted = Counts(); var writing: Snapshot?, writers: [AuthorityJournal] = [], attempts = 0
            let recorded = try MachineUpdateRetainedSetupPolicyOwner.resume(expected: before, candidate: f.candidate,
                directory: f.directory, admission: f.admission, useMachine: { body in
                    try f.reopen(nil); let machine = f.machine(); defer { try? machine.close() }; return try body(machine)
                }, openJournal: { mode in
                    let journal = try f.openPolicyJournal(mode == .readOnly ? .readOnly : .startup)
                    if case .startup = mode {
                        XCTAssertTrue(try journal.read { _ in true }); writers.append(journal)
                    }
                    return journal
                }, verifySnapshot: { _ in }, didStorageStage: { step, stage, scope in
                    if case .writing = step, stage == .afterMutation { writing = try scope.read() }
                }, didJournalStage: { _, active in
                    try active(); attempts += 1
                    XCTAssertThrowsError(try self.run(f, XCTUnwrap(writing), files, refused)) {
                        XCTAssertEqual($0 as? RuntimeActivationError, .incomplete)
                    }
                    XCTAssertEqual(refused.pairOpens, 0); XCTAssertEqual(refused.opens, 0); try active()
                })
            XCTAssertGreaterThan(attempts, 0); XCTAssertFalse(writers.isEmpty)
            accepted.atPairOpen = {
                XCTAssertNoThrow(try f.machine().requireClosedForRetainedSetupPolicyWrite())
                for writer in writers {
                    XCTAssertThrowsError(try writer.read { _ in true })
                }
            }
            accepted.stopAtPair = true
            XCTAssertThrowsError(try run(f, recorded, files, accepted)) { XCTAssertTrue($0 is Fault) }
            XCTAssertEqual(accepted.pairOpens, 1); XCTAssertEqual(accepted.outerPairChecks, 1)
            XCTAssertEqual(accepted.opens, 0); XCTAssertEqual(accepted.publishes, 0); XCTAssertEqual(accepted.commits, 0)
        }
    }
    func testOwnerClosingContractRejectsAnOpenStoreAndClosesItOnFailure() throws {
        try MachineUpdateReplacementTests.withRetainedPolicyWriterFixture { f in
            let machine = f.machine()
            XCTAssertThrowsError(try Context.withOpenedMachine(open: { machine }, closing: .owner, perform: { _ in true })) {
                XCTAssertEqual($0 as? PreparationStoreError, .transactionActive)
            }
            XCTAssertNoThrow(try machine.requireClosedForRetainedSetupPolicyWrite())
            try f.reopen(nil)
            XCTAssertTrue(try Context.withOpenedMachine(open: { f.machine() }, closing: .owner, perform: { actual in
                try actual.close(); return true
            }))
        }
    }
}
