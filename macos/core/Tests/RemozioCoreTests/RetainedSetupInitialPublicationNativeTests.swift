import Darwin
import Foundation
import XCTest
@testable import RemozioCore

/// Owned files prove C1/C2 wiring and refusal. They cannot construct native custody or executing-code approval.
final class RetainedSetupInitialPublicationNativeTests: XCTestCase {
    private typealias Facade = MachineUpdateRetainedSetupInitialPublicationNative
    private typealias Context = MachineUpdateRetainedSetupRuntimeNativeContext
    private typealias Artifact = RuntimePublishedArtifactValidation.Artifact
    private enum Fault: Error { case host }
    private final class Files {
        let root = URL(fileURLWithPath: "/private/tmp/remozio-native-publication-" + UUID().uuidString)
        let directory: ProtectedSetupDirectory
        let names: [String: AdministrativeSetupPublication.File]
        init(owner: UInt32) throws {
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
            guard chmod(root.path, 0o755) == 0 else { throw JournalLeaseError.system(errno) }
            directory = try .init(anchor: root.path, relativePath: "Shared", owner: getuid(), visibility: .sharedMetadata)
            let values: [AdministrativeSetupPublication.File] = [.elevationPolicy, .commandConfiguration,
                .transportIdentity(ownerUID: getuid(), groupID: getgid()), .transportConfiguration, .gatewaySettingsHost,
                .presenceClient(ownerUID: owner), .pairingClient(ownerUID: owner), .frontendClient(ownerUID: owner)]
            names = Dictionary(uniqueKeysWithValues: values.map { ($0.name, $0) })
        }
        func close() throws { directory.close(); try FileManager.default.removeItem(at: root) }
        func file(_ artifact: Artifact) throws -> AdministrativeSetupPublication.File {
            try XCTUnwrap(names[URL(fileURLWithPath: artifact.path).lastPathComponent])
        }
        func read(_ artifact: Artifact) throws -> Data? {
            let file = try file(artifact)
            guard try ProtectedServiceConfiguration.readOptional(anchor: directory.path, relativePath: file.name, owner: getuid()) != nil else { return nil }
            return try ProtectedServiceConfiguration.read(anchor: directory.path, relativePath: file.name,
                owner: getuid(), privateFile: file.mode == 0o600)
        }
        func publish(_ artifact: Artifact, verify: () throws -> Void = {}) throws -> AdministrativeSetupPublicationResult {
            try AdministrativeSetupPublication.publish(artifact.bytes, file: file(artifact), directory: directory,
                owner: getuid(), verify: verify)
        }
        func stamp(_ artifact: Artifact) throws -> [UInt64] {
            var value = stat(); let path = directory.path + "/" + (try file(artifact).name)
            guard lstat(path, &value) == 0 else { throw JournalLeaseError.system(errno) }
            return [value.st_ino, UInt64(value.st_mtimespec.tv_sec), UInt64(value.st_mtimespec.tv_nsec),
                UInt64(value.st_ctimespec.tv_sec), UInt64(value.st_ctimespec.tv_nsec)]
        }
    }
    private final class Counts {
        var opens = 0, pairs = 0, host = 0, services = 0, material = 0, activity = 0, artifacts = 0, publishes = 0, creates = 0
        var depth = 0, callbackQueries = 0
        var machine: PreparationIntentStore?
        var escaped: MachineUpdateRetainedSetupInitialPublication.Scope?
        func loan<Value>(_ scope: MachineUpdateRetainedSetupInitialPublication.Scope, _ body: () throws -> Value) throws -> Value {
            depth += 1; defer { depth -= 1 }; escaped = scope
            return try scope.withActive(body)
        }
    }
    private func run(_ f: RetainedPolicyWriterFixture, expected: Facade.Snapshot, counts: Counts,
        callbacks: Facade.Callbacks) throws -> Facade.Selection {
        try f.machine().close()
        return try Context.withOpenedMachine(open: {
            counts.opens += 1
            let machine = try PreparationIntentStore(lease: InstallationStorageLease.acquire(directoryPath: f.directory.path),
                macID: expected.activation.runtime.preparation.macID, maximumRecords: 64, initialize: false, opening: .retainedPolicyVerification)
            machine.observeStoreRead = { [weak counts] _ in if let counts, counts.depth > 0 { counts.callbackQueries += 1 } }
            counts.machine = machine
            return machine
        }) { machine in
            try Facade.withC2(machine: machine, expected: expected, candidate: f.candidate,
                directory: f.directory, admission: f.admission, readPolicyBoundary: {
                    counts.pairs += 1
                    let journal = try f.openPolicyJournal(.readOnly); defer { try? journal.close() }
                    return try journal.captureRetainedSetupPolicyBoundary(expected: XCTUnwrap(expected.activation.runtime.setup.account?.initialization))
                }, callbacks: callbacks)
        }
    }
    private func callbacks(_ f: RetainedPolicyWriterFixture, expected: Facade.Snapshot, counts: Counts, files: Files,
        hostFails: Bool = false, conflict: Bool = false) -> Facade.Callbacks {
        Facade.Callbacks(verifyCurrent: { actual in
            counts.host += 1; XCTAssertEqual(counts.depth, 0)
            if hostFails { throw Fault.host }; try actual.requireSame(as: expected)
        }, verifyServices: { plan in counts.services += 1; XCTAssertEqual(plan, expected.activation.runtime.plan) },
        readMaterial: { scope in try counts.loan(scope) { counts.material += 1; return f.material } },
        verifyActivity: { activity, scope in try counts.loan(scope) {
            counts.activity += 1; XCTAssertEqual(activity, f.material.serviceActivity)
        } }, readArtifact: { artifact, scope in try counts.loan(scope) {
            counts.artifacts += 1
            if conflict { return Data([0]) }
            return try files.read(artifact)
        } }, publish: { scope in try counts.loan(scope) {
            counts.publishes += 1; let artifact = try XCTUnwrap(scope.artifact)
            if try files.publish(artifact, verify: scope.requireActive) == .created { counts.creates += 1 }
        } })
    }

    func testPartialPublicationKeepsExistingInodesAndTheSQLMarkerWithExactCallbackBudget() throws {
        try RetainedSetupInitialPublicationWriterTests.withRecordedInitialSelectionFixture { f, snapshot, current in
            let files = try Files(owner: snapshot.activation.runtime.preparation.ownerUID)
            defer { XCTAssertNoThrow(try files.close()) }
            let bundle = try RuntimeConfigurationBundle.retainedSetupInitial(snapshot: snapshot, current: current,
                candidate: f.candidate, currentCodePolicy: current.policy.policy)
            let artifacts = try RuntimePublishedArtifactValidation.artifacts(bundle: bundle, material: f.material)
            for artifact in artifacts.prefix(3) { XCTAssertEqual(try files.publish(artifact), .created) }
            let stamps = try artifacts.prefix(3).map { try files.stamp($0) }, counts = Counts()
            let selection = try run(f, expected: snapshot, counts: counts,
                callbacks: callbacks(f, expected: snapshot, counts: counts, files: files))
            XCTAssertEqual(counts.opens, 1); XCTAssertEqual(counts.pairs, 43); XCTAssertEqual(counts.host, 60)
            XCTAssertEqual(counts.services, 18); XCTAssertEqual(counts.material, 18); XCTAssertEqual(counts.activity, 18)
            XCTAssertEqual(counts.artifacts, 24); XCTAssertEqual(counts.publishes, 8); XCTAssertEqual(counts.creates, 5)
            XCTAssertEqual(counts.callbackQueries, 0)
            XCTAssertEqual(try artifacts.prefix(3).map { try files.stamp($0) }, stamps)
            for artifact in artifacts { XCTAssertEqual(try files.read(artifact), artifact.bytes) }
            XCTAssertEqual(try RuntimePublishedArtifactValidation.artifacts(bundle: selection.configuration.bundle, material: f.material).map(\.path), artifacts.map(\.path))
            XCTAssertThrowsError(try XCTUnwrap(counts.escaped).requireActive()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            XCTAssertThrowsError(try XCTUnwrap(counts.machine).validateStorageLease()) { XCTAssertEqual($0 as? PreparationStoreError, .closed) }
            try f.reopen(nil)
            let actual = try f.machine().retainedSetupPolicySnapshot(owner: snapshot.activation.runtime.setup.owner, candidate: f.candidate)
            XCTAssertFalse(actual.activation.runtime.state.configurationPublished); try actual.requireSame(as: snapshot)
        }
    }
    func testConflictingArtifactClosesTheMachineAndExpiresTheOriginalScopeWithoutRepair() throws {
        try RetainedSetupInitialPublicationWriterTests.withRecordedInitialSelectionFixture { f, snapshot, _ in
            let files = try Files(owner: snapshot.activation.runtime.preparation.ownerUID)
            defer { XCTAssertNoThrow(try files.close()) }; let counts = Counts()
            XCTAssertThrowsError(try run(f, expected: snapshot, counts: counts,
                callbacks: callbacks(f, expected: snapshot, counts: counts, files: files, conflict: true))) {
                    XCTAssertEqual($0 as? AdministrativeSetupPublicationError, .conflictingConfiguration)
                }
            XCTAssertEqual(counts.opens, 1); XCTAssertEqual(counts.publishes, 0); XCTAssertEqual(counts.creates, 0)
            XCTAssertEqual(counts.artifacts, 1); XCTAssertEqual(counts.callbackQueries, 0)
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: files.directory.path), [])
            XCTAssertThrowsError(try XCTUnwrap(counts.escaped).requireActive()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            XCTAssertThrowsError(try XCTUnwrap(counts.machine).validateStorageLease()) { XCTAssertEqual($0 as? PreparationStoreError, .closed) }
            try f.reopen(nil)
            try f.machine().retainedSetupPolicySnapshot(owner: snapshot.activation.runtime.setup.owner, candidate: f.candidate).requireSame(as: snapshot)
        }
    }
    func testHostRefusalPrecedesFileLoansAndClosesTheOnlyMachine() throws {
        try RetainedSetupInitialPublicationWriterTests.withRecordedInitialSelectionFixture { f, snapshot, _ in
            let files = try Files(owner: snapshot.activation.runtime.preparation.ownerUID)
            defer { XCTAssertNoThrow(try files.close()) }; let counts = Counts()
            XCTAssertThrowsError(try run(f, expected: snapshot, counts: counts,
                callbacks: callbacks(f, expected: snapshot, counts: counts, files: files, hostFails: true))) { XCTAssertTrue($0 is Fault) }
            XCTAssertEqual(counts.opens, 1); XCTAssertEqual(counts.pairs, 1); XCTAssertEqual(counts.host, 1)
            XCTAssertEqual(counts.material + counts.activity + counts.artifacts + counts.publishes, 0)
            XCTAssertNil(counts.escaped); XCTAssertEqual(counts.callbackQueries, 0)
            XCTAssertThrowsError(try XCTUnwrap(counts.machine).validateStorageLease()) { XCTAssertEqual($0 as? PreparationStoreError, .closed) }
            try f.reopen(nil)
            try f.machine().retainedSetupPolicySnapshot(owner: snapshot.activation.runtime.setup.owner, candidate: f.candidate).requireSame(as: snapshot)
        }
    }
}
