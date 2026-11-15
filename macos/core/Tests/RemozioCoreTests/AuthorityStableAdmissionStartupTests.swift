import Darwin
import Foundation
import XCTest
@testable import RemozioCore

/// Actual owned stores and gates exercise startup reads. Synthetic releases do not prove installed Root execution.
final class AuthorityStableAdmissionStartupTests: XCTestCase {
    private final class Reader: @unchecked Sendable {
        let fixture: RuntimeMaintenanceReaderFixture
        init(_ fixture: RuntimeMaintenanceReaderFixture) { self.fixture = fixture }
        func read() throws -> MachineUpdateAdmissionState { try fixture.machine().updateAdmissionState(candidate: fixture.candidate) }
    }
    private final class LegacyReader: @unchecked Sendable {
        let files: UpdateCandidateStorageFixture
        init(_ files: UpdateCandidateStorageFixture) { self.files = files }
        func read() throws -> MachineUpdateAdmissionState { try files.store.updateAdmissionState(candidate: files.release) }
    }
    private func completed(_ schema: Int64) throws {
        try MachineUpdateReplacementTests.withMaintenanceReaderFixture { f in
            if schema == 29 { try f.edit([RuntimeMaintenanceWindowStorage.createSQL, "PRAGMA user_version=29"]) }
            let actual = try f.machine().stableMachineUpdateSnapshot(candidate: f.candidate)
            XCTAssertEqual(actual.schemaVersion, schema); XCTAssertEqual(actual.activation.phase, .completed)
            let rows = try runtimeMaintenanceFixtureRows(f.databasePath), reader = Reader(f)
            let path = URL(fileURLWithPath: f.databasePath).deletingLastPathComponent(), anchor = path.deletingLastPathComponent().path
            func directory() throws -> ReleaseDestinationLease { try .init(anchor: anchor, relativeDirectory: path.lastPathComponent, owner: getuid()) }
            let state = try reader.read()
            XCTAssertEqual(state.inventory, actual.inventory); XCTAssertEqual(state.registration, actual.admission)
            XCTAssertEqual(state.activation, actual.activation)
            let startup = try XCTUnwrap(AuthorityUpdateAdmissionStartup.capture(machine: f.machine(), macID: actual.inventory.macID,
                installationID: actual.inventory.installationID, accountID: f.authority.accountID,
                activity: .init(directory: directory(), owner: getuid()), candidate: f.candidate, readCurrent: { try reader.read() },
                openBarrier: { scope, identity in try .init(directory: directory(), owner: getuid(), expected: identity, scope: scope) }))
            defer { startup.recovery.close() }
            let admitted = try startup.boundary.acquireAdmission(); try admitted.validate(); admitted.close()
            XCTAssertEqual(try runtimeMaintenanceFixtureRows(f.databasePath), rows)
            XCTAssertThrowsError(try f.machine().updateAdmissionState()) { XCTAssertEqual($0 as? PreparationStoreError, .incompatibleStore) }
            XCTAssertEqual(try runtimeMaintenanceFixtureRows(f.databasePath), rows)
        }
    }
    func testCompletedSchema28StartupAdmitsWithoutChangingAnyRow() throws { try completed(28) }
    func testCompletedSchema29StartupAdmitsWithoutChangingAnyRow() throws { try completed(29) }
    func testLegacySchema16StillAdmitsWithTheSameState() throws {
        let f = try BoundAdmissionRegistrationFixture(); _ = try f.prepare()
        let reader = LegacyReader(f.machine), inventory = try XCTUnwrap(f.machine.store.inventory())
        XCTAssertEqual(try reader.read(), try f.machine.store.updateAdmissionState())
        let startup = try XCTUnwrap(AuthorityUpdateAdmissionStartup.capture(machine: f.machine.store, macID: inventory.macID,
            installationID: inventory.installationID, accountID: f.machine.account, activity: f.activity(), candidate: f.machine.release,
            readCurrent: { try reader.read() }, openBarrier: { scope, identity in
                try .init(directory: f.directory(), owner: getuid(), expected: identity, scope: scope)
            }))
        defer { startup.recovery.close() }
        let admitted = try startup.boundary.acquireAdmission(); try admitted.validate(); admitted.close()
    }
    func testNonterminalActivationKeepsTheActualAdmissionGateClosed() throws {
        let files = try UpdateCandidateStorageFixture(admission: true, activation: true)
        let f = try BoundAdmissionRegistrationFixture(machine: files), registration = try f.prepare()
        try MachineUpdateActivationStorage.enableInLease(installedRelease: files.release, policy: files.policy, store: files.store)
        let candidate = try files.select(files.copy()), reader = LegacyReader(files)
        let coordinator = try UpdateActivationAdmission(anchor: f.root.path, relativeDirectory: "machine", owner: getuid(), expected: registration.machine)
        let drain = try coordinator.beginDrain()
        let record = try files.store.beginMachineUpdateActivation(candidate: candidate, registration: registration,
            runtime: files.store.retainedRuntimeCompatibilityInputs(), replacing: nil, directory: f.directory(), drain: drain, verifyCurrent: {})
        drain.close()
        XCTAssertEqual(try reader.read(), try files.store.updateAdmissionState())
        XCTAssertEqual(try reader.read().activation, record)
        let inventory = try XCTUnwrap(files.store.inventory())
        let startup = try XCTUnwrap(AuthorityUpdateAdmissionStartup.capture(machine: files.store, macID: inventory.macID,
            installationID: inventory.installationID, accountID: files.account, activity: f.activity(), candidate: files.release,
            readCurrent: { try reader.read() }, openBarrier: { scope, identity in
                try .init(directory: f.directory(), owner: getuid(), expected: identity, scope: scope)
            }))
        defer { startup.recovery.close() }
        XCTAssertThrowsError(try startup.boundary.acquireAdmission()) { XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy) }
        XCTAssertThrowsError(try coordinator.beginDrain()) { XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy) }
    }
}
