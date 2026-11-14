import Darwin
import Foundation
import XCTest
@testable import RemozioCore

/// Owned values prove exact reader selection. No native path, service activity or installed identity is exercised.
final class RetainedSetupRuntimeNativeFilesTests: XCTestCase {
    private typealias Files = MachineUpdateRetainedSetupRuntimeNativeFiles
    private enum Fault: Error { case host }
    func testRetainedMaterialRejectsAChangedIdentityAndMissingReferenceWithoutNativeReads() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture(hasReference: true) { f in
            let entry = try f.machine().retainedSetupInitialRuntimeEntry(owner: f.owner, candidate: f.candidate), runtime = entry.runtime
            try Files.requireMaterial(f.material, runtime: runtime)
            let different = try RuntimePreparationMaterial(materialID: Data(repeating: 99, count: 16), services: f.material.services,
                transportIdentity: f.material.transportIdentity, transportPublicKeyInfo: f.material.transportPublicKeyInfo,
                gateway: f.material.gateway, serviceActivity: f.material.serviceActivity, auditDeliveryVersion: f.material.auditDeliveryVersion)
            XCTAssertThrowsError(try Files.requireMaterial(different, runtime: runtime)) {
                XCTAssertEqual($0 as? RuntimePreparationError, .conflictingMaterial)
            }
            let absent = try Files.Runtime(setup: runtime.setup, services: .init(plan: runtime.plan, complete: true),
                state: .init(reference: nil, configurationPublished: false), reservedNumbers: runtime.reservedNumbers)
            XCTAssertThrowsError(try Files.requireMaterial(f.material, runtime: absent)) {
                XCTAssertEqual($0 as? RuntimePreparationError, .incomplete)
            }
            let activity = try XCTUnwrap(f.material.serviceActivity); var hostCalls = 0
            XCTAssertNotEqual(getuid(), 0)
            XCTAssertThrowsError(try Files.readMaterial(runtime: runtime, verifyCurrent: { hostCalls += 1 })) {
                XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
            }
            XCTAssertThrowsError(try Files.verifyActivity(activity, runtime: runtime, verifyCurrent: { hostCalls += 1 })) {
                XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
            }
            XCTAssertEqual(hostCalls, 0)
        }
    }
    func testDerivedArtifactsPinPathAccessAndBytesAndRequirePublishedLeaves() throws {
        try RetainedSetupInitialPublicationWriterTests.withRecordedInitialSelectionFixture { f, snapshot, pair in
            let runtime = snapshot.activation.runtime
            let bundle = try RuntimeConfigurationBundle.retainedSetupInitial(snapshot: snapshot, current: pair,
                candidate: f.candidate, currentCodePolicy: pair.policy.policy)
            let artifacts = try RuntimePublishedArtifactValidation.artifacts(bundle: bundle, material: f.material)
            XCTAssertEqual(artifacts.count, 8); XCTAssertEqual(Set(artifacts.map(\.path)).count, 8)
            XCTAssertTrue(artifacts.contains { $0.access == .privateRoot }); XCTAssertTrue(artifacts.contains { $0.access == .publicRoot })
            XCTAssertTrue(artifacts.contains { if case .servicePrivate = $0.access { return true }; return false })
            // This is only a publication-state value image. No stored marker changes and no native recovery runs.
            let published = try Files.Runtime(setup: runtime.setup, services: .init(plan: runtime.plan, complete: true),
                state: .init(reference: runtime.state.reference, configurationPublished: true), reservedNumbers: runtime.reservedNumbers)
            for artifact in artifacts {
                var events: [String] = []
                let present = try Files.readCheckedArtifact(artifact, bundle: bundle, material: f.material, runtime: runtime,
                    verifyCurrent: { events.append("host") }) { selected, requirement in
                        events.append("read"); XCTAssertEqual(requirement, .optionalLeaf)
                        XCTAssertEqual(selected.path, artifact.path); XCTAssertEqual(selected.access, artifact.access); return selected.bytes
                    }
                XCTAssertEqual(present, artifact.bytes); XCTAssertEqual(events, ["host", "read", "host"])
                XCTAssertNil(try Files.readCheckedArtifact(artifact, bundle: bundle, material: f.material, runtime: runtime,
                    verifyCurrent: {}) { _, requirement in XCTAssertEqual(requirement, .optionalLeaf); return nil })
                XCTAssertThrowsError(try Files.readCheckedArtifact(artifact, bundle: bundle, material: f.material, runtime: published,
                    verifyCurrent: {}) { _, requirement in XCTAssertEqual(requirement, .required); return nil }) {
                        XCTAssertEqual($0 as? RuntimePreparationError, .incomplete)
                    }
                XCTAssertEqual(try Files.readCheckedArtifact(artifact, bundle: bundle, material: f.material, runtime: published,
                    verifyCurrent: {}) { selected, requirement in XCTAssertEqual(requirement, .required); return selected.bytes }, artifact.bytes)
                XCTAssertThrowsError(try Files.readCheckedArtifact(artifact, bundle: bundle, material: f.material, runtime: runtime,
                    verifyCurrent: {}) { _, _ in Data([0]) }) {
                        XCTAssertEqual($0 as? AdministrativeSetupPublicationError, .conflictingConfiguration)
                    }
                let wrongAccess: RuntimePublishedArtifactValidation.Access = artifact.access == .publicRoot ? .privateRoot : .publicRoot
                for wrong in [Files.Artifact(path: "/private/tmp/arbitrary", bytes: artifact.bytes, access: artifact.access),
                    .init(path: artifact.path, bytes: artifact.bytes, access: wrongAccess),
                    .init(path: artifact.path, bytes: artifact.bytes + Data([0]), access: artifact.access)] {
                    XCTAssertThrowsError(try Files.readCheckedArtifact(wrong, bundle: bundle, material: f.material, runtime: runtime,
                        verifyCurrent: {}) { _, _ in XCTFail("A substituted artifact reached the reader"); return nil }) {
                            XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
                        }
                }
                var hostCalls = 0
                XCTAssertThrowsError(try Files.readArtifact(artifact, bundle: bundle, material: f.material, runtime: runtime,
                    verifyCurrent: { hostCalls += 1 })) { XCTAssertEqual($0 as? JournalLeaseError, .rootRequired) }
                XCTAssertEqual(hostCalls, 0)
            }
            let artifact = try XCTUnwrap(artifacts.first); var reads = 0, hostChecks = 0
            XCTAssertThrowsError(try Files.readCheckedArtifact(artifact, bundle: bundle, material: f.material, runtime: runtime,
                verifyCurrent: { throw Fault.host }) { _, _ in reads += 1; return nil }) { XCTAssertTrue($0 is Fault) }
            XCTAssertEqual(reads, 0)
            XCTAssertThrowsError(try Files.readCheckedArtifact(artifact, bundle: bundle, material: f.material, runtime: runtime,
                verifyCurrent: { hostChecks += 1; if hostChecks == 2 { throw Fault.host } }) { selected, _ in reads += 1; return selected.bytes }) {
                    XCTAssertTrue($0 is Fault)
                }
            XCTAssertEqual(reads, 1); XCTAssertEqual(hostChecks, 2)
            try f.machine().retainedSetupPolicySnapshot(owner: runtime.setup.owner, candidate: f.candidate).requireSame(as: snapshot)
        }
    }
}
