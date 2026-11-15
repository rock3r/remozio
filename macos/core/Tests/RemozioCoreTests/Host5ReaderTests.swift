import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Synthetic future bytes exercise current readers. These fixtures grant no native writer or startup authority.
enum Host5ReaderFixture {
    static let limits = try! CBORLimits(maxBytes: 4_194_304, maxDepth: 4, maxItems: 4096)
    static func map(_ bytes: Data) throws -> [UInt64: CBORValue] {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits) else { throw RuntimeActivationError.invalidPlan }
        return fields
    }
    static func bytes(_ fields: [UInt64: CBORValue]) throws -> Data { try DeterministicCBOR.encode(.map(fields), limits: limits) }
    static func host(_ previous: InstalledAuthorityCommandConfiguration) throws -> Data {
        var fields = try map(previous.canonicalBytes); fields[0] = .unsigned(5)
        fields[11] = .text(try AuthorityMaintenanceChannelScope.serviceName(accountID: previous.command.accountID))
        return try bytes(fields)
    }
    static func activation(_ bytes: Data) throws -> Data {
        var fields = try map(bytes)
        guard case .bytes(let raw) = fields[3] else { throw RuntimeActivationError.invalidPlan }
        fields[3] = .bytes(try host(.decode(raw))); return try self.bytes(fields)
    }
}

final class Host5ReaderTests: XCTestCase {
    func testHost5PreservesOptionalFlagsAndRejectsMalformedFixedService() throws {
        let f = try RuntimeActivationFixture(nativeConsumerHosts: true), base = f.plan.host
        for readiness in [false, true] {
            let legacy = try InstalledAuthorityCommandConfiguration(machineDirectory: base.machineDirectory,
                installationID: base.installationID, releaseDigest: base.releaseDigest, codePolicy: base.codePolicy,
                command: base.command, label: base.label, plistName: base.plistName, jobPlacement: base.jobPlacement,
                gatewaySettingsControlEnabled: true, installedReadinessEnabled: readiness)
            let bytes = try Host5ReaderFixture.host(legacy), decoded = try InstalledAuthorityCommandConfiguration.decode(bytes)
            XCTAssertEqual(decoded.canonicalBytes, bytes); XCTAssertEqual(decoded.formatVersion, 5)
            XCTAssertTrue(decoded.maintenanceChannelEnabled); XCTAssertEqual(decoded.installedReadinessEnabled, readiness)
            XCTAssertTrue(decoded.gatewaySettingsControlEnabled)
            for wrong in [CBORValue.text("dev.remozio.foreign.maintenance"), .bytes(Data()), .null] {
                var fields = try Host5ReaderFixture.map(bytes); fields[11] = wrong
                XCTAssertThrowsError(try InstalledAuthorityCommandConfiguration.decode(Host5ReaderFixture.bytes(fields)))
            }
            var missing = try Host5ReaderFixture.map(bytes); missing[11] = nil
            XCTAssertThrowsError(try InstalledAuthorityCommandConfiguration.decode(Host5ReaderFixture.bytes(missing)))
            var extra = try Host5ReaderFixture.map(bytes); extra[12] = .boolean(true)
            XCTAssertThrowsError(try InstalledAuthorityCommandConfiguration.decode(Host5ReaderFixture.bytes(extra)))
        }
    }
    func testOrdinaryPlanReconstructsOnlyTheExactAuthorityMaintenanceAddress() throws {
        let f = try RuntimeActivationFixture(), before = try XCTUnwrap(f.machine.inventory()).canonicalBytes
        let bytes = try Host5ReaderFixture.activation(f.plan.encoded), plan = try RuntimeActivationPlan.decode(bytes)
        XCTAssertEqual(try plan.encoded, bytes); XCTAssertTrue(plan.host.maintenanceChannelEnabled)
        XCTAssertEqual(plan.authorityJob.machServices, f.plan.authorityJob.machServices.union([
            try AuthorityMaintenanceChannelScope.serviceName(accountID: f.account.accountID)]))
        XCTAssertEqual(plan.transportJob.bytes, f.plan.transportJob.bytes)
        let fields = try XCTUnwrap(PropertyListSerialization.propertyList(from: plan.authorityJob.bytes, options: [], format: nil) as? [String: Any])
        XCTAssertEqual(Set(try XCTUnwrap(fields["MachServices"] as? [String: Bool]).keys), plan.authorityJob.machServices)
        XCTAssertEqual(try XCTUnwrap(f.machine.inventory()).canonicalBytes, before)
    }
    func testRetainedPlanAndCompatibilityProjectionPreserveHost5AndHistoricalBytes() throws {
        let f = try RetainedSetupActivationArchiveTests.Fixture(), original = try f.bytes()
        let bytes = try Host5ReaderFixture.activation(original), archive = try RuntimeRetainedSetupActivationArchive.decode(bytes)
        let plan = try RuntimeRetainedSetupActivationPlan(archive: archive), old = try RuntimeRetainedSetupActivationPlan.decode(original)
        XCTAssertEqual(try plan.encoded, bytes); XCTAssertTrue(plan.host.maintenanceChannelEnabled)
        XCTAssertEqual(plan.authorityJob.machServices, old.authorityJob.machServices.union([
            try AuthorityMaintenanceChannelScope.serviceName(accountID: plan.accountID)]))
        XCTAssertEqual(plan.transportJob.bytes, old.transportJob.bytes)
        XCTAssertEqual(try RuntimeActivationCompatibilityProjection.decode(bytes).host.canonicalBytes, archive.host.canonicalBytes)
        XCTAssertEqual(try f.bytes(), original)
    }
    func testNestedSourceAndReleaseConfigurationReadersKeepExactHost5Bytes() throws {
        try MachineUpdateReplacementTests.withOwnedConfigurationPublicationLockFixture { f in
            let value = try XCTUnwrap(f.archive.configuration(accountID: f.accountID)), source = value.source
            let host = try InstalledAuthorityCommandConfiguration.decode(Host5ReaderFixture.host(source.host))
            let changed = RuntimeReleaseConfigurationSource(host: host, transport: source.transport, gateway: source.gateway, clients: source.clients)
            XCTAssertEqual(try RuntimeReleaseConfigurationSource.decode(changed.encoded).host.canonicalBytes, host.canonicalBytes)
            var fields = try Host5ReaderFixture.map(value.startup.encoded)
            let selected = try Host5ReaderFixture.host(value.startup.host); fields[5] = .bytes(selected)
            let bytes = try Host5ReaderFixture.bytes(fields), decoded = try RuntimeReleaseConfigurationPlan.decode(bytes)
            XCTAssertEqual(decoded.host.canonicalBytes, selected); XCTAssertEqual(try decoded.encoded, bytes)
        }
    }
    func testCompletionArchiveAndConfigurationReadersKeepHost5WithoutNormalizingIt() throws {
        let f = try RetainedSetupCompletionConfigurationTests.Fixture()
        let futureActivation = try Host5ReaderFixture.activation(f.completion.activationBytes)
        let completed = try RuntimeRetainedSetupCompletionArchive.decode(f.completion.replacing(activation: futureActivation))
        XCTAssertEqual(try completed.originalActivation().host.formatVersion, 5)
        var fields = f.fields; let host = try Host5ReaderFixture.host(f.host); fields[4] = .bytes(host)
        let bytes = try Host5ReaderFixture.bytes(fields), decoded = try RuntimeRetainedSetupCompletionConfiguration.decode(bytes)
        XCTAssertEqual(decoded.host.canonicalBytes, host); XCTAssertEqual(try decoded.encoded, bytes)
    }
    func testCompatibilityRequiresTheEffectiveHost5ReaderWithoutInventingAWriter() throws {
        let f = try RuntimeActivationFixture(nativeConsumerHosts: true)
        let plan = try RuntimeActivationPlan.decode(Host5ReaderFixture.activation(f.plan.encoded))
        try f.machine.retainRuntimeActivation(plan)
        let snapshot = try RuntimeReleaseCompatibilitySnapshot.capture(machine: f.machine)
        for role in [AuthorityCodeRole.authority, .setupController] {
            let entry = try XCTUnwrap(snapshot.requirements.formats.first { $0.role == role && $0.name == "authority.command-host-config" })
            XCTAssertEqual(entry.readVersions, [5]); XCTAssertTrue(entry.writeVersions.isEmpty)
        }
        let missing = try NativeHostReleaseFixture.make(policy: f.plan.host.codePolicy)
        XCTAssertThrowsError(try snapshot.validate(missing, policy: f.plan.host.codePolicy, machine: f.machine))
        let reader = try NativeHostReleaseFixture.make(policy: f.plan.host.codePolicy) { component in
            let formats = try component.formats.map { item in
                item.name == "authority.command-host-config" ? try ReleaseFormat(name: item.name, readers: item.readers.union([5]), writers: item.writers) : item
            }
            return try .init(role: component.role, identifier: component.identifier, generation: component.generation,
                relativePath: component.relativePath, codeDirectoryHash: component.codeDirectoryHash, build: component.build,
                teamID: component.teamID, formats: formats)
        }
        try snapshot.validate(reader, policy: f.plan.host.codePolicy, machine: f.machine)
    }
    func testPublicProducerKeepsLegacyBytesAndNativePublisherRefusesFutureHost5() throws {
        let f = try RuntimeActivationFixture(), host = f.plan.host
        let legacy = try InstalledAuthorityCommandConfiguration(machineDirectory: host.machineDirectory, installationID: host.installationID,
            releaseDigest: host.releaseDigest, codePolicy: host.codePolicy, command: host.command, label: host.label,
            plistName: host.plistName, jobPlacement: host.jobPlacement)
        XCTAssertEqual(legacy.canonicalBytes, host.canonicalBytes); XCTAssertFalse(legacy.maintenanceChannelEnabled)
        XCTAssertFalse(InstalledAuthorityCommandConfiguration.writerSupportedVersions.contains(5))
        let future = try RuntimeActivationPlan.decode(Host5ReaderFixture.activation(f.plan.encoded))
        let root = URL(fileURLWithPath: "/private/tmp/remozio-host5-no-writer-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o755])
        defer { try? FileManager.default.removeItem(at: root) }
        let runtime = try ProtectedSetupDirectory(anchor: root.path, relativePath: "runtime", owner: getuid())
        let jobs = try ProtectedSetupDirectory(anchor: root.path, relativePath: "jobs", owner: getuid(), visibility: .sharedMetadata)
        defer { jobs.close(); runtime.close() }
        XCTAssertThrowsError(try RuntimeActivationFiles.publish(plan: future, privateState: runtime, jobs: jobs, owner: getuid(), verifyCurrent: { XCTFail("Future host cannot enter the old publisher") }))
        XCTAssertFalse(FileManager.default.fileExists(atPath: runtime.path + "/command-host.cbor"))
    }
}
