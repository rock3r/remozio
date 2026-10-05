import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class AuthorityServiceTests: XCTestCase {
    private func configuration(_ fixture: Fixture, wrongScope: Bool = false) throws -> AuthorityServiceConfiguration {
        try AuthorityServiceConfiguration(macID: Data(repeating: wrongScope ? 9 : 1, count: 16),
            accountID: Data(repeating: 2, count: 16), journalDirectory: fixture.directory,
            serviceName: "dev.remozio.authority.test", teamID: "ABCDEFGHIJ",
            transportIdentifier: "dev.remozio.transport", transportHashes: [Data(repeating: 3, count: 20)], transportUID: 501)
    }
    private func database(_ fixture: Fixture, initialize: Bool = true, configure: Bool = true, configureCode: Bool = true) throws -> sending JournalDatabase {
        let anchor = fixture.root.path
        let limits = try CBORLimits(maxBytes: 16384, maxDepth: 8, maxItems: 512)
        let database = try JournalDatabase(lease: ProtectedJournalLease(anchor: anchor, relativeDirectory: "store", owner: getuid()),
            macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16),
            recordLimits: limits, descriptorLimits: limits, decisionLimits: limits,
            maximumConsumptions: 10, busyMilliseconds: 100, initialize: initialize)
        if initialize && configure {
            let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1)
            _ = try database.write { try $0.configureApprovalAuthority(capabilities: ContractCapabilities(contracts: [contract: []]), allowedContracts: [contract]) }
        }
        if initialize && configureCode {
            _ = try database.write {
                try $0.installCodePolicy(AuthorityCodePolicy(entries: [AuthorityCodeEntry(role: .transport, teamID: "ABCDEFGHIJ",
                    identifier: "dev.remozio.transport", installedGeneration: 1, minimumGeneration: 1,
                    codeDirectoryHash: Data(repeating: 3, count: 20), active: true)]), expectedRevision: nil)
            }
        }
        return database
    }
    private func assertReleased(_ fixture: Fixture) throws {
        let reopened = try database(fixture, initialize: false)
        try reopened.close()
    }
    func testServiceClosesSuppliedJournalOwner() throws {
        let fixture = try Fixture()
        let journal = AuthorityJournal(database: try database(fixture))
        let service = try AuthorityService(configuration: configuration(fixture), journal: journal)
        XCTAssertFalse(try journal.read { try $0.approvalTrustSnapshot().allowedContracts.isEmpty })
        try service.close()
        XCTAssertThrowsError(try journal.read { try $0.approvalTrustSnapshot().revision }) {
            XCTAssertEqual($0 as? JournalDatabaseError, .closed)
        }
        try assertReleased(fixture)
    }
    func testCloseBeforeStartReleasesLeaseAndPreventsStart() throws {
        let fixture = try Fixture()
        let service = try AuthorityService(configuration: configuration(fixture), database: database(fixture))
        XCTAssertThrowsError(try fixture.lease()) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
        try service.close(); try service.close()
        XCTAssertThrowsError(try service.start()) { XCTAssertEqual($0 as? AuthorityXPCEndpointError, .unavailable) }
        try assertReleased(fixture)
    }
    func testFailedStartRetiresInstanceAndReleasesLease() throws {
        guard geteuid() != 0 else { throw XCTSkip("Requires normal user") }
        let fixture = try Fixture()
        let service = try AuthorityService(configuration: configuration(fixture), database: database(fixture))
        XCTAssertThrowsError(try service.start()) { XCTAssertEqual($0 as? AuthorityXPCEndpointError, .unavailable) }
        try assertReleased(fixture)
        XCTAssertThrowsError(try service.start())
        try service.close()
    }
    func testWrongScopeConstructionReleasesLease() throws {
        let fixture = try Fixture()
        XCTAssertThrowsError(try AuthorityService(configuration: configuration(fixture, wrongScope: true), database: database(fixture))) {
            XCTAssertEqual($0 as? AuthorityXPCEndpointError, .invalidConfiguration)
        }
        try assertReleased(fixture)
    }
    func testUnconfiguredStoreIsNotInitializedByService() throws {
        let fixture = try Fixture()
        XCTAssertThrowsError(try AuthorityService(configuration: configuration(fixture), database: database(fixture, configure: false))) {
            XCTAssertEqual($0 as? EnrollmentJournalError, .unconfigured)
        }
        let reopened = try database(fixture, initialize: false)
        XCTAssertThrowsError(try reopened.read { try $0.approvalTrustSnapshot() }) {
            XCTAssertEqual($0 as? EnrollmentJournalError, .unconfigured)
        }
        try reopened.close()
    }
    func testServiceRejectsAbsentCodePolicyAndReleasesStorageWithoutInitializingIt() throws {
        let fixture = try Fixture()
        XCTAssertThrowsError(try AuthorityService(configuration: configuration(fixture), database: database(fixture, configureCode: false))) {
            XCTAssertEqual($0 as? AuthorityTransportAccessError, .unconfigured)
        }
        let reopened = try database(fixture, initialize: false)
        XCTAssertNil(try reopened.read { try $0.codePolicy() })
        try reopened.close()
    }

    func testDeinitializationReleasesLease() throws {
        let fixture = try Fixture()
        var service: AuthorityService? = try AuthorityService(configuration: configuration(fixture), database: database(fixture))
        XCTAssertNotNil(service)
        service = nil
        try assertReleased(fixture)
    }
    private final class Fixture {
        let root: URL
        var directory: String { root.appendingPathComponent("store").path }
        var path: String { directory + "/journal.sqlite" }
        init() throws {
            guard let canonical = realpath(FileManager.default.temporaryDirectory.path, nil) else { throw JournalLeaseError.system(errno) }
            defer { free(canonical) }
            root = URL(fileURLWithPath: String(cString: canonical)).appendingPathComponent(UUID().uuidString)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            for name in ["writer.lock", "journal.sqlite"] {
                let fd = Darwin.open(directory + "/" + name, O_CREAT | O_EXCL | O_WRONLY, 0o600)
                guard fd >= 0 else { throw JournalLeaseError.system(errno) }
                Darwin.close(fd)
            }
        }
        deinit { try? FileManager.default.removeItem(at: root) }
        func lease() throws -> ProtectedJournalLease { try ProtectedJournalLease(anchor: root.path, relativeDirectory: "store", owner: getuid()) }
    }
}
