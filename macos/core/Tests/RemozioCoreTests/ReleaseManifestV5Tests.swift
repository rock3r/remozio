import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class ReleaseManifestV5Tests: XCTestCase {
    private func component(_ count: Int, role: AuthorityCodeRole = .app, longNames: Bool = false) throws -> ReleaseComponent {
        try .init(role: role, identifier: "dev.remozio.component.\(role.rawValue)", generation: 1,
            relativePath: "Contents/MacOS/Component\(role.rawValue)",
            codeDirectoryHash: role == .app ? nil : Data(repeating: 7, count: 20), build: "1", teamID: "ABCDEFGHIJ",
            formats: (0..<count).map { index in
                let prefix = "format.\(index)"
                let name = longNames ? prefix + String(repeating: "x", count: 255 - prefix.utf8.count) : prefix
                return try ReleaseFormat(name: name, readers: [1, 2], writers: [2])
            })
    }
    func testLargerCatalogueUsesSchemaFiveAndCannotDowngradeToEarlierBounds() throws {
        for count in [65, 128] {
            let manifest = try ReleaseManifest(release: "1", build: "1", components: [component(count)])
            XCTAssertEqual(manifest.schemaVersion, 5)
            XCTAssertEqual(try ReleaseManifest.decode(manifest.canonicalBytes), manifest)
            guard case .map(let root) = try DeterministicCBOR.decode(manifest.canonicalBytes, limits: ReleaseManifest.limits) else { return XCTFail() }
            for version in UInt64(1)...4 {
                var changed = root; changed[0] = .unsigned(version)
                if version == 1 { changed.removeValue(forKey: 6) }
                XCTAssertThrowsError(try ReleaseManifest.decode(DeterministicCBOR.encode(.map(changed), limits: ReleaseManifest.limits)))
            }
            var future = root; future[0] = .unsigned(6)
            XCTAssertThrowsError(try ReleaseManifest.decode(DeterministicCBOR.encode(.map(future), limits: ReleaseManifest.limits))) {
                XCTAssertEqual($0 as? ReleaseManifestError, .unsupportedSchema)
            }
        }
        XCTAssertThrowsError(try component(129))
    }
    func testLargerCatalogueKeepsTheGlobalByteBudgetAndCanonicalSmallSchemaFive() throws {
        let small = try ReleaseManifest(release: "1", build: "1", components: [component(1)])
        guard case .map(var root) = try DeterministicCBOR.decode(small.canonicalBytes, limits: ReleaseManifest.limits) else { return XCTFail() }
        root[0] = .unsigned(5); root[6] = .array([])
        let bytes = try DeterministicCBOR.encode(.map(root), limits: ReleaseManifest.limits)
        let decoded = try ReleaseManifest.decode(bytes)
        XCTAssertEqual(decoded.schemaVersion, 5); XCTAssertEqual(try decoded.canonicalBytes, bytes)
        XCTAssertEqual(ReleaseManifest.maximumBytes, 65536)
        XCTAssertThrowsError(try ReleaseManifest(release: "1", build: "1", components: [
            component(128, longNames: true), component(128, role: .authority, longNames: true)]))
    }
    func testLargerCatalogueKeepsTheGlobalItemBudget() throws {
        let values = try AuthorityCodeRole.allCases.map { try component(128, role: $0) }
        XCTAssertThrowsError(try ReleaseManifest(release: "1", build: "1", components: values)) {
            XCTAssertEqual($0 as? CBORError, .limitExceeded(.items))
        }
    }
    func testLargerCatalogueRequiresEveryExactReaderAndWriter() throws {
        let app = try component(128), hash = Data(repeating: 7, count: 20)
        let evidence = SignedReleaseEvidence(manifest: try .init(release: "1", build: "1", components: [app]),
            codeDirectoryHashes: [.app: hash])
        let policy = try AuthorityCodePolicy(entries: [AuthorityCodeEntry(role: .app, teamID: "ABCDEFGHIJ",
            identifier: app.identifier, installedGeneration: 1, minimumGeneration: 1, codeDirectoryHash: hash, active: true)])
        let formats = try app.formats.map { try RetainedReleaseFormat(role: .app, name: $0.name, readVersions: [1, 2], writeVersions: [2]) }
        try ReleaseCompatibilityPreflight.validate(evidence, policy: policy, requirements: .init(formats: formats, requests: []))
        for writer in [false, true] {
            let wrong = try RetainedReleaseFormat(role: .app, name: "format.127", readVersions: writer ? [1] : [3], writeVersions: writer ? [1] : [])
            XCTAssertThrowsError(try ReleaseCompatibilityPreflight.validate(evidence, policy: policy,
                requirements: .init(formats: formats.filter { $0.name != wrong.name } + [wrong], requests: []))) {
                XCTAssertEqual($0 as? ReleaseCompatibilityError, writer ? .missingWriter(.app, wrong.name, 1) : .missingReader(.app, wrong.name, 3))
            }
        }
        XCTAssertThrowsError(try RetainedReleaseRequirements(formats: formats + [
            .init(role: .app, name: "format.extra", readVersions: [1])], requests: []))
    }
}
