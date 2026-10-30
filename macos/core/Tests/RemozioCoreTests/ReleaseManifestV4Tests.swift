import Foundation
import XCTest
import RemozioProtocol
@testable import RemozioCore

final class ReleaseManifestV4Tests: XCTestCase {
    private func component(_ count: Int) throws -> ReleaseComponent {
        try .init(role: .app, identifier: "dev.remozio.app", generation: 1,
            relativePath: "Contents/MacOS/Remozio", codeDirectoryHash: nil, build: "1", teamID: "ABCDEFGHIJ",
            formats: (0..<count).map { try ReleaseFormat(name: "format.\($0)", readers: [1], writers: [1]) })
    }

    func testExtendedFormatListUsesSchemaFourWithoutChangingLegacyBounds() throws {
        let legacy = try ReleaseManifest(release: "1", build: "1", components: [component(32)])
        XCTAssertEqual(legacy.schemaVersion, 1)
        let value = try ReleaseManifest(release: "1", build: "1", components: [component(64)])
        XCTAssertEqual(value.schemaVersion, 4)
        let bytes = try value.canonicalBytes
        XCTAssertEqual(try ReleaseManifest.decode(bytes), value)
        XCTAssertThrowsError(try component(129))
        guard case .map(let root) = try DeterministicCBOR.decode(bytes, limits: ReleaseManifest.limits) else { return XCTFail() }
        for schema in [UInt64(1), 2, 3] {
            var downgraded = root; downgraded[0] = .unsigned(schema)
            if schema == 1 { downgraded.removeValue(forKey: 6) }
            XCTAssertThrowsError(try ReleaseManifest.decode(DeterministicCBOR.encode(.map(downgraded), limits: ReleaseManifest.limits))) {
                XCTAssertEqual($0 as? ReleaseManifestError, .corruptData)
            }
        }
        var future = root; future[0] = .unsigned(6)
        XCTAssertThrowsError(try ReleaseManifest.decode(DeterministicCBOR.encode(.map(future), limits: ReleaseManifest.limits))) {
            XCTAssertEqual($0 as? ReleaseManifestError, .unsupportedSchema)
        }
    }

    func testSchemaFourRetainsItsCanonicalFormEvenWithFewFormats() throws {
        let original = try ReleaseManifest(release: "1", build: "1", components: [component(1)])
        guard case .map(var root) = try DeterministicCBOR.decode(original.canonicalBytes, limits: ReleaseManifest.limits) else { return XCTFail() }
        root[0] = .unsigned(4); root[6] = .array([])
        let bytes = try DeterministicCBOR.encode(.map(root), limits: ReleaseManifest.limits)
        let decoded = try ReleaseManifest.decode(bytes)
        XCTAssertEqual(decoded.schemaVersion, 4)
        XCTAssertEqual(try decoded.canonicalBytes, bytes)
    }

    func testRetainedExtendedFormatsStillRequireEveryExactVersion() throws {
        let app = try component(64)
        let hash = Data(repeating: 7, count: 20)
        let evidence = SignedReleaseEvidence(manifest: try .init(release: "1", build: "1", components: [app]),
            codeDirectoryHashes: [.app: hash])
        let policy = try AuthorityCodePolicy(entries: [AuthorityCodeEntry(role: .app, teamID: "ABCDEFGHIJ",
            identifier: app.identifier, installedGeneration: 1, minimumGeneration: 1, codeDirectoryHash: hash, active: true)])
        let formats = try app.formats.map { try RetainedReleaseFormat(role: .app, name: $0.name, readVersions: [1], writeVersions: [1]) }
        XCTAssertNoThrow(try ReleaseCompatibilityPreflight.validate(evidence, policy: policy,
            requirements: .init(formats: formats, requests: [])))
        let missing = try RetainedReleaseFormat(role: .app, name: "format.63", readVersions: [2])
        XCTAssertThrowsError(try ReleaseCompatibilityPreflight.validate(evidence, policy: policy,
            requirements: .init(formats: formats.filter { $0.name != missing.name } + [missing], requests: []))) {
            XCTAssertEqual($0 as? ReleaseCompatibilityError, .missingReader(.app, "format.63", 2))
        }
        let extra = try RetainedReleaseFormat(role: .app, name: "format.extra", readVersions: [1])
        XCTAssertThrowsError(try ReleaseCompatibilityPreflight.validate(evidence, policy: policy,
            requirements: .init(formats: formats + [extra], requests: []))) {
            XCTAssertEqual($0 as? ReleaseCompatibilityError, .missingFormat(.app, "format.extra"))
        }
    }
    func testExtendedManifestPreservesRequestFeaturesAndRejectsMissingFeatures() throws {
        let base = try component(33)
        let contract = try ReleaseRequestContract(kind: 0, wireVersion: 1, schemaVersion: 3,
            actions: [0, 2], purposes: [.issuedRequest, .biometricAuthorization], features: [2, 5])
        let app = try ReleaseComponent(role: base.role, identifier: base.identifier, generation: base.generation,
            relativePath: base.relativePath, codeDirectoryHash: nil, build: base.build, teamID: base.teamID,
            formats: base.formats, requests: [contract])
        let manifest = try ReleaseManifest(release: "1", build: "1", components: [app])
        XCTAssertEqual(manifest.schemaVersion, 4)
        XCTAssertEqual(try ReleaseManifest.decode(manifest.canonicalBytes).components[0].requests, [contract])
        guard case .map(var root) = try DeterministicCBOR.decode(manifest.canonicalBytes, limits: ReleaseManifest.limits),
              case .array(var components) = root[5], case .map(var c) = components[0],
              case .array(var requests) = c[8], case .map(var request) = requests[0] else { return XCTFail() }
        request.removeValue(forKey: 5); requests[0] = .map(request); c[8] = .array(requests)
        components[0] = .map(c); root[5] = .array(components)
        XCTAssertThrowsError(try ReleaseManifest.decode(DeterministicCBOR.encode(.map(root), limits: ReleaseManifest.limits)))
    }

}
