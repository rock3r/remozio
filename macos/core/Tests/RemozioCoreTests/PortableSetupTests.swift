import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class PortableSetupTests: XCTestCase {
    private let limits = try! CBORLimits(maxBytes: 100_000, maxDepth: 8, maxItems: 256)
    private static let pem = Result { () throws -> String in
        let process = Process(), pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        process.arguments = ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"]
        process.standardOutput = pipe; process.standardError = FileHandle.nullDevice
        try process.run()
        let bytes = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw PortableSetupError.rejected }
        return String(decoding: bytes, as: UTF8.self)
    }
    private func defaults() throws -> SharedSetupDefaults {
        try SharedSetupDefaults(
            presence: PresenceConfiguration(idleMilliseconds: 120_000, observationLifetimeMilliseconds: 5_000, unavailableGraceMilliseconds: 30_000),
            wake: GatewayWakePolicy(maximumEntries: 32, maximumAttempts: 3, minimumEnrollmentIntervalMillis: 1_000, maximumLifetimeMillis: 60_000, maximumTTLSeconds: 60),
            delivery: GatewayDeliveryPolicy(maximumFlights: 4, minimumSendIntervalMillis: 100))
    }
    private func full() throws -> PortableSetup {
        try PortableSetup(defaults: defaults(),
            fcm: SetupFCMConfiguration(project: "synthetic-project", clientEmail: "fixture@fixture.iam.gserviceaccount.com", privateKeyID: "fixture-key", privateKeyPEM: Self.pem.get()),
            cloudflare: SetupCloudflareConfiguration(accountID: String(repeating: "a", count: 32), zoneID: String(repeating: "b", count: 32), dnsSuffix: "remozio.example.invalid", apiToken: "synthetic-token-only"))
    }
    private func value(_ setup: PortableSetup) throws -> [UInt64: CBORValue] {
        guard case let .map(fields) = try DeterministicCBOR.decode(setup.canonicalBytes(), limits: limits) else { throw PortableSetupError.rejected }
        return fields
    }
    private func reject(_ fields: [UInt64: CBORValue], file: StaticString = #filePath, line: UInt = #line) throws {
        let bytes = try DeterministicCBOR.encode(.map(fields), limits: limits)
        XCTAssertThrowsError(try PortableSetup(canonicalBytes: bytes), file: file, line: line)
    }
    func testEncryptedRoundTripPreservesSelectedConfigurationWithoutApplyingIt() throws {
        let original = try full()
        let file = try original.encryptedFile(password: "synthetic export password")
        let restored = try PortableSetup(encryptedFile: file, password: "synthetic export password")
        XCTAssertEqual(try original.canonicalBytes(), try restored.canonicalBytes())
        XCTAssertEqual(restored.defaults.presence.idleMilliseconds, 120_000)
        XCTAssertEqual(restored.defaults.wake.maximumAttempts, 3)
        XCTAssertEqual(restored.defaults.delivery.maximumFlights, 4)
        XCTAssertNoThrow(try restored.fcm?.serviceAccount())
        XCTAssertThrowsError(try PortableSetup(encryptedFile: file, password: "wrong"))
    }
    func testPreviewShowsScopeAndCategoriesWithoutSecretValues() throws {
        let setup = try full(), preview = setup.preview
        XCTAssertEqual(preview.categories, [.sharedDefaults, .fcmCredentials, .cloudflareProvisioning])
        XCTAssertEqual(preview.firebaseProject, "synthetic-project")
        XCTAssertEqual(preview.dnsSuffix, "remozio.example.invalid")
        for rendered in [String(reflecting: setup), String(reflecting: setup.fcm!), String(reflecting: setup.cloudflare!), String(reflecting: preview)] {
            XCTAssertFalse(rendered.contains("synthetic-token-only"))
            XCTAssertFalse(rendered.contains("PRIVATE KEY"))
            XCTAssertFalse(rendered.contains("fixture-key"))
        }
    }
    func testSettingsOnlyExportDoesNotInventProviderCredentials() throws {
        let setup = try PortableSetup(defaults: defaults())
        let restored = try PortableSetup(canonicalBytes: setup.canonicalBytes())
        XCTAssertEqual(restored.preview.categories, [.sharedDefaults])
        XCTAssertNil(restored.fcm); XCTAssertNil(restored.cloudflare)
        XCTAssertNil(restored.preview.firebaseProject); XCTAssertNil(restored.preview.cloudflareAccount)
        let fields = try value(restored)
        XCTAssertEqual(fields[2], .null); XCTAssertEqual(fields[3], .null)
    }
    func testRejectsUnknownFieldsAtEveryMapBoundary() throws {
        let original = try value(full())
        var root = original; root[4] = .text("forbidden authority state"); try reject(root)
        for key: UInt64 in [1, 2, 3] {
            var changed = original
            guard case var .map(nested) = changed[key] else { return XCTFail("fixture map missing") }
            nested[99] = .text("forbidden device state"); changed[key] = .map(nested)
            try reject(changed)
        }
        root = original; root.removeValue(forKey: 2); try reject(root)
        root = original; root[0] = .unsigned(2); try reject(root)
    }
    func testRejectsInvalidSettingsAndIntegerOverflow() throws {
        let original = try value(full())
        for (group, index, replacement): (UInt64, Int, CBORValue) in [
            (0, 0, .unsigned(0)), (0, 1, .unsigned(0)), (1, 0, .unsigned(.max)),
            (1, 1, .unsigned(33)), (1, 4, .unsigned(.max)), (2, 0, .unsigned(65)),
            (2, 3, .unsigned(1)), (0, 2, .boolean(false)),
        ] {
            var changed = original
            guard case var .map(settings) = changed[1], case var .array(values) = settings[group] else { return XCTFail("fixture settings missing") }
            values[index] = replacement; settings[group] = .array(values); changed[1] = .map(settings)
            try reject(changed)
        }
    }
    func testRejectsInvalidProviderScopesAndCredentialContainers() throws {
        for suffix in ["", ".invalid", "a..invalid", "-a.invalid", "a-.invalid", "https://a.invalid", "a.invalid/path", "a.invalid\n"] {
            XCTAssertThrowsError(try SetupCloudflareConfiguration(accountID: String(repeating: "a", count: 32), zoneID: String(repeating: "b", count: 32), dnsSuffix: suffix, apiToken: "synthetic"))
        }
        XCTAssertThrowsError(try SetupCloudflareConfiguration(accountID: "bad", zoneID: String(repeating: "b", count: 32), dnsSuffix: "example.invalid", apiToken: "synthetic"))
        XCTAssertThrowsError(try SetupCloudflareConfiguration(accountID: String(repeating: "a", count: 32), zoneID: String(repeating: "b", count: 32), dnsSuffix: "example.invalid", apiToken: "token\n"))
        XCTAssertThrowsError(try SetupFCMConfiguration(project: "bad/path", clientEmail: "a@b", privateKeyID: "key", privateKeyPEM: Self.pem.get()))
        XCTAssertThrowsError(try SetupFCMConfiguration(project: "synthetic", clientEmail: "a@b", privateKeyID: "key", privateKeyPEM: "not a key"))
        var fields = try value(full()); fields[2] = .bytes(Data("opaque credential blob".utf8)); try reject(fields)
    }
    func testRejectsOversizedTrailingAndDuplicatePayloadData() throws {
        XCTAssertThrowsError(try PortableSetup(canonicalBytes: Data(repeating: 0, count: 65_537)))
        let bytes = try PortableSetup(defaults: defaults()).canonicalBytes()
        XCTAssertThrowsError(try PortableSetup(canonicalBytes: bytes + Data([0])))
        // A duplicate root key cannot be represented by the typed map encoder.
        var duplicate = bytes; duplicate[0] = 0xa5; duplicate.append(contentsOf: [0, 1])
        XCTAssertThrowsError(try PortableSetup(canonicalBytes: duplicate))
    }
}
