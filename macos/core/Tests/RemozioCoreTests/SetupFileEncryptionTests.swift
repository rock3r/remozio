import Foundation
import XCTest
@testable import RemozioCore

final class SetupFileEncryptionTests: XCTestCase {
    private struct Fixture: Decodable { let password: String; let plaintext: String; let compact: String }
    private func fixture() throws -> Fixture {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "setup-jwe", withExtension: "json", subdirectory: "Fixtures"))
        return try JSONDecoder().decode(Fixture.self, from: Data(contentsOf: url))
    }
    private func base64(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
    private func replacing(_ compact: String, index: Int, with value: String) -> Data {
        var parts = compact.components(separatedBy: "."); parts[index] = value
        return Data(parts.joined(separator: ".").utf8)
    }
    private func header(_ changes: [String: Any]) throws -> Data {
        let f = try fixture()
        var fields: [String: Any] = ["alg": "PBES2-HS512+A256KW", "enc": "A256GCM", "p2c": 220_000,
                                     "p2s": base64(Data(0..<32)), "typ": "remozio-setup-v1+jwe"]
        fields.merge(changes) { _, new in new }
        return replacing(f.compact, index: 0, with: base64(try JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys])))
    }
    func testIndependentNodeFixtureOpens() throws {
        let f = try fixture()
        XCTAssertEqual(try SetupFileEncryption.open(Data(f.compact.utf8), password: f.password), Data(f.plaintext.utf8))
    }
    func testRoundTripUsesFreshRandomnessAndPreservesUnicodePassword() throws {
        let payload = Data("synthetic configuration".utf8)
        let password = "password 🔐 e\u{301}"
        let first = try SetupFileEncryption.seal(payload, password: password)
        let second = try SetupFileEncryption.seal(payload, password: password)
        XCTAssertNotEqual(first, second)
        XCTAssertEqual(try SetupFileEncryption.open(first, password: password), payload)
        XCTAssertThrowsError(try SetupFileEncryption.open(first, password: "password 🔐 é"))
    }
    func testWrongPasswordAndModifiedEncryptedPartsFail() throws {
        let f = try fixture()
        XCTAssertThrowsError(try SetupFileEncryption.open(Data(f.compact.utf8), password: "wrong"))
        for index in 1...4 {
            var value = Array(f.compact.components(separatedBy: ".")[index].utf8)
            value[0] = value[0] == 65 ? 66 : 65
            XCTAssertThrowsError(try SetupFileEncryption.open(replacing(f.compact, index: index, with: String(decoding: value, as: UTF8.self)), password: f.password))
        }
        // A valid but changed header still fails authentication.
        XCTAssertThrowsError(try SetupFileEncryption.open(header(["p2c": 220_001]), password: f.password))
    }
    func testRejectsUnboundedWorkAndUnsupportedHeadersBeforeCrypto() throws {
        for change: [String: Any] in [["p2c": 0], ["p2c": -1], ["p2c": 219_999], ["p2c": 1_000_001],
                                      ["p2c": true], ["p2c": "220000"], ["p2c": 220000.5],
                                      ["alg": "dir"], ["enc": "A128GCM"], ["typ": "remozio-setup-v2+jwe"],
                                      ["zip": "DEF"], ["p2s": base64(Data(repeating: 0, count: 8))]] {
            XCTAssertThrowsError(try SetupFileEncryption.validate(header(change)))
        }
    }
    func testRejectsDuplicateHeadersAndNonCanonicalEncoding() throws {
        let f = try fixture()
        let duplicate = "{\"alg\":\"dir\",\"alg\":\"PBES2-HS512+A256KW\",\"enc\":\"A256GCM\",\"p2c\":220000,\"p2s\":\"\(base64(Data(0..<32)))\",\"typ\":\"remozio-setup-v1+jwe\"}"
        XCTAssertThrowsError(try SetupFileEncryption.validate(replacing(f.compact, index: 0, with: base64(Data(duplicate.utf8)))))
        XCTAssertThrowsError(try SetupFileEncryption.validate(Data((f.compact + "=").utf8)))
        XCTAssertThrowsError(try SetupFileEncryption.validate(Data((f.compact + ".extra").utf8)))
        for index in 1...4 {
            XCTAssertThrowsError(try SetupFileEncryption.validate(replacing(f.compact, index: index, with: index == 3 ? "" : "AA")))
        }
    }
    func testMaximumPayloadRoundTrips() throws {
        let payload = Data(repeating: 0xa5, count: SetupFileEncryption.maximumPayloadBytes)
        let encrypted = try SetupFileEncryption.seal(payload, password: "synthetic password")
        XCTAssertLessThanOrEqual(encrypted.count, SetupFileEncryption.maximumFileBytes)
        XCTAssertEqual(try SetupFileEncryption.open(encrypted, password: "synthetic password"), payload)
    }
    func testBoundsInputs() throws {
        XCTAssertThrowsError(try SetupFileEncryption.seal(Data(), password: "test"))
        XCTAssertThrowsError(try SetupFileEncryption.seal(Data(repeating: 0, count: SetupFileEncryption.maximumPayloadBytes + 1), password: "test"))
        XCTAssertThrowsError(try SetupFileEncryption.seal(Data([1]), password: ""))
        XCTAssertThrowsError(try SetupFileEncryption.seal(Data([1]), password: String(repeating: "x", count: 1025)))
        XCTAssertThrowsError(try SetupFileEncryption.validate(Data(repeating: 65, count: SetupFileEncryption.maximumFileBytes + 1)))
    }
}
