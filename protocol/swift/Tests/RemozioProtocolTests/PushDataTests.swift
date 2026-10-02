import Foundation
import XCTest
@testable import RemozioProtocol

final class PushDataTests: XCTestCase {
    private struct Valid: Decodable { let name: String; let data: [String: String]; let identifier: String?; let enrollmentTag: String; let candidateID: String?; let challenge: String? }
    private struct Invalid: Decodable { let name: String; let data: [String: String] }
    private struct Vectors: Decodable { let valid: [Valid]; let invalid: [Invalid] }
    private func vectors() throws -> Vectors {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        return try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: root.appendingPathComponent("vectors/push-data-v1.json")))
    }
    private func hex(_ bytes: Data) -> String { bytes.map { String(format: "%02x", $0) }.joined() }
    func testSharedPayloadsRoundTripAndPreserveEveryByte() throws {
        let rows = try vectors().valid; XCTAssertEqual(rows.count, 2)
        for row in rows {
            let value = try PushData.decode(row.data)
            XCTAssertEqual(value.encode(), row.data)
            switch value {
            case .wake(let v):
                XCTAssertEqual(row.name, "wake"); XCTAssertEqual(hex(v.identifier), row.identifier)
                XCTAssertEqual(hex(v.enrollmentTag), row.enrollmentTag)
            case .tokenChallenge(let v):
                XCTAssertEqual(row.name, "challenge"); XCTAssertEqual(hex(v.candidateID), row.candidateID)
                XCTAssertEqual(hex(v.challenge), row.challenge); XCTAssertEqual(hex(v.enrollmentTag), row.enrollmentTag)
            }
        }
    }
    func testSharedMalformedMixedAndNoncanonicalDataFail() throws {
        let rows = try vectors().invalid; XCTAssertEqual(rows.count, 76)
        for row in rows { XCTAssertThrowsError(try PushData.decode(row.data), row.name) }
    }
    func testConstructorsRejectInvalidLengthsAndDescriptionsRedact() throws {
        let id = Data(repeating: 1, count: 16), secret = Data(repeating: 2, count: 32)
        for count in [0, 15, 17, 31, 33] {
            let invalid = Data(repeating: 3, count: count)
            XCTAssertThrowsError(try PushWake(identifier: invalid, enrollmentTag: secret))
            XCTAssertThrowsError(try PushWake(identifier: secret, enrollmentTag: invalid))
            XCTAssertThrowsError(try PushTokenChallenge(candidateID: id, challenge: invalid, enrollmentTag: secret))
            XCTAssertThrowsError(try PushTokenChallenge(candidateID: id, challenge: secret, enrollmentTag: invalid))
            XCTAssertThrowsError(try PushTokenChallenge(candidateID: invalid, challenge: secret, enrollmentTag: secret))
        }
        let challenge = try PushTokenChallenge(candidateID: id, challenge: secret, enrollmentTag: secret)
        var copy = challenge.challenge; copy[0] ^= 1
        XCTAssertNotEqual(copy, challenge.challenge)
        XCTAssertEqual(String(reflecting: challenge), "PushTokenChallenge(redacted)")
        XCTAssertEqual(String(reflecting: PushData.tokenChallenge(challenge)), "PushData(redacted)")
        XCTAssertEqual(String(reflecting: try PushWake(identifier: secret, enrollmentTag: secret)), "PushWake(redacted)")
    }
}
