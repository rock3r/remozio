import Foundation
import XCTest
@testable import RemozioProtocol

final class SessionEnvelopeTests: XCTestCase {
    func testSharedCanonicalBytesAndUnsignedSequenceRoundTrip() throws {
        let value = try SessionEnvelope(sessionID: Data(repeating: 0xaa, count: 32), sequence: .max, payload: Data([1, 2, 3]))
        let expected = "a40001015820" + String(repeating: "aa", count: 32) + "021bffffffffffffffff0343010203"
        let encoded = try value.encode(maximumPayloadBytes: 3)
        XCTAssertEqual(encoded.map { String(format: "%02x", $0) }.joined(), expected)
        let decoded = try SessionEnvelope.decode(encoded, maximumPayloadBytes: 3)
        XCTAssertEqual(decoded.sequence, .max); XCTAssertEqual(decoded.sessionID, value.sessionID); XCTAssertEqual(decoded.payload, value.payload)
    }
    func testIncompatibleAndOversizedEnvelopesFail() throws {
        let original = try SessionEnvelope(sessionID: Data(repeating: 0, count: 32), sequence: 0, payload: Data([1])).encode(maximumPayloadBytes: 1)
        let limits = try CBORLimits(maxBytes: 100, maxDepth: 2, maxItems: 12)
        guard case let .map(fields) = try DeterministicCBOR.decode(original, limits: limits) else { return XCTFail() }
        let changes: [(UInt64, CBORValue)] = [(0, .unsigned(2)), (1, .bytes(Data(count: 31))), (2, .text("0")),
            (3, .bytes(Data())), (4, .unsigned(1))]
        for (key, value) in changes {
            var changed = fields; changed[key] = value
            let bytes = try DeterministicCBOR.encode(.map(changed), limits: limits)
            XCTAssertThrowsError(try SessionEnvelope.decode(bytes, maximumPayloadBytes: 1))
        }
        XCTAssertThrowsError(try SessionEnvelope(sessionID: Data(count: 32), sequence: 0, payload: Data([1, 2])).encode(maximumPayloadBytes: 1))
        XCTAssertThrowsError(try SessionEnvelope.decode(original, maximumPayloadBytes: Int.max))
        XCTAssertThrowsError(try SessionEnvelope.decode(original + Data([0]), maximumPayloadBytes: 1))
    }
}
