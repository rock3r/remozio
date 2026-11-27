import Foundation
import XCTest
@testable import RemozioProtocol

final class SessionEnvelopeTests: XCTestCase {
    func testSharedCanonicalBytesAndUnsignedSequenceRoundTrip() throws {
        let value = try SessionEnvelope(sessionID: Data(repeating: 0xaa, count: 32), sequence: .max, payload: Data([1, 2, 3]))
        let rows = try CommandCarrierVectors.load().sessionEnvelope.valid
        XCTAssertEqual(rows.count, 1)
        let row = try XCTUnwrap(rows.first)
        let encoded = try row.bytes()
        XCTAssertEqual(try value.encode(maximumPayloadBytes: 3), encoded, row.name)
        let decoded = try SessionEnvelope.decode(encoded, maximumPayloadBytes: 3)
        XCTAssertEqual(decoded.sequence, .max); XCTAssertEqual(decoded.sessionID, value.sessionID); XCTAssertEqual(decoded.payload, value.payload)
    }
    func testIncompatibleAndOversizedEnvelopesFail() throws {
        let original = try SessionEnvelope(sessionID: Data(repeating: 0, count: 32), sequence: 0, payload: Data([1])).encode(maximumPayloadBytes: 1)
        let rows = try CommandCarrierVectors.load().sessionEnvelope.invalid
        XCTAssertEqual(rows.count, 6)
        for row in rows {
            let bytes = try row.bytes()
            XCTAssertThrowsError(try SessionEnvelope.decode(bytes, maximumPayloadBytes: 1), row.name)
        }
        XCTAssertThrowsError(try SessionEnvelope(sessionID: Data(count: 32), sequence: 0, payload: Data([1, 2])).encode(maximumPayloadBytes: 1))
        XCTAssertThrowsError(try SessionEnvelope.decode(original, maximumPayloadBytes: Int.max))
    }
}
