import Foundation
import XCTest
@testable import RemozioProtocol

final class DecisionRefusalFrameTests: XCTestCase {
    func testCanonicalDecisionRefusalVectors() throws {
        let rows = try CommandCarrierVectors.load().decisionRefusalFrame
        XCTAssertEqual(rows.valid.count, 2)
        XCTAssertEqual(rows.signingInputs.count, 2)
        let reasons: [DecisionRefusalFrame.Reason] = [.requestChanged, .actionUnavailable]
        let sequences: [UInt64] = [23, .max]
        func repeated(_ value: UInt8, _ count: Int = 16) -> Data { Data(repeating: value, count: count) }
        let scope = try ChannelScope(macID: repeated(1), accountID: repeated(2), phoneID: repeated(3), enrollmentEpoch: repeated(4))
        for (index, row) in rows.valid.enumerated() {
            let payload = try DecisionRefusalFrame.Payload(scope: scope,
                attempt: .init(sessionID: repeated(5, 32), sequence: sequences[index]), requestID: repeated(6),
                requestDigest: repeated(7, 32), decisionFrameDigest: repeated(8, 32), reason: reasons[index])
            let expected = try DecisionRefusalFrame(payload: payload, signature: repeated(0xcc, 64))
            let bytes = try row.bytes()
            XCTAssertEqual(try expected.encode(), bytes, row.name)
            let decoded = try DecisionRefusalFrame.decode(bytes)
            XCTAssertEqual(decoded.payload.scope, scope)
            XCTAssertEqual(decoded.payload.attempt, payload.attempt)
            XCTAssertEqual(decoded.payload.reason, reasons[index])
            XCTAssertEqual(try decoded.payload.signingInput(), try rows.signingInputs[index].bytes(), row.name)
        }
    }

    func testRejectsInvalidDecisionRefusalVectors() throws {
        let rows = try CommandCarrierVectors.load().decisionRefusalFrame.invalid
        XCTAssertEqual(rows.count, 8)
        for row in rows {
            XCTAssertThrowsError(try DecisionRefusalFrame.decode(row.bytes()), row.name)
        }
    }
}
