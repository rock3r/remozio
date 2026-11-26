import Foundation
import XCTest
@testable import RemozioProtocol

final class RequestDeliveryResultTests: XCTestCase {
    func testCanonicalDeliveryResultVectors() throws {
        let rows = try CommandCarrierVectors.load().requestDeliveryResult.valid
        XCTAssertEqual(rows.count, 2)
        let reasons: [RequestDeliveryResult.Reason] = [.unreadableCapture, .captureLimit]
        for (row, reason) in zip(rows, reasons) {
            let result = try RequestDeliveryResult(requestID: Data(repeating: 0xaa, count: 16),
                requestDigest: Data(repeating: 0xbb, count: 32), reason: reason)
            let bytes = try row.bytes()
            XCTAssertEqual(try result.encode(), bytes, row.name)
            XCTAssertEqual(try RequestDeliveryResult.decode(bytes), result)
        }
    }

    func testRejectsUnknownFieldsReasonsAndInvalidLengths() throws {
        let rows = try CommandCarrierVectors.load().requestDeliveryResult.invalid
        XCTAssertEqual(rows.count, 8)
        for row in rows {
            XCTAssertThrowsError(try RequestDeliveryResult.decode(row.bytes()), row.name)
        }
    }
}
