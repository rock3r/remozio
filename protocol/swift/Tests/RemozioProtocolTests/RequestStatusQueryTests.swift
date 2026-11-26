import Foundation
import XCTest
@testable import RemozioProtocol

final class RequestStatusQueryTests: XCTestCase {
    func testSharedCanonicalQuery() throws {
        let query = try RequestStatusQuery(requestID: Data(repeating: 0xaa, count: 16))
        let rows = try CommandCarrierVectors.load().requestStatusQuery.valid
        XCTAssertEqual(rows.count, 1)
        let row = try XCTUnwrap(rows.first)
        let bytes = try row.bytes()
        XCTAssertEqual(try query.encode(), bytes, row.name)
        XCTAssertEqual(try RequestStatusQuery.decode(bytes), query)
        XCTAssertLessThanOrEqual(bytes.count, RequestStatusQuery.maximumBytes)
    }
    func testVersionShapeAndBoundsAreStrict() throws {
        let rows = try CommandCarrierVectors.load().requestStatusQuery.invalid
        XCTAssertEqual(rows.count, 11)
        for row in rows {
            let bytes = try row.bytes()
            XCTAssertThrowsError(try RequestStatusQuery.decode(bytes), row.name)
        }
        XCTAssertThrowsError(try RequestStatusQuery(requestID: Data(count: 15)))
    }
}
