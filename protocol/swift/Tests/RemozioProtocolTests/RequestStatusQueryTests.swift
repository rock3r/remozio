import Foundation
import XCTest
@testable import RemozioProtocol

final class RequestStatusQueryTests: XCTestCase {
    func testSharedCanonicalQuery() throws {
        let query = try RequestStatusQuery(requestID: Data(repeating: 0xaa, count: 16))
        let bytes = try query.encode()
        XCTAssertEqual(bytes.map { String(format: "%02x", $0) }.joined(),
            "a30001016d726571756573742d73746174650250" + String(repeating: "aa", count: 16))
        XCTAssertEqual(try RequestStatusQuery.decode(bytes), query)
        XCTAssertLessThanOrEqual(bytes.count, RequestStatusQuery.maximumBytes)
    }
    func testVersionShapeAndBoundsAreStrict() throws {
        let original = try RequestStatusQuery(requestID: Data(count: 16)).encode()
        let limits = try CBORLimits(maxBytes: 256, maxDepth: 3, maxItems: 16)
        guard case .map(let fields) = try DeterministicCBOR.decode(original, limits: limits) else { return XCTFail() }
        for (key, value): (UInt64, CBORValue) in [(0, .unsigned(2)), (1, .text("decision")), (1, .unsigned(1)),
            (2, .bytes(Data(count: 15))), (2, .bytes(Data(count: 17))), (2, .array([])), (3, .null)] {
            var changed = fields; changed[key] = value
            XCTAssertThrowsError(try RequestStatusQuery.decode(DeterministicCBOR.encode(.map(changed), limits: limits)))
        }
        for bytes in [Data(), original + Data([0]), Data(repeating: 0, count: 65), Data([0xa0])] {
            XCTAssertThrowsError(try RequestStatusQuery.decode(bytes))
        }
        XCTAssertThrowsError(try RequestStatusQuery(requestID: Data(count: 15)))
    }
}
