import Foundation
import Synchronization
import XCTest
@testable import RemozioHostCore

final class ExactByteDecodeMemoTests: XCTestCase {
    private struct Refused: Error {}
    func testExactKeysAndEvictionRecomputeWithoutKeepingFailures() throws {
        let memo = ExactByteDecodeMemo<UInt8>(capacity: 2)
        var counts: [Data: Int] = [:]
        func value(_ bytes: Data) throws -> UInt8 {
            try memo.value(for: bytes) {
                counts[bytes, default: 0] += 1
                guard let value = bytes.first else { throw Refused() }; return value
            }
        }
        XCTAssertEqual(try value(Data([1])), 1); XCTAssertEqual(try value(Data([1])), 1)
        XCTAssertEqual(counts[Data([1])], 1)
        for byte in UInt8(2)...3 { XCTAssertEqual(try value(Data([byte])), byte) }
        XCTAssertEqual(try value(Data([1])), 1); XCTAssertEqual(counts[Data([1])], 2)
        for _ in 0..<2 { XCTAssertThrowsError(try value(Data())) }
        XCTAssertEqual(counts[Data()], 2)
        XCTAssertEqual(try value(Data([1])), 1); XCTAssertEqual(counts[Data([1])], 2)
    }
    func testConcurrentKeysAndCopyOnWriteKeepValuesIndependent() {
        let memo = ExactByteDecodeMemo<Data>(capacity: 4), failures = Mutex(0)
        DispatchQueue.concurrentPerform(iterations: 128) { index in
            let key = Data([UInt8(index % 8)])
            let value = memo.value(for: key) { key }
            if value != key { failures.withLock { $0 += 1 } }
        }
        XCTAssertEqual(failures.withLock { $0 }, 0)
        let key = Data([7]); var copy = memo.value(for: key) { key }; copy[0] = 9
        XCTAssertEqual(memo.value(for: key) { key }, Data([7]))
        XCTAssertEqual(key, Data([7]))
    }
}
