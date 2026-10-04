import XCTest
@testable import RemozioCore

final class AuthorityClockTests: XCTestCase {
    func testIntegerConversionFloorsFractionalMilliseconds() throws {
        XCTAssertEqual(try AuthorityClock.milliseconds(ticks: 999_999, numerator: 1, denominator: 1), 0)
        XCTAssertEqual(try AuthorityClock.milliseconds(ticks: 1_000_000, numerator: 1, denominator: 1), 1)
        XCTAssertEqual(try AuthorityClock.milliseconds(ticks: 24_000, numerator: 125, denominator: 3), 1)
        XCTAssertEqual(try AuthorityClock.milliseconds(ticks: 23_999, numerator: 125, denominator: 3), 0)
    }

    func testWideIntermediateAndInvalidTimebase() throws {
        XCTAssertEqual(try AuthorityClock.milliseconds(ticks: .max, numerator: .max, denominator: .max),
                       UInt64.max / 1_000_000)
        for pair: (UInt32, UInt32) in [(0, 1), (1, 0)] {
            XCTAssertThrowsError(try AuthorityClock.milliseconds(ticks: 1, numerator: pair.0, denominator: pair.1)) {
                XCTAssertEqual($0 as? AuthorityClockError, .invalidTimebase)
            }
        }
        XCTAssertThrowsError(try AuthorityClock.milliseconds(ticks: .max, numerator: .max, denominator: 1)) {
            XCTAssertEqual($0 as? AuthorityClockError, .overflow)
        }
    }

    func testLiveClockPreservesEpochAcrossCopiesAndMovesForward() throws {
        let clock = try AuthorityClock(), copy = clock, replacement = try AuthorityClock()
        let first = try clock.now(), second = try copy.now()
        XCTAssertEqual(first.epoch, clock.epoch)
        XCTAssertEqual(second.epoch, first.epoch)
        XCTAssertGreaterThanOrEqual(second.milliseconds, first.milliseconds)
        XCTAssertNotEqual(replacement.epoch, clock.epoch)
    }
}
