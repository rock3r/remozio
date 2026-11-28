import Synchronization
import XCTest
@testable import RemozioCore

final class ReplayCapacityDiagnosticsTests: XCTestCase {
    func testEachCounterReportsOnlyItsNewBandAndOnlyTheAllowedFields() {
        for counter in ReplayCapacityDiagnostics.Counter.allCases {
            let messages = Mutex<[String]>([])
            var diagnostics = ReplayCapacityDiagnostics { _, message in messages.withLock { $0.append(message) } }
            for count: Int64 in [79, 80, 80, 94, 95, 95, 99, 100, 100] {
                diagnostics.observe(.init(counter: counter, count: count, limit: 100))
            }
            XCTAssertEqual(messages.withLock { $0 }, [
                "permanent_replay_capacity counter=\(counter.rawValue) count=80 limit=100 band=80",
                "permanent_replay_capacity counter=\(counter.rawValue) count=95 limit=100 band=95",
                "permanent_replay_capacity counter=\(counter.rawValue) count=100 limit=100 band=100",
            ])
        }
    }

    func testInclusiveThresholdsRoundUpAtSmallLimits() {
        let messages = Mutex<[String]>([])
        var diagnostics = ReplayCapacityDiagnostics { _, message in messages.withLock { $0.append(message) } }
        for count: Int64 in [16, 17, 19, 20, 21] {
            diagnostics.observe(.init(counter: .consumedRequests, count: count, limit: 21))
        }
        XCTAssertEqual(messages.withLock { $0 }, [
            "permanent_replay_capacity counter=consumed_requests count=17 limit=21 band=80",
            "permanent_replay_capacity counter=consumed_requests count=20 limit=21 band=95",
            "permanent_replay_capacity counter=consumed_requests count=21 limit=21 band=100",
        ])
    }
}
