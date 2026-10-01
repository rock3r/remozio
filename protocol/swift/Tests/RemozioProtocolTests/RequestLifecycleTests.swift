import Foundation
import XCTest
@testable import RemozioProtocol

final class RequestLifecycleTests: XCTestCase {
    func testCompleteTransitionMatrix() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let rows = try JSONDecoder().decode([[String]].self, from: Data(contentsOf: root.appendingPathComponent("vectors/lifecycle-v1.json")))
        XCTAssertEqual(rows.count, 19)
        var expected: [String: RequestPhase] = [:]
        for row in rows {
            XCTAssertEqual(row.count, 3)
            let phase = try XCTUnwrap(RequestPhase(rawValue: row[0]))
            let event = try XCTUnwrap(RequestEvent(rawValue: row[1]))
            let result = try XCTUnwrap(RequestPhase(rawValue: row[2]))
            XCTAssertNil(expected.updateValue(result, forKey: "\(phase.rawValue):\(event.rawValue)"))
        }
        for phase in RequestPhase.allCases {
            for event in RequestEvent.allCases {
                let key = "\(phase.rawValue):\(event.rawValue)"
                if let result = expected[key] {
                    XCTAssertEqual(try RequestLifecycle.transition(from: phase, event: event), result, key)
                } else {
                    XCTAssertThrowsError(try RequestLifecycle.transition(from: phase, event: event), key) { error in
                        XCTAssertEqual(error as? LifecycleError, phase.isTerminal ? .terminal : .invalidTransition, key)
                    }
                }
            }
        }
    }

    func testCompetingDecisionCannotReplaceFirstAcceptedDecision() throws {
        let accepted = try RequestLifecycle.transition(from: .presented, event: .authorize)
        for other in [RequestEvent.authorize, .decline, .cancel, .expire] {
            XCTAssertThrowsError(try RequestLifecycle.transition(from: accepted, event: other))
        }
        XCTAssertEqual(try RequestLifecycle.transition(from: accepted, event: .beginDispatch), .executing)
    }

    func testUnknownCannotBeRetriedOrTurnedIntoSuccessByLateAcknowledgment() throws {
        let interrupted = try RequestLifecycle.transition(from: .executing, event: .restartAuthority)
        XCTAssertEqual(interrupted, .unknown)
        for event in RequestEvent.allCases {
            XCTAssertThrowsError(try RequestLifecycle.transition(from: interrupted, event: event))
        }
    }
}
