import Foundation
import XCTest
@testable import RemozioProtocol

final class ActionPolicyTests: XCTestCase {
    func testSharedActionPolicyVectors() throws {
        struct Vector: Decodable {
            let name: String
            let kind: String
            let choice: String
            let scope: String
            let seconds: String?
            let permitted: Bool
            let key: String?
            let purpose: String?
            let effect: String?
            let error: String?
        }
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let file = root.appendingPathComponent("vectors/action-policy-v1.json")
        let vectors = try JSONDecoder().decode([Vector].self, from: Data(contentsOf: file))
        XCTAssertGreaterThan(vectors.count, 40)
        for vector in vectors {
            let kind = try XCTUnwrap(RequestKind(rawValue: vector.kind))
            let choice = try XCTUnwrap(ActionChoice(rawValue: vector.choice))
            let scope: ActionScope
            switch vector.scope {
            case "currentRequest": scope = .currentRequest
            case "session": scope = .session
            case "forever": scope = .forever
            case "timed": scope = .timed(seconds: try XCTUnwrap(vector.seconds.flatMap(UInt64.init)))
            default: XCTFail("Unknown scope fixture"); continue
            }
            let action = CapturedAction(choice: choice, scope: scope)
            let retained: Set<CapturedAction> = vector.permitted ? [action] : []
            if let expected = vector.error {
                XCTAssertThrowsError(try ActionPolicy.requirement(for: action, requestKind: kind, retainedPermittedActions: retained), vector.name) { error in
                    XCTAssertEqual((error as? ActionPolicyError)?.rawValue, expected, vector.name)
                }
            } else {
                let result = try ActionPolicy.requirement(for: action, requestKind: kind, retainedPermittedActions: retained)
                XCTAssertEqual(result.keyClass.rawValue, vector.key, vector.name)
                XCTAssertEqual(result.purpose.rawValue, vector.purpose, vector.name)
                XCTAssertEqual(result.effect.rawValue, vector.effect, vector.name)
            }
        }
    }

    func testScopeChangeDoesNotMatchRetainedChoice() {
        let retained = CapturedAction(choice: .allowRule, scope: .timed(seconds: 60))
        let altered = CapturedAction(choice: .allowRule, scope: .timed(seconds: 61))
        XCTAssertThrowsError(try ActionPolicy.requirement(for: altered, requestKind: .littleSnitch, retainedPermittedActions: [retained])) { error in
            XCTAssertEqual(error as? ActionPolicyError, .notPermitted)
        }
    }
}
