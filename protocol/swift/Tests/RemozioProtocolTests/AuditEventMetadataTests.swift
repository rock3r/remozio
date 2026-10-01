import Foundation
import XCTest
@testable import RemozioProtocol

final class AuditEventMetadataTests: XCTestCase {
    private struct Row: Decodable { let name: String; let hex: String }
    private struct Vectors: Decodable { let valid: [Row]; let invalid: [Row] }
    private var limits: CBORLimits { get throws { try CBORLimits(maxBytes: 4096, maxDepth: 8, maxItems: 128) } }
    private func vectors() throws -> Vectors {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        return try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: root.appendingPathComponent("vectors/audit-metadata-v1.json")))
    }
    private func hex(_ text: String) -> Data {
        let chars = Array(text)
        return Data(stride(from: 0, to: chars.count, by: 2).map { UInt8(String(chars[$0...$0 + 1]), radix: 16)! })
    }

    func testSharedMetadataVectorsRoundTripWithoutTextOrNestedPayloads() throws {
        let rows = try vectors().valid
        XCTAssertEqual(rows.count, 85)
        for row in rows {
            let bytes = hex(row.hex)
            let event = try AuditEventMetadata.decode(bytes, limits: limits)
            XCTAssertEqual(try event.encode(limits: limits), bytes, row.name)
            guard case let .map(fields) = try DeterministicCBOR.decode(bytes, limits: limits) else { return XCTFail(row.name) }
            XCTAssertEqual(Set(fields.keys), Set(0...UInt64(19)))
            for value in fields.values {
                switch value {
                case .unsigned, .null: break
                case let .bytes(data): XCTAssertEqual(data.count, 16)
                default: XCTFail("Audit metadata contains a payload: \(row.name)")
                }
            }
        }
    }

    func testMalformedMetadataAndIndependentLimitsFail() throws {
        let rows = try vectors().invalid
        XCTAssertEqual(rows.count, 78)
        for row in rows { XCTAssertThrowsError(try AuditEventMetadata.decode(hex(row.hex), limits: limits), row.name) }
        let bytes = try hex(XCTUnwrap(vectors().valid.first).hex)
        let small = try CBORLimits(maxBytes: bytes.count - 1, maxDepth: 8, maxItems: 128)
        XCTAssertThrowsError(try AuditEventMetadata.decode(bytes, limits: small))
        XCTAssertThrowsError(try AuditEventMetadata.decode(bytes + Data([0]), limits: limits))
        let record = try AuditEventMetadata.decode(bytes, limits: limits)
        XCTAssertThrowsError(try record.encode(limits: small))
    }

    func testActionProjectionKeepsClassesWithoutDurationOrTargetValues() {
        let expected: [AuditActionKind] = [.decline, .cancelTarget, .execute, .approveAccess, .unlockVault,
            .allow, .deny, .allow, .deny, .removeRule]
        for (choice, kind) in zip(ActionChoice.allCases, expected) {
            XCTAssertEqual(AuditActionMetadata(action: CapturedAction(choice: choice, scope: .currentRequest)).kind, kind)
        }
        let scopes: [ActionScope] = [.currentRequest, .session, .timed(seconds: 1), .forever]
        let classes: [AuditLifetime] = [.currentRequest, .session, .timed, .forever]
        for (scope, lifetime) in zip(scopes, classes) {
            XCTAssertEqual(AuditActionMetadata(action: CapturedAction(choice: .allowRule, scope: scope), target: .domain),
                AuditActionMetadata(kind: .allow, lifetime: lifetime, target: .domain))
        }
        XCTAssertEqual(AuditActionMetadata(action: CapturedAction(choice: .allowRule, scope: .timed(seconds: 1))),
            AuditActionMetadata(action: CapturedAction(choice: .allowRule, scope: .timed(seconds: .max))))
    }

    func testUnknownFieldsAndOutcomesRemainExplicit() throws {
        let record = try AuditEventMetadata.decode(hex(XCTUnwrap(vectors().valid.first).hex), limits: limits)
        XCTAssertNil(record.action)
        XCTAssertNil(record.requestID)
        XCTAssertNil(record.eventTimeMs)
        XCTAssertEqual(record.authentication, .unknown)
        XCTAssertEqual(record.outcome, .unknown)
        XCTAssertNotEqual(AuditEventKind.biometricCancelled, .decisionRejected)
        XCTAssertNotEqual(AuditEventKind.dismissed, .cancelled)
        XCTAssertNotEqual(AuditOutcome.attempted, .verifiedSuccess)
    }
}
