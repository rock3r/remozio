import Foundation
import XCTest
@testable import RemozioProtocol

private struct ProgressMutation: Decodable { let name: String; let hex: String }
private struct ProgressRow: Decodable {
    let name: String; let hex: String; let signature: String?; let signingInput: String?
    let wrongVersionSignature: String?; let wrongTypeSignature: String?; let wrongPurposeSignature: String?
    let oldStatusDomainSignature: String?; let mutations: [ProgressMutation]?
}
private struct ProgressVectors: Decodable {
    let publicKey: String; let otherPublicKey: String; let valid: [ProgressRow]; let invalid: [ProgressRow]
}
private func progressHex(_ text: String) -> Data {
    Data(stride(from: 0, to: text.count, by: 2).map {
        let start = text.index(text.startIndex, offsetBy: $0)
        return UInt8(text[start..<text.index(start, offsetBy: 2)], radix: 16)!
    })
}

final class UpdateSchedulingProgressTests: XCTestCase {
    private var signingLimits: CBORLimits { get throws { try .init(maxBytes: 8192, maxDepth: 2, maxItems: 32) } }
    private func vectors() throws -> ProgressVectors {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        return try JSONDecoder().decode(ProgressVectors.self, from: Data(contentsOf:
            root.appendingPathComponent("vectors/update-scheduling-progress-v1.json")))
    }
    private func verify(_ signature: Data, _ key: Data, _ payload: Data) throws -> Bool {
        try UpdateSchedulingProgressSignature.verify(signature: signature, authorityPublicKey: key,
            wireVersion: 1, canonicalPayload: payload, inputLimits: signingLimits)
    }
    func testSharedObservationsPreserveCanonicalBytesAndRootSignatures() throws {
        let data = try vectors(); XCTAssertEqual(data.valid.count, 10)
        for row in data.valid {
            let bytes = progressHex(row.hex), value = try UpdateSchedulingProgressResponse.decode(bytes)
            XCTAssertEqual(try value.encode(), bytes, row.name); XCTAssertNil(value.status.controlDigest)
            XCTAssertEqual(try UpdateSchedulingProgressSigningInput.make(wireVersion: 1, canonicalPayload: bytes,
                inputLimits: signingLimits), progressHex(row.signingInput!))
            XCTAssertTrue(try verify(progressHex(row.signature!), progressHex(data.publicKey), bytes))
            XCTAssertEqual(value.description, "UpdateSchedulingProgressResponse(redacted)")
            XCTAssertEqual(value.debugDescription, value.description)
            for blocker in value.blockers { XCTAssertEqual(blocker.description, "UpdateSchedulingBlocker(redacted)") }
        }
    }
    func testMalformedAndContradictoryObservationsFailBeforeValidSignatureAcceptance() throws {
        let data = try vectors(); XCTAssertEqual(data.invalid.count, 118); var signed = 0
        for row in data.invalid {
            let bytes = progressHex(row.hex)
            XCTAssertThrowsError(try UpdateSchedulingProgressResponse.decode(bytes), row.name)
            XCTAssertThrowsError(try UpdateSchedulingProgressSigningInput.make(wireVersion: 1,
                canonicalPayload: bytes, inputLimits: signingLimits), row.name)
            if let signature = row.signature {
                signed += 1
                XCTAssertTrue(P256Verification.verify(signature: progressHex(signature), publicKey: progressHex(data.publicKey),
                    input: progressHex(row.signingInput!)))
                XCTAssertThrowsError(try verify(progressHex(signature), progressHex(data.publicKey), bytes))
            }
        }
        XCTAssertEqual(signed, 22)
    }
    func testSignaturesBindEnrollmentCandidateProgressAndEveryPresentationField() throws {
        let data = try vectors(), key = progressHex(data.publicKey)
        for row in data.valid {
            let bytes = progressHex(row.hex), signature = progressHex(row.signature!)
            XCTAssertFalse(try verify(signature, progressHex(data.otherPublicKey), bytes))
            for wrong in [row.wrongVersionSignature, row.wrongTypeSignature, row.wrongPurposeSignature, row.oldStatusDomainSignature] {
                XCTAssertFalse(try verify(progressHex(wrong!), key, bytes))
            }
            for mutation in row.mutations! {
                let changed = progressHex(mutation.hex)
                _ = try UpdateSchedulingProgressResponse.decode(changed)
                XCTAssertFalse(try verify(signature, key, changed), row.name + ":" + mutation.name)
            }
        }
    }
    func testExplicitUnknownAgesAndSecurityNeverBecomeZeroOrOrdinary() throws {
        let rows = try vectors().valid
        func value(_ name: String) throws -> UpdateSchedulingProgressResponse {
            try .decode(progressHex(rows.first { $0.name == name }!.hex))
        }
        let unknown = try value("unknown")
        XCTAssertNil(unknown.readyAgeMilliseconds(afterObservationAge: 1))
        XCTAssertEqual(unknown.security, .unknown); XCTAssertEqual(unknown.designation, .unknown)
        XCTAssertEqual(unknown.admission, .unknown); XCTAssertTrue(unknown.availableActions.isEmpty)
        let ready = try value("ready-owner")
        XCTAssertEqual(ready.readyAgeMilliseconds(afterObservationAge: 0), 0)
        XCTAssertEqual(ready.readyAgeMilliseconds(afterObservationAge: 5), 5)
        XCTAssertNil(ready.readyAgeMilliseconds(afterObservationAge: nil))
        let maximum = try value("maximum-values")
        XCTAssertEqual(maximum.readyAgeMilliseconds(afterObservationAge: 0), .max)
        XCTAssertNil(maximum.readyAgeMilliseconds(afterObservationAge: 1))
        XCTAssertNil(maximum.blockers[0].oldestAgeMilliseconds(afterObservationAge: 1))
        XCTAssertNil(maximum.blockers[1].oldestAgeMilliseconds(afterObservationAge: 0))
        XCTAssertEqual(maximum.blockers[2].oldestAgeMilliseconds(afterObservationAge: 2), 2)
        XCTAssertNil(maximum.blockers[3].count); XCTAssertNil(maximum.blockers[3].oldestAgeMilliseconds)
    }
    func testIrreversiblePhasesExposeProgressWithoutOfferingReversibleActions() throws {
        let rows = try vectors().valid
        for row in rows where row.name.hasPrefix("irreversible-") {
            let value = try UpdateSchedulingProgressResponse.decode(progressHex(row.hex))
            XCTAssertTrue(value.phase.irreversible); XCTAssertTrue(value.availableActions.isEmpty)
        }
        let other = try UpdateSchedulingProgressResponse.decode(progressHex(rows.first { $0.name == "draining-other-owner" }!.hex))
        XCTAssertFalse(other.availableActions.contains(.deferUpdate)); XCTAssertTrue(other.availableActions.contains(.cancelDrain))
    }
    func testValueCopiesAndHistoricalStatusCannotGrantObservationAuthority() throws {
        let first = try UpdateSchedulingProgressResponse.decode(progressHex(vectors().valid[0].hex))
        var supplied = [try UpdateSchedulingBlocker(kind: .activeCommands, count: 1, oldestAgeMilliseconds: 0)]
        let value = try UpdateSchedulingProgressResponse(status: first.status, phase: first.phase,
            designation: first.designation, security: first.security, readyAgeMilliseconds: first.readyAgeMilliseconds,
            availableActions: first.availableActions, blockers: supplied, admission: first.admission)
        let bytes = try value.encode(); supplied.removeAll()
        XCTAssertEqual(try value.encode(), bytes)
        let old = try UpdateSchedulingStatusResponse(scope: first.status.scope, queryNonce: first.status.queryNonce,
            updateID: first.status.updateID, generation: 1, revision: 1, requestedAction: .installWhenCurrentWorkFinishes,
            controlDigest: Data(repeating: 0, count: 32))
        XCTAssertThrowsError(try UpdateSchedulingProgressResponse(status: old, phase: first.phase,
            designation: first.designation, security: first.security, readyAgeMilliseconds: nil,
            availableActions: [], blockers: [], admission: first.admission))
        XCTAssertThrowsError(try UpdateSchedulingStatusResponse.decode(bytes))
    }
    func testResourceAndVersionLimitsRemainStrict() throws {
        let bytes = progressHex(try vectors().valid[0].hex)
        for wire: UInt64 in [0, 2, .max] {
            XCTAssertThrowsError(try UpdateSchedulingProgressSigningInput.make(wireVersion: wire,
                canonicalPayload: bytes, inputLimits: signingLimits))
        }
        XCTAssertThrowsError(try UpdateSchedulingProgressResponse.decode(Data(repeating: 0, count: 4097)))
        let size = try UpdateSchedulingProgressSigningInput.make(wireVersion: 1, canonicalPayload: bytes, inputLimits: signingLimits).count
        XCTAssertThrowsError(try UpdateSchedulingProgressSigningInput.make(wireVersion: 1, canonicalPayload: bytes,
            inputLimits: CBORLimits(maxBytes: size - 1, maxDepth: 2, maxItems: 32)))
    }
}
