import CryptoKit
import Foundation
import RemozioCore
import RemozioProtocol
import XCTest

final class AuditReplyBuilderTests: XCTestCase {
    private let key = P256.Signing.PrivateKey()
    private func id(_ n: UInt8, count: Int = 16) -> Data { Data(repeating: n, count: count) }
    private var bound: CBORLimits { get throws { try CBORLimits(maxBytes: 16384, maxDepth: 8, maxItems: 512) } }
    private func limits(batch: CBORLimits? = nil, record: CBORLimits? = nil, history: CBORLimits? = nil,
                        descriptor: CBORLimits? = nil, signing: CBORLimits? = nil, count: Int = 2) throws -> AuditReplyLimits {
        try AuditReplyLimits(batch: batch ?? bound, record: record ?? bound, history: history ?? bound,
            descriptor: descriptor ?? bound, signing: signing ?? bound, maximumRecords: count)
    }
    private func builder(limits: AuditReplyLimits? = nil, signer: ((Data) throws -> Data)? = nil) throws -> AuditReplyBuilder {
        try AuditReplyBuilder(macID: id(1), accountID: id(2), authorityPublicKey: key.publicKey.x963Representation,
            limits: limits ?? self.limits(), signer: signer ?? { try self.key.signature(for: $0).rawRepresentation })
    }
    private func epoch(_ n: UInt8 = 3, mac: UInt8 = 1, account: UInt8 = 2, retained: UInt64 = 0,
                       head: UInt64 = 4, cause: AuditEpochCause = .restart) throws -> AuditEpochRead {
        let bytes = try DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(id(mac)), 2: .bytes(id(account)), 3: .bytes(id(n)),
            4: .unsigned(7), 5: .unsigned(cause.rawValue), 6: .null, 7: .null, 8: .null,
        ]), limits: bound)
        return try AuditEpochRead(descriptor: AuditEpochDescriptor.decode(bytes, limits: bound), retainedAfter: retained, head: head)
    }
    private func record(_ sequence: UInt64, epoch: UInt8 = 3, mac: UInt8 = 1, account: UInt8 = 2,
                        eventID: UInt8? = nil) throws -> Data {
        try AuditEventMetadata(eventID: id(eventID ?? UInt8(truncatingIfNeeded: sequence)), macID: id(mac), accountID: id(account),
            journalEpoch: id(epoch), sequence: sequence, requestID: id(8), eventTimeMs: nil, authorityReceiptTimeMs: nil,
            kind: .requestCreated, category: .command, action: nil, decisionPhoneID: nil, authentication: .system,
            outcome: .pending, reason: .none, droppedEventCount: nil, peerDeviceID: nil).encode(limits: bound)
    }
    private func pageQuery(epoch: UInt8 = 3, generation: UInt64 = 7, after: UInt64 = 0) throws -> AuditPageRequest {
        try AuditPageRequest(nonce: id(9, count: 32), epoch: id(epoch), generation: generation, after: after)
    }
    private func historyQuery(epoch: UInt8? = nil, after: UInt64? = nil) throws -> AuditHistoryRequest {
        try AuditHistoryRequest(nonce: id(9, count: 32), epoch: epoch.map { id($0) }, after: after)
    }
    private func status(_ reply: SignedAuditReply) throws -> AuditHistoryStatus {
        XCTAssertEqual(reply.kind, .history); XCTAssertEqual(reply.wireVersion, 1)
        XCTAssertTrue(try AuditHistoryStatusSignature.verify(signature: reply.signature, publicKey: key.publicKey.x963Representation,
            wireVersion: 1, canonicalPayload: reply.canonicalBody, payloadLimits: bound, inputLimits: bound))
        return try AuditHistoryStatus.decode(reply.canonicalBody, limits: bound, descriptorLimits: bound)
    }

    func testProducesScopedContiguousSignedPage() throws {
        let reply = try builder().page(pageQuery(), epoch: epoch(), canonicalRecords: [record(1), record(2)])
        XCTAssertEqual(reply.kind, .page); XCTAssertEqual(reply.wireVersion, 1)
        XCTAssertTrue(try AuditBatchSignature.verify(signature: reply.signature, publicKey: key.publicKey.x963Representation,
            wireVersion: 1, canonicalPayload: reply.canonicalBody, payloadLimits: bound, inputLimits: bound))
        let batch = try AuditBatch.decode(reply.canonicalBody, batchLimits: bound, recordLimits: bound, maximumRecords: 2)
        XCTAssertEqual(batch.macID, id(1)); XCTAssertEqual(batch.accountID, id(2)); XCTAssertEqual(batch.queryNonce, id(9, count: 32))
        XCTAssertEqual(batch.records.map(\.sequence), [1, 2]); XCTAssertEqual(batch.nextAfter, 2); XCTAssertTrue(batch.hasMore)
        XCTAssertFalse(try AuditHistoryStatusSignature.verify(signature: reply.signature, publicKey: key.publicKey.x963Representation,
            wireVersion: 1, canonicalPayload: reply.canonicalBody, payloadLimits: bound, inputLimits: bound))
    }

    func testDerivesDiscoveryAvailabilityAndCursorAheadWithoutSubstitutingEpochs() throws {
        let writer = try builder(), current = try epoch(4), old = try epoch(3, head: 2)
        let discovery = try status(writer.history(historyQuery(), current: current))
        XCTAssertEqual(discovery.disposition, .discovery); XCTAssertNil(discovery.queried)
        let available = try status(writer.history(historyQuery(epoch: 3, after: 1), current: current, queried: old))
        XCTAssertEqual(available.disposition, .available); XCTAssertEqual(available.queried?.epoch, id(3))
        XCTAssertEqual(available.current.epoch, id(4)); XCTAssertEqual(available.requestedAfter, 1)
        let ahead = try status(writer.history(historyQuery(epoch: 3, after: 3), current: current, queried: old))
        XCTAssertEqual(ahead.disposition, .cursorAhead); XCTAssertEqual(ahead.queriedHead, 2)
        let missing = try status(writer.history(historyQuery(epoch: 3, after: 3), current: current))
        XCTAssertEqual(missing.disposition, .unavailable); XCTAssertNil(missing.queried)
        let same = try status(writer.history(historyQuery(epoch: 4, after: 4), current: current))
        XCTAssertEqual(same.disposition, .available); XCTAssertEqual(same.currentHead, same.queriedHead)
        XCTAssertEqual(try same.current.encode(limits: bound), try same.queried?.encode(limits: bound))
        let signed = try writer.history(historyQuery(), current: current)
        XCTAssertFalse(try AuditBatchSignature.verify(signature: signed.signature, publicKey: key.publicKey.x963Representation,
            wireVersion: 1, canonicalPayload: signed.canonicalBody, payloadLimits: bound, inputLimits: bound))
    }

    func testRejectsMixedScopesMismatchedReadsAndInvalidRecordsBeforeSigning() throws {
        var calls = 0
        let writer = try builder(signer: { calls += 1; return try self.key.signature(for: $0).rawRepresentation })
        XCTAssertThrowsError(try writer.page(pageQuery(), epoch: epoch(mac: 9), canonicalRecords: [record(1)]))
        XCTAssertThrowsError(try writer.page(pageQuery(), epoch: epoch(account: 9), canonicalRecords: [record(1)]))
        XCTAssertThrowsError(try writer.page(pageQuery(generation: 8), epoch: epoch(), canonicalRecords: [record(1)]))
        XCTAssertThrowsError(try writer.page(pageQuery(epoch: 4), epoch: epoch(), canonicalRecords: [record(1)]))
        for rows in [[try record(1, mac: 9)], [try record(1, account: 9)], [try record(1, epoch: 4)],
                     [try record(2)], [try record(1), try record(3)], [try record(1), try record(2, eventID: 1)],
                     [Data([0xa0])], []] {
            XCTAssertThrowsError(try writer.page(pageQuery(), epoch: epoch(), canonicalRecords: rows))
        }
        XCTAssertThrowsError(try writer.history(historyQuery(), current: epoch(mac: 9)))
        XCTAssertThrowsError(try writer.history(historyQuery(), current: epoch(), queried: epoch(4)))
        XCTAssertThrowsError(try writer.history(historyQuery(epoch: 4, after: 0), current: epoch(), queried: epoch(5)))
        XCTAssertThrowsError(try writer.history(historyQuery(epoch: 4, after: 0), current: epoch(), queried: epoch(4, account: 9)))
        XCTAssertThrowsError(try writer.history(historyQuery(epoch: 3, after: 0), current: epoch(), queried: epoch(head: 5)))
        XCTAssertThrowsError(try writer.history(historyQuery(epoch: 3, after: 0), current: epoch(), queried: epoch(cause: .restoration)))
        XCTAssertEqual(calls, 0)
    }

    func testHandlesRetentionAndMaximumSequenceWithoutOverflow() throws {
        let writer = try builder()
        let pruned = try writer.page(pageQuery(), epoch: epoch(retained: .max, head: .max), canonicalRecords: [])
        let empty = try AuditBatch.decode(pruned.canonicalBody, batchLimits: bound, recordLimits: bound, maximumRecords: 2)
        XCTAssertEqual(empty.nextAfter, .max); XCTAssertFalse(empty.hasMore); XCTAssertTrue(empty.retentionGap)
        let final = try writer.page(pageQuery(after: UInt64.max - 1), epoch: epoch(head: .max), canonicalRecords: [record(.max)])
        XCTAssertEqual(try AuditBatch.decode(final.canonicalBody, batchLimits: bound, recordLimits: bound, maximumRecords: 2).nextAfter, .max)
        XCTAssertThrowsError(try writer.page(pageQuery(after: .max), epoch: epoch(head: UInt64.max - 1), canonicalRecords: [])) {
            XCTAssertEqual($0 as? AuditReplyError, .reconciliationRequired)
        }
        let ahead = try status(writer.history(historyQuery(epoch: 3, after: .max), current: epoch(head: UInt64.max - 1)))
        XCTAssertEqual(ahead.disposition, .cursorAhead)
        XCTAssertThrowsError(try epoch(retained: 5, head: 4))
    }

    func testEnforcesAllResourceLimitsBeforeInvokingSigner() throws {
        var calls = 0
        let sign: (Data) throws -> Data = { calls += 1; return try self.key.signature(for: $0).rawRepresentation }
        let tiny = try CBORLimits(maxBytes: 16, maxDepth: 8, maxItems: 512)
        for custom in [try limits(batch: tiny), try limits(record: tiny), try limits(signing: tiny), try limits(count: 1)] {
            XCTAssertThrowsError(try builder(limits: custom, signer: sign).page(pageQuery(), epoch: epoch(), canonicalRecords: [record(1), record(2)]))
        }
        for custom in [try limits(history: tiny), try limits(descriptor: tiny), try limits(signing: tiny)] {
            XCTAssertThrowsError(try builder(limits: custom, signer: sign).history(historyQuery(), current: epoch()))
        }
        XCTAssertThrowsError(try limits(count: 0))
        XCTAssertEqual(calls, 0)
    }

    func testRejectsWrongKeyMalformedSignatureAndDoubleHash() throws {
        let other = P256.Signing.PrivateKey()
        let wrongSigners: [(Data) throws -> Data] = [
            { _ in Data(repeating: 0, count: 64) },
            { try other.signature(for: $0).rawRepresentation },
            { try self.key.signature(for: $0).derRepresentation },
            { try self.key.signature(for: Data(SHA256.hash(data: $0))).rawRepresentation },
        ]
        for signer in wrongSigners {
            let writer = try builder(signer: signer)
            XCTAssertThrowsError(try writer.page(pageQuery(), epoch: epoch(), canonicalRecords: [record(1)])) {
                XCTAssertEqual($0 as? AuditReplyError, .invalidSignature)
            }
            XCTAssertThrowsError(try writer.history(historyQuery(), current: epoch())) {
                XCTAssertEqual($0 as? AuditReplyError, .invalidSignature)
            }
        }
    }

    func testRejectsMalformedRequestsAndAuthorityBeforeReadingOrSigning() throws {
        XCTAssertThrowsError(try AuditHistoryRequest(nonce: id(9), epoch: nil, after: nil))
        XCTAssertThrowsError(try AuditHistoryRequest(nonce: id(9, count: 32), epoch: id(3), after: nil))
        XCTAssertThrowsError(try AuditHistoryRequest(nonce: id(9, count: 32), epoch: nil, after: 0))
        XCTAssertThrowsError(try AuditHistoryRequest(nonce: id(9, count: 32), epoch: id(3, count: 15), after: 0))
        XCTAssertThrowsError(try AuditPageRequest(nonce: id(9), epoch: id(3), generation: 7, after: 0))
        XCTAssertThrowsError(try AuditPageRequest(nonce: id(9, count: 32), epoch: id(3, count: 15), generation: 7, after: 0))
        XCTAssertThrowsError(try AuditReplyBuilder(macID: id(1), accountID: id(2), authorityPublicKey: id(4, count: 65), limits: limits()) { _ in
            XCTFail("Invalid key must not reach the signer"); return Data()
        })
        XCTAssertThrowsError(try AuditReplyBuilder(macID: id(1, count: 15), accountID: id(2),
            authorityPublicKey: key.publicKey.x963Representation, limits: limits()) { _ in Data() })
    }
    private struct SharedRow: Decodable { let name: String; let hex: String; let input: String }
    private struct SharedVectors: Decodable { let valid: [SharedRow] }
    private func vectors(_ name: String) throws -> [SharedRow] {
        var root = URL(fileURLWithPath: #filePath)
        for _ in 0..<5 { root.deleteLastPathComponent() }
        return try JSONDecoder().decode(SharedVectors.self,
            from: Data(contentsOf: root.appendingPathComponent("protocol/vectors/" + name))).valid
    }
    private func hex(_ text: String) -> Data {
        let chars = Array(text)
        return Data(stride(from: 0, to: chars.count, by: 2).map { UInt8(String(chars[$0...$0 + 1]), radix: 16)! })
    }

    func testReproducesAllSharedPagePayloadsAndSigningInputs() throws {
        let rows = try vectors("audit-batches-v1.json")
        XCTAssertEqual(rows.count, 8)
        for row in rows {
            let expected = hex(row.hex)
            let batch = try AuditBatch.decode(expected, batchLimits: bound, recordLimits: bound, maximumRecords: 2)
            let header = try DeterministicCBOR.encode(.map([
                0: .unsigned(1), 1: .bytes(batch.macID), 2: .bytes(batch.accountID), 3: .bytes(batch.journalEpoch),
                4: .unsigned(batch.epochCreationGeneration), 5: .unsigned(AuditEpochCause.unknown.rawValue),
                6: .null, 7: .null, 8: .null,
            ]), limits: bound)
            let read = try AuditEpochRead(descriptor: AuditEpochDescriptor.decode(header, limits: bound),
                retainedAfter: batch.retainedAfter, head: batch.head)
            let writer = try AuditReplyBuilder(macID: batch.macID, accountID: batch.accountID,
                authorityPublicKey: key.publicKey.x963Representation, limits: limits()) { input in
                    XCTAssertEqual(input, self.hex(row.input), row.name)
                    return try self.key.signature(for: input).rawRepresentation
                }
            let query = try AuditPageRequest(nonce: batch.queryNonce, epoch: batch.journalEpoch,
                generation: batch.epochCreationGeneration, after: batch.requestedAfter)
            let reply = try writer.page(query, epoch: read, canonicalRecords: batch.records.map { try $0.encode(limits: bound) })
            XCTAssertEqual(reply.canonicalBody, expected, row.name)
        }
    }

    func testReproducesAllSharedHistoryPayloadsAndSigningInputs() throws {
        let rows = try vectors("audit-history-status-v1.json")
        XCTAssertEqual(rows.count, 15)
        for row in rows {
            let expected = hex(row.hex)
            let report = try AuditHistoryStatus.decode(expected, limits: bound, descriptorLimits: bound)
            let current = try AuditEpochRead(descriptor: report.current, retainedAfter: report.currentRetainedAfter, head: report.currentHead)
            let queried = try report.queried.map {
                try AuditEpochRead(descriptor: $0, retainedAfter: XCTUnwrap(report.queriedRetainedAfter), head: XCTUnwrap(report.queriedHead))
            }
            let writer = try AuditReplyBuilder(macID: report.macID, accountID: report.accountID,
                authorityPublicKey: key.publicKey.x963Representation, limits: limits()) { input in
                    XCTAssertEqual(input, self.hex(row.input), row.name)
                    return try self.key.signature(for: input).rawRepresentation
                }
            let query = try AuditHistoryRequest(nonce: report.queryNonce, epoch: report.requestedEpoch, after: report.requestedAfter)
            XCTAssertEqual(try writer.history(query, current: current, queried: queried).canonicalBody, expected, row.name)
        }
    }

}
