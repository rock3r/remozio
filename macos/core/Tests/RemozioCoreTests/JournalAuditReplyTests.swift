import CryptoKit
import Darwin
import Foundation
@testable import RemozioCore
import RemozioProtocol
import SQLite3
import XCTest

final class JournalAuditReplyTests: XCTestCase {
    private enum Failure: Error { case injected }
    private let key = P256.Signing.PrivateKey()
    private var bound: CBORLimits { get throws { try CBORLimits(maxBytes: 16384, maxDepth: 8, maxItems: 512) } }
    private func id(_ value: UInt8, count: Int = 16) -> Data { Data(repeating: value, count: count) }
    private func limits(batch: CBORLimits? = nil, signing: CBORLimits? = nil, count: Int = 4) throws -> AuditReplyLimits {
        try AuditReplyLimits(batch: batch ?? bound, record: bound, history: bound, descriptor: bound,
                            signing: signing ?? bound, maximumRecords: count)
    }
    private func builder(limits: AuditReplyLimits? = nil, mac: UInt8 = 1,
                         signer: ((Data) throws -> Data)? = nil) throws -> AuditReplyBuilder {
        try AuditReplyBuilder(macID: id(mac), accountID: id(2), authorityPublicKey: key.publicKey.x963Representation,
            limits: limits ?? self.limits(), signer: signer ?? { try self.key.signature(for: $0).rawRepresentation })
    }
    private func query(epoch: UInt8 = 3, generation: UInt64 = 7, after: UInt64 = 0) throws -> AuditPageRequest {
        try AuditPageRequest(nonce: id(9, count: 32), epoch: id(epoch), generation: generation, after: after)
    }
    private func history(epoch: UInt8? = nil, after: UInt64? = nil) throws -> AuditHistoryRequest {
        try AuditHistoryRequest(nonce: id(9, count: 32), epoch: epoch.map { id($0) }, after: after)
    }
    private func descriptor(_ epoch: UInt8) throws -> AuditEpochDescriptor {
        try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(id(1)), 2: .bytes(id(2)), 3: .bytes(id(epoch)),
            4: .unsigned(7), 5: .unsigned(AuditEpochCause.restart.rawValue), 6: .null, 7: .null, 8: .null,
        ]), limits: bound), limits: bound)
    }
    private func record(_ sequence: UInt64, epoch: UInt8 = 3) throws -> Data {
        try AuditEventMetadata(eventID: id(UInt8(sequence)), macID: id(1), accountID: id(2), journalEpoch: id(epoch),
            sequence: sequence, requestID: id(8), eventTimeMs: nil, authorityReceiptTimeMs: nil,
            kind: .consumed, category: .command, action: nil, decisionPhoneID: nil, authentication: .system,
            outcome: .accepted, reason: .none, droppedEventCount: nil, peerDeviceID: nil).encode(limits: bound)
    }
    private func populate(_ database: JournalDatabase, epoch: UInt8 = 3, count: Int = 4) throws -> AuditEpochWriter {
        try database.write { transaction in
            let writer = try transaction.createEpoch(descriptor(epoch))
            for index in 0..<count {
                try transaction.append(record(UInt64(index + 1), epoch: epoch), writer: writer, expectedHead: UInt64(index))
            }
            return writer
        }
    }
    private func batch(_ reply: SignedAuditReply) throws -> AuditBatch {
        XCTAssertTrue(try AuditBatchSignature.verify(signature: reply.signature, publicKey: key.publicKey.x963Representation,
            wireVersion: reply.wireVersion, canonicalPayload: reply.canonicalBody, payloadLimits: bound, inputLimits: bound))
        return try AuditBatch.decode(reply.canonicalBody, batchLimits: bound, recordLimits: bound, maximumRecords: 4)
    }
    private func status(_ reply: SignedAuditReply) throws -> AuditHistoryStatus {
        XCTAssertTrue(try AuditHistoryStatusSignature.verify(signature: reply.signature, publicKey: key.publicKey.x963Representation,
            wireVersion: reply.wireVersion, canonicalPayload: reply.canonicalBody, payloadLimits: bound, inputLimits: bound))
        return try AuditHistoryStatus.decode(reply.canonicalBody, limits: bound, descriptorLimits: bound)
    }

    func testReadsCommittedPageAndReleasesTransactionBeforeSigning() throws {
        let fixture = try Fixture(bounds: bound), database = fixture.database
        let writer = try populate(database, count: 2)
        var calls = 0
        let reply = try builder(signer: { input in
            calls += 1
            try database.write { try $0.append(self.record(3), writer: writer, expectedHead: 2) }
            return try self.key.signature(for: input).rawRepresentation
        }).page(query(), journal: database)
        let result = try batch(reply)
        XCTAssertEqual(result.head, 2)
        XCTAssertEqual(result.records.map(\.sequence), [1, 2])
        XCTAssertEqual(calls, 1)
        XCTAssertEqual(try database.read { try $0.epoch(id(3))?.head }, 3)
    }

    func testHistoryUsesExplicitCurrentEpochAndPreservesOldUnavailableAndAheadStates() throws {
        let fixture = try Fixture(bounds: bound), database = fixture.database
        _ = try populate(database, count: 2)
        _ = try populate(database, epoch: 4, count: 0)
        let replies = try builder()
        let discovery = try status(replies.history(history(), journal: database, currentEpoch: id(4)))
        XCTAssertEqual(discovery.current.epoch, id(4)); XCTAssertEqual(discovery.currentHead, 0)
        XCTAssertEqual(discovery.disposition, .discovery)
        let old = try status(replies.history(history(epoch: 3, after: 1), journal: database, currentEpoch: id(4)))
        XCTAssertEqual(old.queried?.epoch, id(3)); XCTAssertEqual(old.queriedHead, 2)
        XCTAssertEqual(old.disposition, .available)
        let ahead = try status(replies.history(history(epoch: 3, after: 3), journal: database, currentEpoch: id(4)))
        XCTAssertEqual(ahead.disposition, .cursorAhead)
        let missing = try status(replies.history(history(epoch: 8, after: 0), journal: database, currentEpoch: id(4)))
        XCTAssertEqual(missing.disposition, .unavailable); XCTAssertNil(missing.queried)
        let same = try status(replies.history(history(epoch: 4, after: 0), journal: database, currentEpoch: id(4)))
        XCTAssertEqual(same.queriedHead, same.currentHead)
        XCTAssertTrue(try batch(replies.page(query(epoch: 4), journal: database)).records.isEmpty)
    }

    func testHistoryReleasesReadBeforeSignerAndKeepsItsSnapshot() throws {
        let fixture = try Fixture(bounds: bound), database = fixture.database
        _ = try populate(database, count: 1)
        let reply = try builder(signer: { input in
            try database.write { try $0.prune(epoch: self.id(3), through: 1, expectedHead: 1) }
            return try self.key.signature(for: input).rawRepresentation
        }).history(history(epoch: 3, after: 0), journal: database, currentEpoch: id(3))
        let result = try status(reply)
        XCTAssertEqual(result.currentRetainedAfter, 0); XCTAssertEqual(result.queriedRetainedAfter, 0)
        XCTAssertEqual(try database.read { try $0.epoch(id(3))?.retainedAfter }, 1)
    }

    func testRecordCountBodyBytesItemsAndSigningEnvelopeAllPaginateWithoutSkipping() throws {
        let fixture = try Fixture(bounds: bound), database = fixture.database
        _ = try populate(database)
        let read = try database.read { try XCTUnwrap($0.epoch(id(3))) }
        let one = try builder().page(query(), epoch: read, canonicalRecords: [record(1)])
        let signingSize = try AuditBatchSigningInput.make(wireVersion: 1, canonicalPayload: one.canonicalBody,
            payloadLimits: bound, inputLimits: bound).count
        let bytes = try CBORLimits(maxBytes: one.canonicalBody.count, maxDepth: 8, maxItems: 512)
        let items = try CBORLimits(maxBytes: 16384, maxDepth: 8, maxItems: 22)
        let signing = try CBORLimits(maxBytes: signingSize, maxDepth: 8, maxItems: 512)
        for custom in [try limits(count: 1), try limits(batch: bytes), try limits(batch: items), try limits(signing: signing)] {
            var calls = 0
            let replies = try builder(limits: custom, signer: { calls += 1; return try self.key.signature(for: $0).rawRepresentation })
            var cursor: UInt64 = 0
            for expected: UInt64 in 1...4 {
                let result = try batch(replies.page(query(after: cursor), journal: database))
                XCTAssertEqual(result.records.map(\.sequence), [expected])
                XCTAssertEqual(result.hasMore, expected < 4)
                cursor = result.nextAfter
            }
            XCTAssertEqual(calls, 4)
        }
    }

    func testRetentionGapAndFullyPrunedPageAreReported() throws {
        let fixture = try Fixture(bounds: bound), database = fixture.database
        _ = try populate(database)
        try database.write { try $0.prune(epoch: id(3), through: 2, expectedHead: 4) }
        let partial = try batch(builder().page(query(), journal: database))
        XCTAssertTrue(partial.retentionGap); XCTAssertEqual(partial.records.map(\.sequence), [3, 4])
        try database.write { try $0.prune(epoch: id(3), through: 4, expectedHead: 4) }
        let all = try batch(builder().page(query(), journal: database))
        XCTAssertTrue(all.retentionGap); XCTAssertTrue(all.records.isEmpty)
        XCTAssertEqual(all.nextAfter, 4); XCTAssertFalse(all.hasMore)
    }

    func testQueryScopeAndImpossibleBoundsFailBeforeSigning() throws {
        let fixture = try Fixture(bounds: bound), database = fixture.database
        _ = try populate(database)
        var calls = 0
        let sign: (Data) throws -> Data = { calls += 1; return try self.key.signature(for: $0).rawRepresentation }
        let replies = try builder(signer: sign)
        XCTAssertThrowsError(try replies.page(query(epoch: 8), journal: database))
        XCTAssertThrowsError(try replies.page(query(generation: 8), journal: database))
        XCTAssertThrowsError(try replies.page(query(after: 5), journal: database))
        XCTAssertThrowsError(try replies.history(history(), journal: database, currentEpoch: id(8)))
        XCTAssertThrowsError(try builder(mac: 8, signer: sign).page(query(), journal: database))
        XCTAssertThrowsError(try builder(mac: 8, signer: sign).history(history(), journal: database, currentEpoch: id(3)))
        let tiny = try CBORLimits(maxBytes: 16, maxDepth: 8, maxItems: 512)
        let one = try CBORLimits(maxBytes: 16384, maxDepth: 8, maxItems: 21)
        for custom in [try limits(batch: tiny), try limits(batch: one), try limits(signing: tiny)] {
            XCTAssertThrowsError(try builder(limits: custom, signer: sign).page(query(), journal: database))
        }
        XCTAssertEqual(calls, 0)
    }

    func testUnavailableOrCorruptStorageNeverProducesSignedEmptyHistory() throws {
        for failure in ["closed", "lease", "missingRecord"] {
            let fixture = try Fixture(bounds: bound), database = fixture.database
            _ = try populate(database)
            if failure == "closed" { try database.close() }
            if failure == "lease" { XCTAssertEqual(chmod(fixture.path, 0o644), 0) }
            if failure == "missingRecord" { try fixture.sql("DELETE FROM audit_records_v1") }
            var calls = 0
            let replies = try builder(signer: { calls += 1; return try self.key.signature(for: $0).rawRepresentation })
            XCTAssertThrowsError(try replies.page(query(), journal: database))
            if failure != "missingRecord" {
                XCTAssertThrowsError(try replies.history(history(), journal: database, currentEpoch: id(3)))
            }
            XCTAssertEqual(calls, 0)
        }
    }

    func testSignerFailureDoesNotMutateJournalOrPreventAnotherRead() throws {
        let fixture = try Fixture(bounds: bound), database = fixture.database
        _ = try populate(database, count: 1)
        let failed = try builder(signer: { _ in throw Failure.injected })
        XCTAssertThrowsError(try failed.page(query(), journal: database))
        XCTAssertThrowsError(try failed.history(history(), journal: database, currentEpoch: id(3)))
        XCTAssertEqual(try batch(builder().page(query(), journal: database)).records.count, 1)
    }

    private final class Fixture {
        let root: URL
        let database: JournalDatabase
        var path: String { root.appendingPathComponent("store/journal.sqlite").path }
        init(bounds: CBORLimits) throws {
            guard let canonical = realpath(FileManager.default.temporaryDirectory.path, nil) else { throw Failure.injected }
            defer { free(canonical) }
            root = URL(fileURLWithPath: String(cString: canonical)).appendingPathComponent(UUID().uuidString)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            let directory = root.appendingPathComponent("store").path
            try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            for name in ["writer.lock", "journal.sqlite"] {
                let fd = Darwin.open(directory + "/" + name, O_CREAT | O_EXCL | O_WRONLY, 0o600)
                guard fd >= 0 else { throw JournalLeaseError.system(errno) }
                Darwin.close(fd)
            }
            database = try JournalDatabase(lease: ProtectedJournalLease(anchor: root.path, relativeDirectory: "store", owner: getuid()),
                macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16),
                recordLimits: bounds, descriptorLimits: bounds, decisionLimits: bounds,
                maximumConsumptions: 10, busyMilliseconds: 100, initialize: true)
        }
        deinit { try? database.close(); try? FileManager.default.removeItem(at: root) }
        func sql(_ query: String) throws {
            var connection: OpaquePointer?
            guard sqlite3_open(path, &connection) == SQLITE_OK, let connection else { throw Failure.injected }
            defer { sqlite3_close(connection) }
            guard sqlite3_exec(connection, query, nil, nil, nil) == SQLITE_OK else { throw Failure.injected }
        }
    }
}
