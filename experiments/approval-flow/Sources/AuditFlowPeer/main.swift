import CryptoKit
import Darwin
import Foundation
import RemozioCore
import RemozioProtocol

// Synthetic test controller only. This stdin protocol supplies no production channel authentication.
struct Input: Decodable {
    let command: String
    let nonce: String?
    let epoch: String?
    let generation: String?
    let after: String?
}
enum HarnessError: Error { case invalidInput, invalidState }
func id(_ value: UInt8, count: Int = 16) -> Data { Data(repeating: value, count: count) }
func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
func bytes(_ text: String?) throws -> Data {
    guard let text, text.count <= 64, text.count.isMultiple(of: 2) else { throw HarnessError.invalidInput }
    let chars = Array(text.utf8)
    return try Data(stride(from: 0, to: chars.count, by: 2).map {
        guard let byte = UInt8(String(decoding: chars[$0...$0 + 1], as: UTF8.self), radix: 16) else { throw HarnessError.invalidInput }
        return byte
    })
}
func number(_ text: String?) throws -> UInt64 {
    guard let text, text.count <= 20, let value = UInt64(text) else { throw HarnessError.invalidInput }
    return value
}
func readInput() throws -> Input? {
    var line = Data()
    while true {
        let next = getchar()
        if next == EOF {
            guard line.isEmpty else { throw HarnessError.invalidInput }
            return nil
        }
        if next == 10 { break }
        guard line.count < 4096 else { throw HarnessError.invalidInput }
        line.append(UInt8(next))
    }
    return try JSONDecoder().decode(Input.self, from: line)
}
func emit(_ fields: [String: String]) throws {
    let encoded = try JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys])
    guard encoded.count <= 140_000 else { throw HarnessError.invalidState }
    FileHandle.standardOutput.write(encoded + Data([10]))
}

final class SyntheticJournal {
    struct Epoch { let value: UInt8; var head: UInt64; var retained: UInt64; let cause: AuditEpochCause; let previous: UInt8? }
    let key = P256.Signing.PrivateKey()
    let bound = try! CBORLimits(maxBytes: 32768, maxDepth: 8, maxItems: 2048)
    var epochs: [UInt8: Epoch] = [3: Epoch(value: 3, head: 4, retained: 0, cause: .initial, previous: nil)]
    var current: UInt8 = 3

    func record(_ sequence: UInt64, epoch: UInt8) throws -> Data {
        guard (1...4).contains(sequence) else { throw HarnessError.invalidState }
        let kind: AuditEventKind = sequence == 4 ? .unknownOutcome : sequence == 3 ? .dispatched : sequence == 2 ? .decisionAccepted : .requestCreated
        let outcome: AuditOutcome = sequence == 4 ? .unresolved : sequence == 3 ? .attempted : sequence == 2 ? .accepted : .pending
        return try AuditEventMetadata(eventID: id(UInt8(sequence)), macID: id(1), accountID: id(2), journalEpoch: id(epoch),
            sequence: sequence, requestID: id(epoch + 5), eventTimeMs: nil, authorityReceiptTimeMs: nil,
            kind: kind, category: .command, action: nil, decisionPhoneID: nil, authentication: .system,
            outcome: outcome, reason: sequence == 4 ? .outcomeUnavailable : .none,
            droppedEventCount: nil, peerDeviceID: nil).encode(limits: bound)
    }
    func read(_ epoch: Epoch) throws -> AuditEpochRead {
        let priorDigest = try epoch.previous.map { Data(SHA256.hash(data: try record(1, epoch: $0))) }
        let header = try DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(id(1)), 2: .bytes(id(2)), 3: .bytes(id(epoch.value)),
            4: .unsigned(7), 5: .unsigned(epoch.cause.rawValue),
            6: epoch.previous.map { .bytes(id($0)) } ?? .null,
            7: epoch.previous.map { _ in .unsigned(1) } ?? .null, 8: priorDigest.map(CBORValue.bytes) ?? .null,
        ]), limits: bound)
        return try AuditEpochRead(descriptor: AuditEpochDescriptor.decode(header, limits: bound), retainedAfter: epoch.retained, head: epoch.head)
    }
    func builder() throws -> AuditReplyBuilder {
        try AuditReplyBuilder(macID: id(1), accountID: id(2), authorityPublicKey: key.publicKey.x963Representation,
            limits: AuditReplyLimits(batch: bound, record: bound, history: bound, descriptor: bound, signing: bound, maximumRecords: 2)) {
                try self.key.signature(for: $0).rawRepresentation
            }
    }
    func find(_ value: Data) -> Epoch? { epochs.values.first { id($0.value) == value } }
    func handle(_ input: Input) throws {
        let reply: SignedAuditReply
        switch input.command {
        case "history":
            let requested = try input.epoch.map { try bytes($0) }
            let after = try input.after.map { try number($0) }
            let query = try AuditHistoryRequest(nonce: bytes(input.nonce), epoch: requested, after: after)
            let old = try requested.flatMap(find).map(read)
            guard let active = epochs[current] else { throw HarnessError.invalidState }
            reply = try builder().history(query, current: read(active), queried: old)
        case "page":
            let query = try AuditPageRequest(nonce: bytes(input.nonce), epoch: bytes(input.epoch),
                generation: number(input.generation), after: number(input.after))
            guard let epoch = find(query.epoch) else { throw HarnessError.invalidState }
            let start = max(query.after, epoch.retained)
            guard start <= epoch.head else { throw HarnessError.invalidInput }
            let count = min(UInt64(2), epoch.head - start)
            let records = try (0..<count).map { try record(start + $0 + 1, epoch: epoch.value) }
            reply = try builder().page(query, epoch: read(epoch), canonicalRecords: records)
        case "restore":
            guard current == 3 else { throw HarnessError.invalidState }
            epochs[3]?.head = 1
            epochs[4] = Epoch(value: 4, head: 2, retained: 0, cause: .restoration, previous: 3)
            current = 4
            try emit(["control": "restored"]); return
        case "forgetOld":
            guard current == 4 else { throw HarnessError.invalidState }
            epochs.removeValue(forKey: 3)
            try emit(["control": "forgotOld"]); return
        case "pruneCurrent":
            guard let head = epochs[current]?.head else { throw HarnessError.invalidState }
            epochs[current]?.retained = head
            try emit(["control": "pruned"]); return
        default: throw HarnessError.invalidInput
        }
        try emit(["kind": reply.kind == .page ? "page" : "history", "wireVersion": String(reply.wireVersion),
            "body": hex(reply.canonicalBody), "signature": hex(reply.signature)])
    }
}

do {
    guard geteuid() != 0, CommandLine.arguments.count == 1 else { throw HarnessError.invalidInput }
    let journal = SyntheticJournal()
    try emit(["authorityKey": hex(journal.key.publicKey.x963Representation)])
    while let input = try readInput() { try journal.handle(input) }
} catch {
    FileHandle.standardError.write(Data("Synthetic audit peer failed.\n".utf8))
    exit(1)
}
