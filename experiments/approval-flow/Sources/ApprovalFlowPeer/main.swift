import CryptoKit
import Darwin
import Foundation
@testable import RemozioCore
import RemozioProtocol

// Synthetic peer only: stdin is the test controller, not an enrollment or network interface.
struct Input: Decodable {
    let command: String
    let authoritySeed: String?
    let phoneA: String?
    let phoneB: String?
    let body: String?
    let signature: String?
    let nonce: String?
    let epoch: String?
    let generation: String?
    let after: String?
}

enum HarnessError: Error { case invalidInput, invalidState, injectedPrecommitFailure }
func bytes(_ hex: String?) throws -> Data {
    guard let hex, hex.count <= 65_536, hex.count.isMultiple(of: 2) else { throw HarnessError.invalidInput }
    let chars = Array(hex.utf8)
    var output = Data()
    for index in stride(from: 0, to: chars.count, by: 2) {
        guard let byte = UInt8(String(decoding: chars[index...index + 1], as: UTF8.self), radix: 16) else {
            throw HarnessError.invalidInput
        }
        output.append(byte)
    }
    return output
}
func number(_ text: String?) throws -> UInt64 {
    guard let text, !text.isEmpty, text.utf8.count <= 20,
          text.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }), let value = UInt64(text) else { throw HarnessError.invalidInput }
    return value
}
func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
func id(_ value: UInt8, count: Int = 16) -> Data { Data(repeating: value, count: count) }
func readInput() throws -> Input? {
    var line = Data()
    while true {
        let next = getchar()
        if next == EOF {
            guard line.isEmpty else { throw HarnessError.invalidInput }
            return nil
        }
        if next == 10 { break }
        guard line.count < 140_000 else { throw HarnessError.invalidInput }
        line.append(UInt8(next))
    }
    return try JSONDecoder().decode(Input.self, from: line)
}
func emit(_ fields: [String: String]) throws {
    let data = try JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys])
    guard data.count <= 140_000 else { throw HarnessError.invalidState }
    FileHandle.standardOutput.write(data + Data([10]))
}

final class FakeAuthority {
    let limits = try! CBORLimits(maxBytes: 32768, maxDepth: 32, maxItems: 4096)
    let authority: P256.Signing.PrivateKey
    let epoch = UUID()
    var request: IssuedRequestPayload?
    let requestDigest: Data
    let contract: RequestContract
    let journal: JournalFixture
    var failNextConsumption = false
    var failNextOutcome = false
    let phoneA: Data
    let phoneB: Data
    var activeA = true
    var narrowA = false
    var phase = RequestPhase.presented
    var reason = RequestStatusReason.none
    var winner: Data?
    var now: UInt64 = 100
    var revision: UInt64 = 1
    var terminalAge: UInt64?

    init(capture: Data, setup: Input, directory: String) throws {
        guard setup.command == "setup" else { throw HarnessError.invalidInput }
        authority = try P256.Signing.PrivateKey(rawRepresentation: bytes(setup.authoritySeed))
        phoneA = try bytes(setup.phoneA)
        phoneB = try bytes(setup.phoneB)
        _ = try P256.Signing.PublicKey(x963Representation: phoneA)
        _ = try P256.Signing.PublicKey(x963Representation: phoneB)
        _ = try CommandCapture(canonicalBytes: capture, limits: limits)
        contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1)
        let payload = try IssuedRequestPayload(contract: contract,
            macID: id(1), accountID: id(2), requestID: id(3), challenge: id(4, count: 32), requiredFeatures: [],
            createdUnixMilliseconds: 1000, expiresUnixMilliseconds: 1100, canonicalCapture: capture,
            permittedActions: [.init(choice: .execute, scope: .currentRequest)], bodyLimits: limits, captureLimits: limits)
        request = payload
        requestDigest = try payload.requestDigest(bodyLimits: limits, signingLimits: limits)
        journal = try JournalFixture(directory: directory, limits: limits)
    }

    func sign(_ body: Data, status: Bool) throws -> Data {
        try authority.signature(for: SigningInput.make(wireVersion: 1, messageType: status ? .status : .request,
            purpose: status ? .status : .issuedRequest, canonicalPayload: body,
            payloadLimits: limits, inputLimits: limits)).rawRepresentation
    }

    func status() throws -> [String: String] {
        let pending = phase == .queued || phase == .presented
        let body = try RequestStatusPayload(macID: id(1), accountID: id(2), requestID: id(3),
            requestDigest: requestDigest, challenge: id(4, count: 32),
            revision: revision, phase: phase, reason: reason, observationID: id(7), observedAgeMs: now - 90,
            authorizationRemainingMs: pending ? (now < 200 ? 200 - now : 0) : nil,
            estimatedLifetimeMs: nil, lateObservation: false, terminalAgeMs: terminalAge, decisionPhoneID: winner).encode(limits: limits)
        return ["status": hex(body), "statusSignature": hex(try sign(body, status: true))]
    }

    func start() throws {
        guard let request else { throw HarnessError.invalidState }
        let body = try request.encode(limits: limits)
        var frame = try status()
        frame["request"] = hex(body)
        frame["requestSignature"] = hex(try sign(body, status: false))
        frame["authorityKey"] = hex(authority.publicKey.x963Representation)
        try emit(frame)
    }

    func trust() throws -> ApprovalTrustSnapshot {
        let capabilities = ContractCapabilities(contracts: [contract: []])
        let a = try ApprovalEnrollment(phoneID: id(5), active: activeA, capabilities: capabilities,
            keys: [EnrolledApprovalKey(id: id(11), keyClass: narrowA ? .decision : .biometric, publicKey: phoneA)])
        let b = try ApprovalEnrollment(phoneID: id(6), active: true, capabilities: capabilities,
            keys: [EnrolledApprovalKey(id: id(12), keyClass: .biometric, publicKey: phoneB)])
        return try ApprovalTrustSnapshot(macID: id(1), accountID: id(2), revision: UUID(),
            authorityCapabilities: capabilities, allowedContracts: [contract], enrollments: [a, b])
    }

    func apply(_ outcome: ConsumptionOutcome) {
        phase = outcome.phase
        winner = outcome.receipt.decision.phoneID
        switch phase {
        case .unknown: reason = outcome.event.reason == .authorityRestarted ? .authorityRestarted : .outcomeUnavailable
        case .succeeded, .failed: reason = .verifiedResult
        case .declined: reason = .declined
        case .cancelled: reason = .noDispatchProved
        default: reason = .none
        }
        if phase.isTerminal { terminalAge = terminalAge ?? now - 90; request = nil }
    }

    func recordOutcome(_ event: RequestEvent) throws {
        now = max(now, 160)
        let inject = failNextOutcome
        failNextOutcome = false
        let outcome = try journal.database.write { transaction in
            guard let current = try transaction.consumptionOutcome(requestID: id(3)),
                  let epoch = try transaction.epoch(journal.writer.epoch) else { throw HarnessError.invalidState }
            let outcome = try transaction.transitionConsumption(requestID: id(3), expectedRevision: current.revision,
                event: event, eventID: randomID(), receiptTimeMs: nil, writer: journal.writer, expectedHead: epoch.head)
            if inject { throw HarnessError.injectedPrecommitFailure }
            return outcome
        }
        apply(outcome)
        revision += 1
    }

    func auditReply(_ input: Input) throws {
        let builder = try AuditReplyBuilder(macID: id(1), accountID: id(2), authorityPublicKey: authority.publicKey.x963Representation,
            limits: AuditReplyLimits(batch: limits, record: limits, history: limits, descriptor: limits,
                signing: limits, maximumRecords: 2)) { try self.authority.signature(for: $0).rawRepresentation }
        let reply: SignedAuditReply
        if input.command == "auditHistory" {
            reply = try builder.history(AuditHistoryRequest(nonce: bytes(input.nonce), epoch: input.epoch.map { try bytes($0) },
                after: input.after.map { try number($0) }), journal: journal.database, currentEpoch: journal.writer.epoch)
        } else {
            reply = try builder.page(AuditPageRequest(nonce: bytes(input.nonce), epoch: bytes(input.epoch),
                generation: number(input.generation), after: number(input.after)), journal: journal.database)
        }
        try emit(["kind": reply.kind == .page ? "page" : "history", "wireVersion": String(reply.wireVersion),
            "body": hex(reply.canonicalBody), "signature": hex(reply.signature)])
    }

    func handle(_ input: Input) throws {
        switch input.command {
        case "revokeA": activeA = false; try emit(["control": "revokedA"])
        case "narrowA": narrowA = true; try emit(["control": "narrowedA"])
        case "expireClock": now = 200; try emit(["control": "expiredClock"])
        case "decision":
            now = max(now, 150)
            do {
                guard let request else { throw DecisionVerificationError.unavailableRequest }
                let inject = failNextConsumption
                failNextConsumption = false
                let accepted = try journal.database.write { transaction in
                    guard let current = try transaction.epoch(journal.writer.epoch) else { throw HarnessError.invalidState }
                    let receipt = try transaction.consume(canonicalDecision: bytes(input.body), signature: bytes(input.signature),
                        retained: RetainedApprovalRequest(payload: request, phase: phase,
                            admittedAt: AuthorityMoment(epoch: epoch, milliseconds: 100), deadlineMilliseconds: 200),
                        trust: trust(), now: AuthorityMoment(epoch: epoch, milliseconds: now), eventID: randomID(), receiptTimeMs: nil,
                        writer: journal.writer, expectedHead: current.head, requestLimits: limits, signingLimits: limits)
                    if inject { throw HarnessError.injectedPrecommitFailure }
                    return receipt
                }
                phase = .authorized
                winner = accepted.decision.phoneID
                revision += 1
                var frame = try status()
                frame["decision"] = "accepted"
                try emit(frame)
            } catch {
                try emit(["rejection": String(describing: error)])
            }
        case "failNextConsumption": failNextConsumption = true; try emit(["control": "consumptionFailureArmed"])
        case "failNextOutcome": failNextOutcome = true; try emit(["control": "outcomeFailureArmed"])
        case "auditHistory", "auditPage": try auditReply(input)
        case "journalSnapshot":
            var snapshot = try journal.snapshot()
            snapshot["retainedCapture"] = request == nil ? "false" : "true"
            try emit(snapshot)
        case "loseOutcome", "beginDispatch", "verifySuccess":
            do {
                let event: RequestEvent = input.command == "loseOutcome" ? .loseOutcome : input.command == "beginDispatch" ? .beginDispatch : .verifySuccess
                try recordOutcome(event)
                try emit(status())
            } catch { try emit(["rejection": String(describing: error)]) }
        case "reopenJournal":
            // Drop the pending capture. Cached request identity remains only to sign this test session's status.
            request = nil
            try journal.reopen()
            now = max(now, 170)
            if let outcome = try journal.database.read({ try $0.consumptionOutcome(requestID: id(3)) }) {
                if outcome.phase.isTerminal { apply(outcome); revision += 1 }
                else { try recordOutcome(.restartAuthority) }
            } else {
                phase = .cancelled; reason = .authorityRestarted; terminalAge = now - 90; revision += 1
            }
            try emit(status())
        default: throw HarnessError.invalidInput
        }
    }
}

do {
    guard geteuid() != 0, CommandLine.arguments.count == 3, let setup = try readInput() else {
        throw HarnessError.invalidInput
    }
    let captureURL = URL(fileURLWithPath: CommandLine.arguments[1])
    let size = try captureURL.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
    guard size > 0, size <= 32768 else { throw HarnessError.invalidInput }
    let peer = try FakeAuthority(capture: Data(contentsOf: captureURL), setup: setup, directory: CommandLine.arguments[2])
    try peer.start()
    while let input = try readInput() { try peer.handle(input) }
} catch {
    FileHandle.standardError.write(Data("Synthetic approval peer failed.\n".utf8))
    exit(1)
}
