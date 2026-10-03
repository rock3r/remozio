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
    let phoneADecision: String?
    let phoneBDecision: String?
    let channelPhone: String?
    let channelEpoch: String?
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

final class SyntheticAuthority {
    let limits = try! CBORLimits(maxBytes: 32768, maxDepth: 32, maxItems: 4096)
    let authority: P256.Signing.PrivateKey
    let epoch = UUID()
    let journal: JournalFixture
    var owner: ApprovalRequestCoordinator
    let binding: ApprovalRequestState
    var delivery: PendingRequestDelivery?
    var activeDeliveries = 0
    var withdrawnDeliveries = 0
    var failNextConsumption = false
    var failNextOutcome = false
    var now: UInt64 = 100
    var revision: UInt64 = 0
    struct RecoveryObservation {
        let phase: RequestPhase
        let reason: RequestStatusReason
        let winner: Data?
        let terminalAge: UInt64
    }
    var recovered: RecoveryObservation?
    var moment: AuthorityMoment { .init(epoch: epoch, milliseconds: now) }

    init(capture: Data, setup: Input, directory: String) throws {
        guard setup.command == "setup" else { throw HarnessError.invalidInput }
        authority = try P256.Signing.PrivateKey(rawRepresentation: bytes(setup.authoritySeed))
        _ = try CommandCapture(canonicalBytes: capture, limits: limits)
        let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1)
        let capabilities = ContractCapabilities(contracts: [contract: []])
        let journal = try JournalFixture(directory: directory, limits: limits)
        self.journal = journal
        var trustRevision = try journal.database.write {
            try $0.configureApprovalAuthority(capabilities: capabilities, allowedContracts: [contract])
        }
        for (phone, biometric, decision) in [(UInt8(5), setup.phoneA, setup.phoneADecision), (UInt8(6), setup.phoneB, setup.phoneBDecision)] {
            let enrollment = try StoredApprovalEnrollment(epoch: id(phone + 20), notificationTag: id(phone, count: 32),
                identityPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
                approval: ApprovalEnrollment(phoneID: id(phone), active: true, capabilities: capabilities, keys: [
                    EnrolledApprovalKey(id: id(phone + 6), keyClass: .biometric, publicKey: bytes(biometric)),
                    EnrolledApprovalKey(id: id(phone + 8), keyClass: .decision, publicKey: bytes(decision)),
                ]))
            trustRevision = try journal.database.write { tx in
                guard let head = try tx.epoch(journal.writer.epoch)?.head else { throw HarnessError.invalidState }
                return try tx.addApprovalEnrollment(enrollment, expectedTrustRevision: trustRevision,
                    eventID: randomID(), receiptTimeMs: nil, writer: journal.writer, expectedAuditHead: head)
            }
        }
        let owner = try Self.makeOwner(journal, epoch: epoch, limits: limits)
        self.owner = owner
        let payload = try owner.admit(ApprovalRequestDraft(contract: contract, requiredFeatures: [], capture: capture,
            actions: [.init(choice: .execute, scope: .currentRequest), .init(choice: .decline, scope: .currentRequest)],
            firstObservedAt: .init(epoch: epoch, milliseconds: 90), deadlineMilliseconds: 200,
            createdUnixMilliseconds: 1000, expiresUnixMilliseconds: 1100),
            now: .init(epoch: epoch, milliseconds: 100), receiptTimeMs: nil)
        binding = try owner.markPresented(requestID: payload.requestID, now: .init(epoch: epoch, milliseconds: 100), receiptTimeMs: nil)
        delivery = try PendingRequestDelivery(request: owner.pendingRequest(requestID: binding.requestID,
            now: .init(epoch: epoch, milliseconds: 100), receiptTimeMs: nil))
        try reconcileDelivery()
    }

    static func makeOwner(_ journal: JournalFixture, epoch: UUID, limits: CBORLimits) throws -> ApprovalRequestCoordinator {
        try .init(database: journal.database, writer: journal.writer, clockEpoch: epoch,
            maximumRequests: 8, maximumRetainedBytes: 65536, requestLimits: limits, captureLimits: limits,
            decisionLimits: limits, signingLimits: limits, auditLimits: limits)
    }

    func sign(_ body: Data, status: Bool) throws -> Data {
        try authority.signature(for: SigningInput.make(wireVersion: 1, messageType: status ? .status : .request,
            purpose: status ? .status : .issuedRequest, canonicalPayload: body,
            payloadLimits: limits, inputLimits: limits)).rawRepresentation
    }

    func reconcileDelivery() throws {
        guard let delivery else { return }
        var router = PresenceRouter(configuration: try .init(observationLifetimeMilliseconds: 100, unavailableGraceMilliseconds: 0))
        let routing = router.evaluate(mode: .away, snapshot: .init(), now: .init(epoch: epoch, milliseconds: now))
        let update = try owner.reconcileDelivery(requestID: binding.requestID, delivery: delivery,
            routing: routing, now: moment, receiptTimeMs: nil) { _ in true }
        activeDeliveries = update.active.count
        withdrawnDeliveries += update.withdrawn.count
        if update.closure != nil { self.delivery = nil }
    }

    func status() throws -> [String: String] {
        revision += 1
        let payload: RequestStatusPayload
        if let recovered {
            // Only the private restart simulation uses cached status metadata. It cannot rebuild an execution binding.
            payload = try RequestStatusPayload(macID: binding.macID, accountID: binding.accountID, requestID: binding.requestID,
                requestDigest: binding.requestDigest, challenge: binding.challenge, revision: revision,
                phase: recovered.phase, reason: recovered.reason, observationID: id(7),
                observedAgeMs: now - binding.firstObservedAt.milliseconds, authorizationRemainingMs: nil,
                estimatedLifetimeMs: nil, lateObservation: false, terminalAgeMs: recovered.terminalAge, decisionPhoneID: recovered.winner)
        } else {
            payload = try owner.state(requestID: binding.requestID).statusPayload(observationID: id(7),
                observationRevision: revision, now: moment, estimatedLifetimeMs: nil, lateObservation: false)
        }
        let body = try payload.encode(limits: limits)
        let signature = try sign(body, status: true)
        let message = try ApprovalMessage(wireVersion: 1, type: .status, purpose: .status, body: body, signature: signature)
        return ["status": hex(body), "statusSignature": hex(signature), "statusMessage": hex(try message.encode(maximumBodyBytes: limits.maxBytes))]
    }

    func start() throws {
        let request = try owner.pendingRequest(requestID: binding.requestID, now: moment, receiptTimeMs: nil)
        let body = try request.payload.encode(limits: limits)
        var frame = try status()
        frame["request"] = hex(body)
        let signature = try sign(body, status: false)
        frame["requestSignature"] = hex(signature)
        frame["requestMessage"] = hex(try ApprovalMessage(wireVersion: 1, type: .request, purpose: .issuedRequest,
            body: body, signature: signature).encode(maximumBodyBytes: limits.maxBytes))
        frame["authorityKey"] = hex(authority.publicKey.x963Representation)
        try emit(frame)
    }

    func recordOutcome(_ event: RequestEvent) throws {
        now = max(now, 160)
        let inject = failNextOutcome
        failNextOutcome = false
        guard let current = try owner.historicalOutcome(requestID: binding.requestID) else { throw HarnessError.invalidState }
        _ = try journal.withAuditFailure(inject) {
            try owner.recordOutcome(requestID: binding.requestID, expectedRevision: current.revision,
                event: event, now: moment, receiptTimeMs: nil)
        }
        try reconcileDelivery()
    }

    func reopen() throws {
        now = max(now, 170)
        if recovered == nil {
            let current = try owner.state(requestID: binding.requestID)
            if current.phase == .queued || current.phase == .presented {
                _ = try owner.retirePending(requestID: binding.requestID, reason: .authorityRestart, now: moment, receiptTimeMs: nil)
            }
            try reconcileDelivery()
            let terminal = try owner.state(requestID: binding.requestID)
            if terminal.phase.isTerminal {
                let status = try terminal.statusPayload(observationID: id(7), observationRevision: revision + 1,
                    now: moment, estimatedLifetimeMs: nil, lateObservation: false)
                recovered = RecoveryObservation(phase: status.phase, reason: status.reason, winner: status.decisionPhoneID,
                    terminalAge: status.terminalAgeMs!)
            }
        }
        try journal.reopen()
        if let outcome = try journal.database.read({ try $0.consumptionOutcome(requestID: binding.requestID) }), !outcome.phase.isTerminal {
            // Explicit test recovery observation, after the old execution binding has been abandoned.
            let terminal = try journal.database.write { tx in
                guard let head = try tx.epoch(journal.writer.epoch)?.head else { throw HarnessError.invalidState }
                return try tx.transitionConsumption(requestID: binding.requestID, expectedRevision: outcome.revision,
                    event: .restartAuthority, eventID: randomID(), receiptTimeMs: nil, writer: journal.writer, expectedHead: head)
            }
            recovered = RecoveryObservation(phase: terminal.phase, reason: .authorityRestarted,
                winner: terminal.receipt.decision.phoneID, terminalAge: now - binding.firstObservedAt.milliseconds)
        }
        owner = try Self.makeOwner(journal, epoch: epoch, limits: limits)
        guard recovered != nil else { throw HarnessError.invalidState }
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
        case "revokeA":
            _ = try journal.database.write { tx in
                guard let head = try tx.epoch(journal.writer.epoch)?.head else { throw HarnessError.invalidState }
                return try tx.revokeApprovalEnrollment(phoneID: id(5), epoch: id(25), expectedTrustRevision: tx.approvalTrustSnapshot().revision,
                    eventID: randomID(), receiptTimeMs: nil, writer: journal.writer, expectedAuditHead: head)
            }
            try reconcileDelivery()
            try emit(["control": "revokedA"])
        case "expireClock": now = 200; try emit(["control": "expiredClock"])
        case "decision":
            now = max(now, 150)
            do {
                let inject = failNextConsumption
                failNextConsumption = false
                _ = try journal.withAuditFailure(inject) {
                    try owner.consume(canonicalDecision: bytes(input.body), signature: bytes(input.signature),
                        authenticatedPhoneID: bytes(input.channelPhone), authenticatedEnrollmentEpoch: bytes(input.channelEpoch),
                        now: moment, receiptTimeMs: nil)
                }
                try reconcileDelivery()
                var frame = try status(); frame["decision"] = "accepted"; try emit(frame)
            } catch {
                try reconcileDelivery()
                try emit(["rejection": String(describing: error)])
            }
        case "failNextConsumption": failNextConsumption = true; try emit(["control": "consumptionFailureArmed"])
        case "failNextOutcome": failNextOutcome = true; try emit(["control": "outcomeFailureArmed"])
        case "auditHistory", "auditPage": try auditReply(input)
        case "journalSnapshot":
            try reconcileDelivery()
            var snapshot = try journal.snapshot(requestID: binding.requestID)
            var retained = false
            if recovered == nil {
                let state = try owner.state(requestID: binding.requestID)
                if state.phase == .queued || state.phase == .presented {
                    _ = try owner.pendingRequest(requestID: binding.requestID, now: moment, receiptTimeMs: nil); retained = true
                } else if state.phase == .authorized || state.phase == .executing {
                    _ = try owner.consumedRequest(requestID: binding.requestID, now: moment); retained = true
                }
                snapshot["ownedPhase"] = state.phase.rawValue
            }
            snapshot["retainedCapture"] = retained ? "true" : "false"
            snapshot["activeDeliveries"] = String(activeDeliveries)
            snapshot["withdrawnDeliveries"] = String(withdrawnDeliveries)
            snapshot["liveOwned"] = (try? owner.state(requestID: binding.requestID)) == nil ? "false" : "true"
            try emit(snapshot)
        case "status": now += 10; try reconcileDelivery(); try emit(status())
        case "disappear":
            now = max(now, 150)
            _ = try owner.retirePending(requestID: binding.requestID, reason: .targetDisappeared, now: moment, receiptTimeMs: nil)
            try reconcileDelivery(); try emit(status())
        case "loseOutcome", "beginDispatch", "verifySuccess":
            do {
                let event: RequestEvent = input.command == "loseOutcome" ? .loseOutcome : input.command == "beginDispatch" ? .beginDispatch : .verifySuccess
                try recordOutcome(event); try emit(status())
            } catch { try emit(["rejection": String(describing: error)]) }
        case "reopenJournal": try reopen(); try emit(status())
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
    let peer = try SyntheticAuthority(capture: Data(contentsOf: captureURL), setup: setup, directory: CommandLine.arguments[2])
    try peer.start()
    while let input = try readInput() { try peer.handle(input) }
} catch {
    FileHandle.standardError.write(Data("Synthetic approval peer failed.\n".utf8))
    exit(1)
}
