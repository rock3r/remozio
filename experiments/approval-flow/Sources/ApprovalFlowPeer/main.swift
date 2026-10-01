import CryptoKit
import Darwin
import Foundation
import RemozioCore
import RemozioProtocol

// Synthetic peer only: stdin is the test controller, not an enrollment or network interface.
struct Input: Decodable {
    let command: String
    let authoritySeed: String?
    let phoneA: String?
    let phoneB: String?
    let body: String?
    let signature: String?
}

enum HarnessError: Error { case invalidInput, invalidState }
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
func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
func id(_ value: UInt8, count: Int = 16) -> Data { Data(repeating: value, count: count) }
func readInput() throws -> Input? {
    guard let line = readLine() else { return nil }
    guard line.utf8.count <= 140_000 else { throw HarnessError.invalidInput }
    return try JSONDecoder().decode(Input.self, from: Data(line.utf8))
}
func emit(_ fields: [String: String]) throws {
    let data = try JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys])
    FileHandle.standardOutput.write(data + Data([10]))
}

final class FakeAuthority {
    let limits = try! CBORLimits(maxBytes: 32768, maxDepth: 32, maxItems: 4096)
    let authority: P256.Signing.PrivateKey
    let epoch = UUID()
    let request: IssuedRequestPayload
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

    init(capture: Data, setup: Input) throws {
        guard setup.command == "setup" else { throw HarnessError.invalidInput }
        authority = try P256.Signing.PrivateKey(rawRepresentation: bytes(setup.authoritySeed))
        phoneA = try bytes(setup.phoneA)
        phoneB = try bytes(setup.phoneB)
        _ = try P256.Signing.PublicKey(x963Representation: phoneA)
        _ = try P256.Signing.PublicKey(x963Representation: phoneB)
        _ = try CommandCapture(canonicalBytes: capture, limits: limits)
        request = try IssuedRequestPayload(contract: RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1),
            macID: id(1), accountID: id(2), requestID: id(3), challenge: id(4, count: 32), requiredFeatures: [],
            createdUnixMilliseconds: 1000, expiresUnixMilliseconds: 1100, canonicalCapture: capture,
            permittedActions: [.init(choice: .execute, scope: .currentRequest)], bodyLimits: limits, captureLimits: limits)
    }

    func sign(_ body: Data, status: Bool) throws -> Data {
        try authority.signature(for: SigningInput.make(wireVersion: 1, messageType: status ? .status : .request,
            purpose: status ? .status : .issuedRequest, canonicalPayload: body,
            payloadLimits: limits, inputLimits: limits)).rawRepresentation
    }

    func status() throws -> [String: String] {
        let pending = phase == .queued || phase == .presented
        let body = try RequestStatusPayload(macID: request.macID, accountID: request.accountID, requestID: request.requestID,
            requestDigest: request.requestDigest(bodyLimits: limits, signingLimits: limits), challenge: request.challenge,
            revision: revision, phase: phase, reason: reason, observationID: id(7), observedAgeMs: now - 90,
            authorizationRemainingMs: pending ? (now < 200 ? 200 - now : 0) : nil,
            estimatedLifetimeMs: nil, lateObservation: false, terminalAgeMs: terminalAge, decisionPhoneID: winner).encode(limits: limits)
        return ["status": hex(body), "statusSignature": hex(try sign(body, status: true))]
    }

    func start() throws {
        let body = try request.encode(limits: limits)
        var frame = try status()
        frame["request"] = hex(body)
        frame["requestSignature"] = hex(try sign(body, status: false))
        frame["authorityKey"] = hex(authority.publicKey.x963Representation)
        try emit(frame)
    }

    func trust() throws -> ApprovalTrustSnapshot {
        let capabilities = ContractCapabilities(contracts: [request.contract: []])
        let a = try ApprovalEnrollment(phoneID: id(5), active: activeA, capabilities: capabilities,
            keys: [EnrolledApprovalKey(id: id(11), keyClass: narrowA ? .decision : .biometric, publicKey: phoneA)])
        let b = try ApprovalEnrollment(phoneID: id(6), active: true, capabilities: capabilities,
            keys: [EnrolledApprovalKey(id: id(12), keyClass: .biometric, publicKey: phoneB)])
        return try ApprovalTrustSnapshot(macID: request.macID, accountID: request.accountID, revision: UUID(),
            authorityCapabilities: capabilities, allowedContracts: [request.contract], enrollments: [a, b])
    }

    func handle(_ input: Input) throws {
        switch input.command {
        case "revokeA": activeA = false; try emit(["control": "revokedA"])
        case "narrowA": narrowA = true; try emit(["control": "narrowedA"])
        case "expireClock": now = 200; try emit(["control": "expiredClock"])
        case "decision":
            now = max(now, 150)
            do {
                let accepted = try DecisionVerifier.verify(canonicalDecision: bytes(input.body), signature: bytes(input.signature),
                    retained: RetainedApprovalRequest(payload: request, phase: phase,
                        admittedAt: AuthorityMoment(epoch: epoch, milliseconds: 100), deadlineMilliseconds: 200),
                    trust: trust(), now: AuthorityMoment(epoch: epoch, milliseconds: now),
                    decisionLimits: limits, requestLimits: limits, signingLimits: limits)
                // In-memory simulation only. This is not durable consumption or a dispatch permit.
                phase = try RequestLifecycle.transition(from: phase, event: .authorize)
                winner = accepted.decision.phoneID
                revision += 1
                var frame = try status()
                frame["decision"] = "accepted"
                try emit(frame)
            } catch {
                try emit(["rejection": String(describing: error)])
            }
        case "loseOutcome":
            guard phase == .authorized else { throw HarnessError.invalidState }
            now = max(now, 160)
            phase = try RequestLifecycle.transition(from: phase, event: .loseOutcome)
            reason = .outcomeUnavailable
            terminalAge = now - 90
            revision += 1
            try emit(status())
        default: throw HarnessError.invalidInput
        }
    }
}

do {
    guard geteuid() != 0, CommandLine.arguments.count == 2, let setup = try readInput() else {
        throw HarnessError.invalidInput
    }
    let captureURL = URL(fileURLWithPath: CommandLine.arguments[1])
    let size = try captureURL.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
    guard size > 0, size <= 32768 else { throw HarnessError.invalidInput }
    let peer = try FakeAuthority(capture: Data(contentsOf: captureURL), setup: setup)
    try peer.start()
    while let input = try readInput() { try peer.handle(input) }
} catch {
    FileHandle.standardError.write(Data("Synthetic approval peer failed.\n".utf8))
    exit(1)
}
