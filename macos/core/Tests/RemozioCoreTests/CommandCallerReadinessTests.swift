import CryptoKit
import Darwin
import Foundation
import os
import RemozioMach
import RemozioProtocol
import Security
import XCTest
@testable import RemozioCore

final class CommandCallerReadinessTests: XCTestCase {
    private let mac = Data(repeating: 1, count: 16), account = Data(repeating: 2, count: 16)
    private enum Cancelled: Error { case stopped }
    private enum Reply: Sendable {
        case result(CommandAdmissionOutcome), lost, malformed, wrongDigest
    }
    private final class Endpoint {
        let port: mach_port_t
        init() throws {
            var value: mach_port_t = 0
            guard mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &value) == KERN_SUCCESS else {
                throw MachCommandCallerError.configuration
            }
            guard mach_port_insert_right(mach_task_self_, value, value, UInt32(MACH_MSG_TYPE_MAKE_SEND)) == KERN_SUCCESS else {
                _ = mach_port_mod_refs(mach_task_self_, value, MACH_PORT_RIGHT_RECEIVE, -1); throw MachCommandCallerError.configuration
            }
            port = value
        }
        deinit {
            _ = mach_port_mod_refs(mach_task_self_, port, MACH_PORT_RIGHT_RECEIVE, -1)
            _ = mach_port_deallocate(mach_task_self_, port)
        }
    }
    private struct Server {
        let completed: DispatchSemaphore
        let results: OSAllocatedUnfairLock<Result<Void, Error>?>
        let submissions: OSAllocatedUnfairLock<[CommandSubmission]>
        func finish() throws -> [CommandSubmission] {
            XCTAssertEqual(completed.wait(timeout: .now() + 5), .success)
            try results.withLock { try XCTUnwrap($0).get() }
            return submissions.withLock { $0 }
        }
    }
    private func expression() throws -> String {
        var code: SecCode?, information: CFDictionary?
        XCTAssertEqual(SecCodeCopySelf([], &code), errSecSuccess)
        XCTAssertEqual(remozio_copy_dynamic_signing_information(try XCTUnwrap(code), &information), errSecSuccess)
        let values = try XCTUnwrap(information as? [String: Any]), hash = try XCTUnwrap(values[kSecCodeInfoUnique as String] as? Data)
        return "cdhash H\"" + hash.map { String(format: "%02x", $0) }.joined() + "\""
    }
    private func limits() throws -> CBORLimits { try .init(maxBytes: 8192, maxDepth: 16, maxItems: 1024) }
    private func template() throws -> CommandSubmission {
        try .init(schemaVersion: 1, executablePath: Data("/usr/bin/true".utf8),
            arguments: [Data("raw argv0".utf8), Data(), Data([0xff, 0x0a])], directoryPath: Data("/tmp".utf8),
            requestedTargetUID: 1234, environmentAdditions: [.init(name: Data("RAW".utf8), value: Data([0xfe, 0x22]))],
            ioMode: .pipes, disconnectBehavior: .terminate, unverifiedRationale: "original rationale",
            binding: .init(id: Data(repeating: 9, count: 16), nonce: Data(repeating: 8, count: 32),
                callerBinding: Data(repeating: 7, count: 16)), limits: limits())
    }
    private func busy(_ reason: CommandAdmissionRejectionReason) -> Reply {
        .result(.notAdmitted(reason, CommandAdmissionRetryClass(rawValue: reason.rawValue)!))
    }
    private func serve(_ endpoint: Endpoint, replies: [Reply], io: Bool = false) throws -> Server {
        let port = endpoint.port, expression = try expression(), user = geteuid(), mac = mac, account = account
        let completed = DispatchSemaphore(value: 0), results = OSAllocatedUnfairLock(initialState: Result<Void, Error>?.none)
        let submissions = OSAllocatedUnfairLock(initialState: [CommandSubmission]())
        DispatchQueue.global().async {
            defer { completed.signal() }
            let result = Result<Void, Error> {
                let receiver = try MachCommandCallerReceiver(receivePort: port, expression: expression, userID: user,
                    auditSessionID: nil, maxPayloadBytes: 8192)
                for reply in replies {
                    let session = try RetainedCommandHandshake(hello: receiver.receiveHello(timeoutMilliseconds: 5000),
                        capabilities: io ? .executionChannels : .admissionResults, macID: mac, accountID: account, expression: expression,
                        userID: user, auditSessionID: nil)
                    defer { session.close() }
                    let input = try io ? receiver.receiveIOInput(timeoutMilliseconds: 5000) : receiver.receiveAdmissionInput(timeoutMilliseconds: 5000)
                    defer { input.closeIfUnclaimed() }
                    let submission = try CommandSubmission(canonicalBytes: input.payload,
                        limits: CBORLimits(maxBytes: 8192, maxDepth: 16, maxItems: 1024), expectedSchemaVersion: 1)
                    submissions.withLock { $0.append(submission) }
                    let outcome: CommandAdmissionOutcome
                    switch reply {
                    case .lost: continue
                    case .malformed: try input.sendAdmissionReply(Data([0xa0])); continue
                    case .wrongDigest: outcome = .notAdmitted(.updateWaiting, .updateWaiting)
                    case .result(let value): outcome = value
                    }
                    let digest = Data(SHA256.hash(data: submission.canonicalBytes))
                    let replyDigest = if case .wrongDigest = reply { Data(repeating: 0, count: 32) } else { digest }
                    let payload = CommandAdmissionResultPayload(profile: session.profile, submission: submission.binding,
                        submissionDigest: replyDigest, outcome: outcome)
                    try input.sendAdmissionReply(payload.canonicalBytes)
                    if io, case .admitted(let request) = outcome {
                        try XCTUnwrap(input.outputs).sendTerminalResult(CommandTerminalResultPayload(profile: session.profile,
                            original: submission, request: request, outcome: .exited(13)).canonicalBytes, timeoutMilliseconds: 1000)
                    }
                }
            }
            results.withLock { $0 = result }
        }
        return Server(completed: completed, results: results, submissions: submissions)
    }
    private func submit(_ endpoint: Endpoint, fd: Int32, configuration: CommandCallerReadinessConfiguration? = nil,
                        cancellation: () throws -> Void = {}, status: (CommandCallerReadinessStatus) -> Void = { _ in },
                        clock: (() throws -> UInt64)? = nil, wait: ((UInt32, () throws -> Void) throws -> Void)? = nil,
                        lookup: (() throws -> mach_port_t)? = nil) throws -> VerifiedCommandAdmissionResult {
        try CommandCallerReadiness.submit(template(), inputDescriptor: fd, authorityPort: lookup ?? { endpoint.port },
            expression: expression(), userID: geteuid(), auditSessionID: nil, macID: mac, accountID: account,
            submissionLimits: limits(), configuration: configuration ?? .init(timeoutMilliseconds: 5000,
                initialBackoffMilliseconds: 1, maximumBackoffMilliseconds: 4, controlTimeoutMilliseconds: 1000),
            checkCancellation: cancellation, onStatus: status, clock: clock, wait: wait)
    }
    private func assertNoNextAttempt(_ endpoint: Endpoint) throws {
        let receiver = try MachCommandCallerReceiver(receivePort: endpoint.port, expression: expression(), userID: geteuid(),
            auditSessionID: nil, maxPayloadBytes: 8192)
        XCTAssertThrowsError(try receiver.receiveNext(timeoutMilliseconds: 20)) { XCTAssertEqual($0 as? MachCommandCallerError, .timeout) }
    }

    func testAllBusyClassesMakeFreshSubmissionsAndPreserveInvocationAndUnreadPipe() throws {
        let endpoint = try Endpoint(), admitted = CommandAdmittedRequest(requestID: Data(repeating: 3, count: 16),
            requestDigest: Data(repeating: 4, count: 32), challenge: Data(repeating: 5, count: 32))
        let reasons: [CommandAdmissionRejectionReason] = [.updateInstalling, .authorityStarting, .updateWaiting, .storageUnavailable]
        let server = try serve(endpoint, replies: reasons.map(busy) + [.result(.admitted(admitted))])
        var fds: [Int32] = [-1, -1]; XCTAssertEqual(pipe(&fds), 0); defer { for fd in fds { _ = Darwin.close(fd) } }
        XCTAssertEqual(Darwin.write(fds[1], "queued", 6), 6)
        let flags = fcntl(fds[0], F_GETFL), original = try template()
        var statuses: [CommandCallerReadinessStatus] = [], delays: [UInt32] = []
        let result = try submit(endpoint, fd: fds[0], status: { statuses.append($0) }, wait: { delay, check in
            delays.append(delay); try check()
        })
        XCTAssertEqual(result.outcome, .admitted(admitted))
        let submissions = try server.finish(); XCTAssertEqual(submissions.count, 5)
        XCTAssertEqual(Set(submissions.map(\.binding.id)).count, 5); XCTAssertEqual(Set(submissions.map(\.binding.nonce)).count, 5)
        XCTAssertEqual(Set(submissions.map(\.binding.callerBinding)).count, 5)
        for submission in submissions {
            XCTAssertNotEqual(submission.binding.id, original.binding.id); XCTAssertNotEqual(submission.binding.nonce, original.binding.nonce)
            XCTAssertEqual(submission.executablePath, original.executablePath); XCTAssertEqual(submission.arguments, original.arguments)
            XCTAssertEqual(submission.directoryPath, original.directoryPath); XCTAssertEqual(submission.requestedTargetUID, original.requestedTargetUID)
            XCTAssertEqual(submission.environmentAdditions, original.environmentAdditions); XCTAssertEqual(submission.ioMode, original.ioMode)
            XCTAssertEqual(submission.disconnectBehavior, original.disconnectBehavior); XCTAssertEqual(submission.unverifiedRationale, original.unverifiedRationale)
        }
        XCTAssertEqual(statuses, reasons.map(CommandCallerReadinessStatus.waiting)); XCTAssertEqual(delays, [1, 2, 4, 4])
        XCTAssertEqual(fcntl(fds[0], F_GETFL), flags)
        var bytes = [UInt8](repeating: 0, count: 6)
        XCTAssertEqual(Darwin.read(fds[0], &bytes, 6), 6); XCTAssertEqual(Data(bytes), Data("queued".utf8))
        try assertNoNextAttempt(endpoint)
    }

    func testReasonChangesNeverResetTheDeadlineAndExhaustionKeepsTheLatestReason() throws {
        let endpoint = try Endpoint(), server = try serve(endpoint, replies: [busy(.updateInstalling), busy(.storageUnavailable)])
        let fd = Darwin.open("/dev/null", O_RDONLY); defer { _ = Darwin.close(fd) }
        var now: UInt64 = 1000
        let configuration = try CommandCallerReadinessConfiguration(timeoutMilliseconds: 30, initialBackoffMilliseconds: 10,
            maximumBackoffMilliseconds: 20, controlTimeoutMilliseconds: 1000)
        XCTAssertThrowsError(try submit(endpoint, fd: fd, configuration: configuration, clock: { now }, wait: { delay, check in
            now += UInt64(delay); try check()
        })) { XCTAssertEqual($0 as? CommandCallerReadinessError, .deadlineExceeded(lastBusyReason: .storageUnavailable)) }
        XCTAssertEqual(try server.finish().count, 2); try assertNoNextAttempt(endpoint)
    }

    func testPermanentAndUncertainOutcomesNeverMakeAnotherAttempt() throws {
        let outcomes: [CommandAdmissionOutcome] = [.notAdmitted(.invalidRequest, .never), .notAdmitted(.policyRejected, .never),
            .notAdmitted(.capacityExceeded, .never), .notAdmitted(.unsupported, .never), .notAdmitted(.requesterExited, .never),
            .uncertain(.admissionRejected), .uncertain(.duplicateSubmission), .uncertain(.storageFailure)]
        let fd = Darwin.open("/dev/null", O_RDONLY); defer { _ = Darwin.close(fd) }
        for outcome in outcomes {
            let endpoint = try Endpoint(), server = try serve(endpoint, replies: [.result(outcome)])
            XCTAssertEqual(try submit(endpoint, fd: fd).outcome, outcome)
            XCTAssertEqual(try server.finish().count, 1); try assertNoNextAttempt(endpoint)
        }
    }

    func testLostMalformedAndWrongBindingRepliesDoNotReuseAnEarlierBusyProof() throws {
        let fd = Darwin.open("/dev/null", O_RDONLY); defer { _ = Darwin.close(fd) }
        for reply in [Reply.lost, .malformed, .wrongDigest] {
            let endpoint = try Endpoint(), server = try serve(endpoint, replies: [busy(.updateWaiting), reply])
            let configuration = try CommandCallerReadinessConfiguration(timeoutMilliseconds: 5000,
                initialBackoffMilliseconds: 1, maximumBackoffMilliseconds: 1, controlTimeoutMilliseconds: 100)
            XCTAssertThrowsError(try submit(endpoint, fd: fd, configuration: configuration))
            XCTAssertEqual(try server.finish().count, 2); try assertNoNextAttempt(endpoint)
        }
    }

    func testCancellationDuringBusyWaitNeverResubmits() throws {
        let endpoint = try Endpoint(), server = try serve(endpoint, replies: [busy(.authorityStarting)])
        let fd = Darwin.open("/dev/null", O_RDONLY); defer { _ = Darwin.close(fd) }
        var cancelled = false
        XCTAssertThrowsError(try submit(endpoint, fd: fd, cancellation: { if cancelled { throw Cancelled.stopped } },
            wait: { _, check in cancelled = true; try check() })) { XCTAssertTrue($0 is Cancelled) }
        XCTAssertEqual(try server.finish().count, 1); try assertNoNextAttempt(endpoint)
    }

    func testUnavailableEndpointWaitsBeforeExposureAndUsesTheSameDeadline() throws {
        let endpoint = try Endpoint(), server = try serve(endpoint, replies: [.result(.uncertain(.admissionRejected))])
        let fd = Darwin.open("/dev/null", O_RDONLY); defer { _ = Darwin.close(fd) }
        var calls = 0, statuses: [CommandCallerReadinessStatus] = []
        let result = try submit(endpoint, fd: fd, status: { statuses.append($0) }, lookup: {
            calls += 1
            if calls < 3 { throw CommandAuthorityEndpointError.unavailable }
            return endpoint.port
        })
        XCTAssertEqual(result.outcome, .uncertain(.admissionRejected)); XCTAssertEqual(calls, 3); XCTAssertEqual(statuses, [.connecting])
        XCTAssertEqual(try server.finish().count, 1); try assertNoNextAttempt(endpoint)
        var now: UInt64 = 0
        let configuration = try CommandCallerReadinessConfiguration(timeoutMilliseconds: 10, initialBackoffMilliseconds: 10)
        XCTAssertThrowsError(try submit(endpoint, fd: fd, configuration: configuration, clock: { now },
            wait: { delay, check in now += UInt64(delay); try check() }, lookup: { throw CommandAuthorityEndpointError.unavailable })) {
            XCTAssertEqual($0 as? CommandCallerReadinessError, .deadlineExceeded(lastBusyReason: nil))
        }
        try assertNoNextAttempt(endpoint)
    }

    func testClockJumpDuringStatusCallbackExpiresBeforeAnotherSubmission() throws {
        let endpoint = try Endpoint(), server = try serve(endpoint, replies: [busy(.updateWaiting)])
        let fd = Darwin.open("/dev/null", O_RDONLY); defer { _ = Darwin.close(fd) }
        var now: UInt64 = 0
        XCTAssertThrowsError(try submit(endpoint, fd: fd, status: { _ in now = 5000 }, clock: { now })) {
            XCTAssertEqual($0 as? CommandCallerReadinessError, .deadlineExceeded(lastBusyReason: .updateWaiting))
        }
        XCTAssertEqual(try server.finish().count, 1); try assertNoNextAttempt(endpoint)
    }

    func testCancellationDuringNegotiationCannotMasqueradeAsTransportUnavailability() throws {
        let endpoint = try Endpoint(), fd = Darwin.open("/dev/null", O_RDONLY)
        defer { _ = Darwin.close(fd) }
        var checkpoints = 0, lookups = 0
        XCTAssertThrowsError(try submit(endpoint, fd: fd, cancellation: {
            checkpoints += 1
            if checkpoints == 4 { throw MachCommandCallerError.timeout }
        }, lookup: { lookups += 1; return endpoint.port })) {
            XCTAssertEqual($0 as? MachCommandCallerError, .timeout)
        }
        XCTAssertEqual(lookups, 1)
        let receiver = try MachCommandCallerReceiver(receivePort: endpoint.port, expression: expression(), userID: geteuid(),
            auditSessionID: nil, maxPayloadBytes: 8192)
        XCTAssertThrowsError(try receiver.receiveHello(timeoutMilliseconds: 1000)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .malformed)
        }
        try assertNoNextAttempt(endpoint)
    }

    func testDeadlineAfterSendRemainsUncertainDespiteAnEarlierBusyReply() throws {
        let endpoint = try Endpoint(), server = try serve(endpoint, replies: [busy(.updateInstalling), .lost])
        let fd = Darwin.open("/dev/null", O_RDONLY); defer { _ = Darwin.close(fd) }
        var now: UInt64 = 0
        XCTAssertThrowsError(try submit(endpoint, fd: fd, cancellation: {
            if server.submissions.withLock({ $0.count }) == 2 { now = 5000 }
        }, clock: { now })) { XCTAssertEqual($0 as? MachCommandCallerError, .timeout) }
        XCTAssertEqual(try server.finish().count, 2); try assertNoNextAttempt(endpoint)
    }

    func testFreshLookupCanReconnectToAReplacementEndpointAfterABusyReply() throws {
        let first = try Endpoint(), second = try Endpoint()
        let firstServer = try serve(first, replies: [busy(.updateInstalling)])
        let secondServer = try serve(second, replies: [.result(.uncertain(.admissionRejected))])
        let fd = Darwin.open("/dev/null", O_RDONLY); defer { _ = Darwin.close(fd) }
        var lookups = 0
        XCTAssertEqual(try submit(first, fd: fd, lookup: {
            lookups += 1; return lookups == 1 ? first.port : second.port
        }).outcome, .uncertain(.admissionRejected))
        XCTAssertEqual(try firstServer.finish().count, 1); XCTAssertEqual(try secondServer.finish().count, 1)
        XCTAssertEqual(lookups, 2); try assertNoNextAttempt(first); try assertNoNextAttempt(second)
    }

    func testDeadlineDuringLookupAndBackwardClockCannotExposeTheInvocation() throws {
        let endpoint = try Endpoint(), fd = Darwin.open("/dev/null", O_RDONLY); defer { _ = Darwin.close(fd) }
        var now: UInt64 = 0
        XCTAssertThrowsError(try submit(endpoint, fd: fd, clock: { now }, lookup: { now = 5000; return endpoint.port })) {
            XCTAssertEqual($0 as? CommandCallerReadinessError, .deadlineExceeded(lastBusyReason: nil))
        }
        try assertNoNextAttempt(endpoint)
        var reads = 0
        XCTAssertThrowsError(try submit(endpoint, fd: fd, clock: { reads += 1; return reads == 1 ? 10 : 9 })) {
            XCTAssertEqual($0 as? CommandCallerReadinessError, .clockMovedBackwards)
        }
        try assertNoNextAttempt(endpoint)
    }

    func testPublicEntryRequiresRootPolicyBeforeEndpointOrInputUse() throws {
        let policy = try XPCPeerPolicy(teamID: "AB12345678", componentIdentifier: "dev.remozio.authority",
            approvedCodeDirectoryHashes: [Data(repeating: 0, count: 20)], expectedUserID: geteuid())
        XCTAssertThrowsError(try CommandCallerReadiness.submit(template(), inputDescriptor: -1,
            authorityPort: { XCTFail("Must not look up an authority"); return 0 }, authorityPolicy: policy,
            macID: mac, accountID: account, submissionLimits: limits(),
            configuration: .init(timeoutMilliseconds: 5000))) { XCTAssertEqual($0 as? MachCommandHandshakeError, .invalidConfiguration) }
    }
}


extension CommandCallerReadinessTests {
    private func submitIO(_ endpoint: Endpoint, input: Int32, output: Int32,
                          configuration: CommandCallerReadinessConfiguration? = nil,
                          cancellation: () throws -> Void = {}, status: (CommandCallerReadinessStatus) -> Void = { _ in },
                          clock: (() throws -> UInt64)? = nil,
                          wait: ((UInt32, () throws -> Void) throws -> Void)? = nil) throws -> sending CommandIOAdmission {
        try CommandCallerReadiness.submitIO(template(), inputDescriptor: input, outputDescriptor: output, errorDescriptor: output,
            authorityPort: { endpoint.port }, expression: expression(), userID: geteuid(), auditSessionID: nil,
            macID: mac, accountID: account, submissionLimits: limits(),
            configuration: configuration ?? .init(timeoutMilliseconds: 5000, initialBackoffMilliseconds: 1,
                maximumBackoffMilliseconds: 4, controlTimeoutMilliseconds: 1000),
            checkCancellation: cancellation, onStatus: status, clock: clock, wait: wait)
    }
    func testIOReadinessRetriesFourBoundBusyClassesAndRetainsActualTerminalSession() throws {
        let endpoint = try Endpoint(), request = CommandAdmittedRequest(requestID: Data(repeating: 4, count: 16),
            requestDigest: Data(repeating: 5, count: 32), challenge: Data(repeating: 6, count: 32))
        let reasons: [CommandAdmissionRejectionReason] = [.updateInstalling, .authorityStarting, .updateWaiting, .storageUnavailable]
        let server = try serve(endpoint, replies: reasons.map(busy) + [.result(.admitted(request))], io: true)
        var input: [Int32] = [-1, -1]; XCTAssertEqual(pipe(&input), 0)
        let output = Darwin.open("/dev/null", O_WRONLY | O_CLOEXEC)
        defer { for fd in input + [output] { _ = Darwin.close(fd) } }
        XCTAssertEqual(Darwin.write(input[1], "queued", 6), 6)
        let inputFlags = fcntl(input[0], F_GETFL), outputFlags = fcntl(output, F_GETFL)
        var statuses: [CommandCallerReadinessStatus] = [], delays: [UInt32] = []
        let result = try submitIO(endpoint, input: input[0], output: output, status: { statuses.append($0) }, wait: { delay, check in
            delays.append(delay); try check()
        })
        guard case .admitted(let session) = result else { return XCTFail("Admission must keep its terminal session") }
        defer { session.close() }
        let submissions = try server.finish(), original = try template()
        XCTAssertEqual(submissions.count, 5)
        XCTAssertEqual(Set(submissions.map(\.binding.id)).count, 5); XCTAssertEqual(Set(submissions.map(\.binding.nonce)).count, 5)
        XCTAssertEqual(Set(submissions.map(\.binding.callerBinding)).count, 5)
        for submission in submissions {
            XCTAssertEqual(submission.arguments, original.arguments); XCTAssertEqual(submission.environmentAdditions, original.environmentAdditions)
            XCTAssertEqual(submission.executablePath, original.executablePath); XCTAssertEqual(submission.directoryPath, original.directoryPath)
            XCTAssertEqual(submission.requestedTargetUID, original.requestedTargetUID); XCTAssertEqual(submission.ioMode, original.ioMode)
            XCTAssertEqual(submission.disconnectBehavior, original.disconnectBehavior); XCTAssertEqual(submission.unverifiedRationale, original.unverifiedRationale)
            XCTAssertNotEqual(submission.binding.id, original.binding.id); XCTAssertNotEqual(submission.binding.nonce, original.binding.nonce)
        }
        let terminal = try XCTUnwrap(session.pollTerminalResult(timeoutMilliseconds: 1000))
        XCTAssertEqual(terminal.outcome, .exited(13)); XCTAssertEqual(terminal.request, request)
        XCTAssertEqual(terminal.submission, submissions.last?.binding)
        XCTAssertEqual(statuses, reasons.map(CommandCallerReadinessStatus.waiting)); XCTAssertEqual(delays, [1, 2, 4, 4])
        XCTAssertEqual(fcntl(input[0], F_GETFL), inputFlags); XCTAssertEqual(fcntl(output, F_GETFL), outputFlags)
        var bytes = [UInt8](repeating: 0, count: 6)
        XCTAssertEqual(Darwin.read(input[0], &bytes, 6), 6); XCTAssertEqual(Data(bytes), Data("queued".utf8))
        try assertNoNextAttempt(endpoint)
    }
    func testIOReadinessNeverRetriesPermanentOrUncertainOrInvalidReplies() throws {
        let input = Darwin.open("/dev/null", O_RDONLY), output = Darwin.open("/dev/null", O_WRONLY)
        defer { _ = Darwin.close(input); _ = Darwin.close(output) }
        for reply: Reply in [.result(.notAdmitted(.policyRejected, .never)), .result(.uncertain(.storageFailure)), .malformed, .wrongDigest, .lost] {
            let endpoint = try Endpoint(), server = try serve(endpoint, replies: [reply], io: true)
            let configuration = try CommandCallerReadinessConfiguration(timeoutMilliseconds: 5000, initialBackoffMilliseconds: 1,
                maximumBackoffMilliseconds: 4, controlTimeoutMilliseconds: 100)
            switch reply {
            case .result(let expected):
                guard case .result(let result) = try submitIO(endpoint, input: input, output: output, configuration: configuration) else {
                    return XCTFail("Only admission can retain a session")
                }
                XCTAssertEqual(result.outcome, expected)
            default: XCTAssertThrowsError(try submitIO(endpoint, input: input, output: output, configuration: configuration))
            }
            XCTAssertEqual(try server.finish().count, 1); try assertNoNextAttempt(endpoint)
        }
    }
    func testIOReadinessKeepsOneDeadlineAcrossReasonChangesAndCancellation() throws {
        let input = Darwin.open("/dev/null", O_RDONLY), output = Darwin.open("/dev/null", O_WRONLY)
        defer { _ = Darwin.close(input); _ = Darwin.close(output) }
        do {
            let endpoint = try Endpoint(), server = try serve(endpoint, replies: [busy(.updateInstalling), busy(.storageUnavailable)], io: true)
            var now: UInt64 = 1000
            let configuration = try CommandCallerReadinessConfiguration(timeoutMilliseconds: 30, initialBackoffMilliseconds: 10,
                maximumBackoffMilliseconds: 20, controlTimeoutMilliseconds: 1000)
            XCTAssertThrowsError(try submitIO(endpoint, input: input, output: output, configuration: configuration,
                clock: { now }, wait: { delay, check in now += UInt64(delay); try check() })) {
                XCTAssertEqual($0 as? CommandCallerReadinessError, .deadlineExceeded(lastBusyReason: .storageUnavailable))
            }
            XCTAssertEqual(try server.finish().count, 2); try assertNoNextAttempt(endpoint)
        }
        do {
            let endpoint = try Endpoint(), server = try serve(endpoint, replies: [busy(.updateWaiting)], io: true)
            var cancelled = false
            XCTAssertThrowsError(try submitIO(endpoint, input: input, output: output,
                cancellation: { if cancelled { throw Cancelled.stopped } }, status: { _ in cancelled = true })) {
                XCTAssertTrue($0 is Cancelled)
            }
            XCTAssertEqual(try server.finish().count, 1); try assertNoNextAttempt(endpoint)
        }
    }
}
