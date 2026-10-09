import Darwin
import Foundation
import RemozioProtocol

/// Owns the original command resources inside the serialized Root controller. This grants no child release permission.
final class RetainedCommandExecutionResources {
    let capture: CommandCapture
    let request: CommandAdmittedRequest
    private let caller: RetainedCommandCaller
    private let input: RetainedCommandInputDescriptor
    private let filesystem: CommandFilesystemCapture
    private let outputs: RetainedCommandOutputChannels
    private let terminal: MachCommandReplyRight
    private let profile: CommandHandshakeProfile
    private let submissionDigest: Data
    private var executionRetired = false
    private var closed = false
    private var terminalAttempted = false

    init(capture: CommandCapture, caller: RetainedCommandCaller, input: RetainedCommandInputDescriptor,
         filesystem: CommandFilesystemCapture, outputs: RetainedCommandOutputChannels, terminal: MachCommandReplyRight,
         profile: CommandHandshakeProfile, submissionDigest: Data, request: CommandAdmittedRequest) {
        self.capture = capture; self.caller = caller; self.input = input; self.filesystem = filesystem
        self.outputs = outputs; self.terminal = terminal; self.profile = profile
        self.submissionDigest = submissionDigest; self.request = request
    }
    deinit { close() }
    var requiresStreamPump: Bool { profile.supportsStreamingExecution }
    var requesterExitObserved: Bool { caller.requesterExitObserved }

    func recheck(currentPolicy: XPCPeerPolicy, checkCancellation: () throws -> Void = {}) throws {
        try recheck(expression: currentPolicy.requirement, userID: currentPolicy.expectedUserID,
            auditSessionID: currentPolicy.expectedAuditSessionID, checkCancellation: checkCancellation)
    }
    /// Internal fixture identity seam. Production requires the current protected caller policy.
    func recheck(expression: String, userID: uid_t, auditSessionID: au_asid_t?, checkCancellation: () throws -> Void = {}) throws {
        guard !closed, !executionRetired else { throw RetainedCommandCaptureError.closed }
        do {
            try checkCancellation()
            try caller.recheck(expression: expression, userID: userID, auditSessionID: auditSessionID)
            try filesystem.recheck(checkCancellation: checkCancellation)
            try input.withBorrowedDescriptor { _ in () }
            try outputs.recheckStreams(); try terminal.recheck()
            try caller.recheck(expression: expression, userID: userID, auditSessionID: auditSessionID)
        } catch { retireExecutionResources(); throw error }
    }

    /// Checks the original caller without treating executable changes as a running-command cancellation.
    func recheckCaller(expression: String, userID: uid_t, auditSessionID: au_asid_t?) throws {
        guard !closed, !executionRetired else { throw RetainedCommandCaptureError.closed }
        try caller.recheck(expression: expression, userID: userID, auditSessionID: auditSessionID)
    }

    /// Borrow only during this serialized callback. Do not close or retain these descriptors.
    func withBorrowedDescriptors<Value>(_ body: (Int32, Int32, Int32, Int32) throws -> Value) throws -> Value {
        guard !closed, !executionRetired else { throw RetainedCommandCaptureError.closed }
        return try input.withBorrowedDescriptor { input in
            try outputs.output.withBorrowedDescriptor { output in
                try outputs.error.withBorrowedDescriptor { error in
                    try filesystem.withBorrowedDirectoryDescriptor { directory in
                        try body(input, output, error, directory)
                    }
                }
            }
        }
    }

    /// Only the trusted controller supplies an established result after the required durable transition.
    /// A failed private delivery consumes this attempt and cannot authorize another command.
    func sendTerminalOutcome(_ outcome: CommandTerminalOutcome) throws {
        guard !closed, !terminalAttempted else { throw MachCommandHandshakeError.retired }
        let payload = CommandTerminalResultPayload(profile: profile, submission: capture.submission,
            submissionDigest: submissionDigest, request: request, outcome: outcome)
        let bytes = try payload.canonicalBytes
        terminalAttempted = true
        defer { terminal.close() }
        try terminal.sendTerminalNonblocking(bytes)
    }
    func close() {
        guard !closed else { return }
        closed = true; retireExecutionResources(); terminal.close()
    }
    private func retireExecutionResources() {
        guard !executionRetired else { return }
        executionRetired = true
        filesystem.close(); outputs.close(); caller.close(); input.close()
    }
}
