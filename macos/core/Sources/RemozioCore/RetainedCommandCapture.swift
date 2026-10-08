import Darwin
import Foundation
import RemozioProtocol

public enum RetainedCommandCaptureError: Error, Equatable { case binding, invalidContext, closed, alreadyOwned }

/// Owns the original caller, input, and filesystem observations for one command request. This grants no execution authority.
/// Construction takes ownership on success and failure. The request owner must serialize access and must not reuse the received submission.
public final class RetainedCommandCapture {
    public let capture: CommandCapture
    private let caller: RetainedCommandCaller
    private let input: RetainedCommandInputDescriptor
    private let filesystem: CommandFilesystemCapture
    private let admissionReply: MachCommandReplyRight?
    private var closed = false
    private var requestOwned = false

    /// Supply target credentials and the minimal environment from protected policy and OS resolution.
    /// The expected caller binding comes from the authenticated channel; the authority creates the stream binding.
    public convenience init(received: sending ReceivedMachCommandInputSubmission, expectedCallerBinding: Data,
                            submissionSchemaVersion: UInt64, captureSchemaVersion: UInt64, currentPolicy: XPCPeerPolicy,
                            resolvedTarget: CommandTarget, minimalEnvironment: [CapturedEnvironmentEntry], streamBinding: Data,
                            submissionLimits: CBORLimits, captureLimits: CBORLimits, maximumAncestryEntries: Int = 16,
                            checkCancellation: @Sendable () throws -> Void = {}) throws {
        try self.init(received: received, expectedCallerBinding: expectedCallerBinding, submissionSchemaVersion: submissionSchemaVersion,
            captureSchemaVersion: captureSchemaVersion, expression: currentPolicy.requirement, userID: currentPolicy.expectedUserID,
            auditSessionID: currentPolicy.expectedAuditSessionID, resolvedTarget: resolvedTarget, minimalEnvironment: minimalEnvironment,
            streamBinding: streamBinding, submissionLimits: submissionLimits, captureLimits: captureLimits,
            maximumAncestryEntries: maximumAncestryEntries, checkCancellation: checkCancellation)
    }

    init(received: sending ReceivedMachCommandInputSubmission, expectedCallerBinding: Data, submissionSchemaVersion: UInt64,
         captureSchemaVersion: UInt64, expression: String, userID: uid_t, auditSessionID: au_asid_t?, resolvedTarget: CommandTarget,
         minimalEnvironment: [CapturedEnvironmentEntry], streamBinding: Data, submissionLimits: CBORLimits, captureLimits: CBORLimits,
         maximumAncestryEntries: Int = 16, checkCancellation: @Sendable () throws -> Void = {}) throws {
        try received.claimForCaptureOwner()
        var heldFilesystem: CommandFilesystemCapture?
        do {
            try checkCancellation()
            try received.caller.recheck(expression: expression, userID: userID, auditSessionID: auditSessionID)
            let submission = try CommandSubmission(canonicalBytes: received.payload, limits: submissionLimits,
                expectedSchemaVersion: submissionSchemaVersion)
            guard expectedCallerBinding.count == 16, submission.binding.callerBinding == expectedCallerBinding else {
                throw RetainedCommandCaptureError.binding
            }
            guard resolvedTarget.uid == submission.requestedTargetUID else { throw RetainedCommandCaptureError.invalidContext }
            let environment = try Self.environment(minimal: minimalEnvironment, additions: submission.environmentAdditions)
            let filesystem = try CommandFilesystemCapture(executablePath: submission.executablePath,
                directoryPath: submission.directoryPath, checkCancellation: checkCancellation)
            heldFilesystem = filesystem
            let source = try received.input.capture(streamBinding: streamBinding)
            let ancestry = try received.caller.captureAncestry(expression: expression, userID: userID,
                auditSessionID: auditSessionID, maximumEntries: maximumAncestryEntries, checkCancellation: checkCancellation)
            let capture = try CommandCapture(schemaVersion: captureSchemaVersion, executable: filesystem.executable,
                arguments: submission.arguments, directory: filesystem.directory, target: resolvedTarget, environment: environment,
                input: source, ioMode: submission.ioMode, disconnectBehavior: submission.disconnectBehavior,
                requester: received.caller.requester, ancestry: ancestry, unverifiedRationale: submission.unverifiedRationale,
                submission: submission.binding, limits: captureLimits)
            try filesystem.recheck(checkCancellation: checkCancellation)
            try received.caller.recheck(expression: expression, userID: userID, auditSessionID: auditSessionID)
            self.capture = capture; self.caller = received.caller; self.input = received.input; self.filesystem = filesystem
            self.admissionReply = received.reply
        } catch {
            heldFilesystem?.close(); received.caller.close(); received.input.close(); received.reply?.close()
            throw error
        }
    }

    deinit { close() }

    /// A repeated transfer must not close resources already held by an admitted request.
    func claimForRequestOwner() throws {
        guard !closed else { throw RetainedCommandCaptureError.closed }
        guard !requestOwned else { throw RetainedCommandCaptureError.alreadyOwned }
        requestOwned = true
    }

    /// Preflight may reject a first transfer before the coordinator can claim it.
    func closeIfUnclaimed() {
        if !requestOwned { close() }
    }

    /// Invoke after durable permit consumption and current elevation-policy validation, immediately before dispatch.
    public func recheck(currentPolicy: XPCPeerPolicy, checkCancellation: () throws -> Void = {}) throws {
        try recheck(expression: currentPolicy.requirement, userID: currentPolicy.expectedUserID,
            auditSessionID: currentPolicy.expectedAuditSessionID, checkCancellation: checkCancellation)
    }

    func recheck(expression: String, userID: uid_t, auditSessionID: au_asid_t?, checkCancellation: () throws -> Void = {}) throws {
        guard !closed else { throw RetainedCommandCaptureError.closed }
        do {
            try checkCancellation()
            try caller.recheck(expression: expression, userID: userID, auditSessionID: auditSessionID)
            try filesystem.recheck(checkCancellation: checkCancellation)
            try input.withBorrowedDescriptor { _ in () }
            try caller.recheck(expression: expression, userID: userID, auditSessionID: auditSessionID)
        } catch { close(); throw error }
    }

    /// Borrow the original object only for this callback. Do not close, retain, or pass it to another thread.
    public func withBorrowedInputDescriptor<T>(_ body: (Int32) throws -> T) throws -> T {
        guard !closed else { throw RetainedCommandCaptureError.closed }
        return try input.withBorrowedDescriptor(body)
    }

    /// Borrow the retained working-directory object only for this callback, under the same ownership rules as input.
    public func withBorrowedDirectoryDescriptor<T>(_ body: (Int32) throws -> T) throws -> T {
        guard !closed else { throw RetainedCommandCaptureError.closed }
        return try filesystem.withBorrowedDirectoryDescriptor(body)
    }

    /// Only the serialized request controller may reply after transfer. The bytes convey no semantics by themselves.
    func sendAdmissionReply(_ bytes: Data, timeoutMilliseconds: UInt32 = 5000) throws {
        guard !closed, let admissionReply else { throw MachCommandHandshakeError.retired }
        try admissionReply.send(bytes, timeoutMilliseconds: timeoutMilliseconds)
    }

    public func close() {
        if !closed { filesystem.close(); caller.close(); input.close(); admissionReply?.close(); closed = true }
    }

    private static func environment(minimal: [CapturedEnvironmentEntry], additions: [CommandEnvironmentAddition]) throws -> [CapturedEnvironmentEntry] {
        var values: [Data: CapturedEnvironmentEntry] = [:]
        for entry in minimal {
            guard entry.source == .minimal, !entry.name.isEmpty, !entry.name.contains(0), !entry.name.contains(0x3d),
                  !entry.value.contains(0), values[entry.name] == nil else { throw RetainedCommandCaptureError.invalidContext }
            values[entry.name] = entry
        }
        for entry in additions {
            values[entry.name] = CapturedEnvironmentEntry(name: entry.name, value: entry.value, source: .requested)
        }
        return values.values.sorted { $0.name.lexicographicallyPrecedes($1.name) }
    }
}
