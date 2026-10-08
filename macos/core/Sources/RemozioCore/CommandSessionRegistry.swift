import Darwin
import Foundation
import os
import RemozioProtocol

public enum CommandSessionRegistryError: Error, Equatable {
    case invalidConfiguration, invalidCodePolicy, capacity, unknownSession, closed, operationActive
}

/// Serial ownership of verified frontend sessions for one trusted local account.
/// The host owns the sole receive loop and supplies a fresh protected code-policy snapshot for every operation.
/// This registry grants no command admission, replay exemption, retry authority, or execution permit.
public final class CommandSessionRegistry {
    public let maximumSessions: Int
    private let macID: Data
    private let accountID: Data
    private let userID: uid_t
    private let auditSessionID: au_asid_t?
    private var sessions: [Data: RetainedCommandHandshake] = [:]
    private var roleRevision: UUID?
    private var activeInput: ObjectIdentifier?
    private var busy = false
    private let closedState = OSAllocatedUnfairLock(initialState: false)
    private var closed: Bool { closedState.withLock { $0 } }
    public var retainedSessionCount: Int { sessions.count }

    public init(macID: Data, accountID: Data, userID: uid_t, auditSessionID: au_asid_t? = nil, maximumSessions: Int) throws {
        guard macID.count == 16, accountID.count == 16, maximumSessions > 0 else {
            throw CommandSessionRegistryError.invalidConfiguration
        }
        self.macID = macID; self.accountID = accountID; self.userID = userID
        self.auditSessionID = auditSessionID; self.maximumSessions = maximumSessions
    }

    /// Reserve a slot before sending an accepted profile. The returned value contains no mutable session handle.
    public func accept(hello: sending MachCommandHello, currentCodePolicy: AuthorityCodePolicySnapshot,
                       timeoutMilliseconds: UInt32 = 5000) throws -> CommandHandshakeProfile {
        try accept(hello: hello, context: { try self.context(currentCodePolicy) }, timeoutMilliseconds: timeoutMilliseconds)
    }

    func accept(hello: MachCommandHello, context: () throws -> Context,
                timeoutMilliseconds: UInt32 = 5000) throws -> CommandHandshakeProfile {
        defer { hello.close() }
        try begin(); defer { end() }
        let current = try resolve(context)
        _ = synchronize(current)
        guard sessions.count < maximumSessions else { throw CommandSessionRegistryError.capacity }
        let session = try RetainedCommandHandshake(hello: hello, macID: macID, accountID: accountID,
            expression: current.expression, userID: userID, auditSessionID: auditSessionID,
            timeoutMilliseconds: timeoutMilliseconds)
        guard sessions[session.profile.callerBinding] == nil else {
            session.close(); throw MachCommandHandshakeError.wrongBinding
        }
        sessions[session.profile.callerBinding] = session
        return session.profile
    }

    /// Route by a decoded claim, then verify the actual sender against the retained session before capture assembly.
    public func assemble(received: sending ReceivedMachCommandInputSubmission, currentCodePolicy: AuthorityCodePolicySnapshot,
                         captureSchemaVersion: UInt64, resolvedTarget: CommandTarget, minimalEnvironment: [CapturedEnvironmentEntry],
                         streamBinding: Data, submissionLimits: CBORLimits, captureLimits: CBORLimits,
                         maximumAncestryEntries: Int = 16, checkCancellation: @Sendable () throws -> Void = {}) throws -> sending RetainedCommandCapture {
        try assemble(received: received, context: { try self.context(currentCodePolicy) }, captureSchemaVersion: captureSchemaVersion,
            resolvedTarget: resolvedTarget, minimalEnvironment: minimalEnvironment, streamBinding: streamBinding,
            submissionLimits: submissionLimits, captureLimits: captureLimits, maximumAncestryEntries: maximumAncestryEntries,
            checkCancellation: checkCancellation)
    }

    func assemble(received: sending ReceivedMachCommandInputSubmission, context: () throws -> Context,
                  captureSchemaVersion: UInt64, resolvedTarget: CommandTarget, minimalEnvironment: [CapturedEnvironmentEntry],
                  streamBinding: Data, submissionLimits: CBORLimits, captureLimits: CBORLimits,
                  maximumAncestryEntries: Int = 16, checkCancellation: @Sendable () throws -> Void = {}) throws -> sending RetainedCommandCapture {
        if busy, activeInput == ObjectIdentifier(received.input) { throw CommandSessionRegistryError.operationActive }
        do { try begin() }
        catch { received.closeIfUnclaimed(); throw error }
        activeInput = ObjectIdentifier(received.input)
        defer { activeInput = nil; end() }
        let current: Context
        let session: RetainedCommandHandshake
        do {
            current = try resolve(context)
            _ = synchronize(current)
            try checkCancellation()
            guard !closed else { throw CommandSessionRegistryError.closed }
            guard case .map(let fields) = try DeterministicCBOR.decode(received.payload, limits: submissionLimits),
                  case .unsigned(let schema) = fields[0], CommandSubmission.supportedSchemaVersions.contains(schema) else {
                throw CommandCaptureError.version
            }
            let submission = try CommandSubmission(canonicalBytes: received.payload, limits: submissionLimits,
                expectedSchemaVersion: schema)
            guard let selected = sessions[submission.binding.callerBinding] else { throw CommandSessionRegistryError.unknownSession }
            session = selected
        } catch { received.closeIfUnclaimed(); throw error }
        // The session owns cleanup after this transfer, including failure. The registry must not use the receipt again.
        return try session.assemble(received: received, expression: current.expression, userID: userID, auditSessionID: auditSessionID,
            captureSchemaVersion: captureSchemaVersion, resolvedTarget: resolvedTarget, minimalEnvironment: minimalEnvironment,
            streamBinding: streamBinding, submissionLimits: submissionLimits, captureLimits: captureLimits,
            maximumAncestryEntries: maximumAncestryEntries, checkCancellation: { [closedState] in
                try checkCancellation()
                guard !closedState.withLock({ $0 }) else { throw CommandSessionRegistryError.closed }
            })
    }

    /// Run from the serial host loop even when no messages arrive. No deadline is imposed on admitted requests.
    @discardableResult
    public func prune(currentCodePolicy: AuthorityCodePolicySnapshot) throws -> Int {
        try prune(context: { try self.context(currentCodePolicy) })
    }
    @discardableResult
    func prune(context: () throws -> Context) throws -> Int {
        try begin(); defer { end() }
        return synchronize(try resolve(context))
    }

    /// Local host retirement only. A payload cannot authenticate this operation.
    public func retire(callerBinding: Data) throws {
        try begin(); defer { end() }
        sessions.removeValue(forKey: callerBinding)?.close()
    }

    public func close() {
        closedState.withLock { $0 = true }
        if !busy { clear() }
    }
    deinit { close() }

    struct Context: Sendable { let expression: String; let roleRevision: UUID }
    func context(_ snapshot: AuthorityCodePolicySnapshot) throws -> Context {
        guard let entry = snapshot.policy.entries.first(where: { $0.role == .commandFrontend }), entry.active,
              entry.installedGeneration >= entry.minimumGeneration,
              let revision = snapshot.roleRevisions[.commandFrontend] else { throw CommandSessionRegistryError.invalidCodePolicy }
        let policy = try XPCPeerPolicy(teamID: entry.teamID, componentIdentifier: entry.identifier,
            approvedCodeDirectoryHashes: [entry.codeDirectoryHash], expectedUserID: userID, expectedAuditSessionID: auditSessionID)
        return Context(expression: policy.requirement, roleRevision: revision)
    }
    private func resolve(_ provider: () throws -> Context) throws -> Context {
        do { return try provider() }
        catch { clear(); roleRevision = nil; throw error }
    }
    private func synchronize(_ context: Context) -> Int {
        let before = sessions.count
        if let roleRevision, roleRevision != context.roleRevision { clear() }
        roleRevision = context.roleRevision
        for key in Array(sessions.keys) {
            guard let session = sessions[key] else { continue }
            do { try session.recheck(expression: context.expression, userID: userID, auditSessionID: auditSessionID) }
            catch { sessions.removeValue(forKey: key)?.close() }
        }
        return before - sessions.count
    }
    private func begin() throws {
        guard !closed else { throw CommandSessionRegistryError.closed }
        guard !busy else { throw CommandSessionRegistryError.operationActive }
        busy = true
    }
    private func end() { busy = false; if closed { clear() } }
    private func clear() { for session in sessions.values { session.close() }; sessions.removeAll() }
}
