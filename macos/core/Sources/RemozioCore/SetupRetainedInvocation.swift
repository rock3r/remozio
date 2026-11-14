import Darwin
import Foundation
import Security

/// Owns one retained invocation through work, reply and explicit cleanup. It cannot create native loans.
final class SetupRetainedInvocation: @unchecked Sendable, CustomStringConvertible, CustomReflectable {
    let peer: XPCPeerCredentials
    private let capture: (XPCInvocationGuard, SignedReleaseEvidence) throws -> SetupRetainedCallerBinding
    let acceptedPolicy: XPCPeerPolicy
    let incarnation: UUID
    private let processID = getpid(), processOwner = getuid()
    private let lock = NSRecursiveLock()
    private let cancellation = SetupAuditUpgradeCancellation()
    private let verifyRights: () throws -> Void
    private let closeRights: () -> Void
    private let verifyReservation: () throws -> Void
    private let closeReservation: () -> Void
    private var active = false, invoked = false, closed = false
    var description: String { "SetupRetainedInvocation(redacted)" }
    var customMirror: Mirror { Mirror(self, children: EmptyCollection<Mirror.Child>()) }

    /// Import on the actual exported invocation. No external form crosses dispatch or enters storage.
    static func open(owner: SetupAccountOwner, invocation: XPCInvocationGuard, externalForm: Data) throws -> Self {
        guard getuid() == 0, geteuid() == 0 else { throw SetupAdministratorAuthorizationError.wrongProcess }
        let peer = try invocation.verifyInvocation()
        guard peer.userID > 0, peer.userID < UInt32.max else { throw SetupAdministratorAuthorizationError.wrongProcess }
        let reference = try SetupAdministratorNative.importCurrentRights(externalForm: externalForm)
        return try begin(owner: owner, peer: peer, incarnation: invocation.incarnation, policy: invocation.acceptedPeerPolicy, verifyRights: {
            try SetupAdministratorNative.validatePolicy()
            try SetupAdministratorNative.copyRights(reference, flags: [])
            try SetupAdministratorNative.validatePolicy()
        }, closeRights: { _ = AuthorizationFree(reference, []) })
    }
    /// Ordinary-owner controls cannot import Root rights or construct an invocation in a Root process.
    static func openOwned(owner: SetupAccountOwner, binding: SetupRetainedCallerBinding, policy: XPCPeerPolicy,
                          verifyRights: @escaping () throws -> Void, closeRights: @escaping () -> Void = {}) throws -> Self {
        guard getuid() > 0, getuid() == geteuid() else { throw SetupAdministratorAuthorizationError.wrongProcess }
        return try begin(owner: owner, peer: binding.peer, incarnation: binding.incarnation, policy: policy,
            verifyRights: verifyRights, closeRights: closeRights)
    }
    private static func begin(owner: SetupAccountOwner, peer: XPCPeerCredentials, incarnation: UUID, policy: XPCPeerPolicy,
        verifyRights: @escaping () throws -> Void, closeRights: @escaping () -> Void) throws -> Self {
        do {
            try verifyRights()
            let reservation = try owner.reserveRetainedInvocation()
            do {
                try verifyRights(); try reservation.verify()
                return Self(peer: peer, incarnation: incarnation, policy: policy, verifyRights: verifyRights, closeRights: closeRights,
                    verifyReservation: reservation.verify, closeReservation: reservation.close, capture: { invocation, candidate in
                        try owner.retainedCallerBinding(invocation: invocation, candidate: candidate, admission: reservation.admission)
                    })
            } catch { reservation.close(); throw error }
        } catch { closeRights(); throw error }
    }
    private init(peer: XPCPeerCredentials, incarnation: UUID, policy: XPCPeerPolicy,
                 verifyRights: @escaping () throws -> Void, closeRights: @escaping () -> Void,
                 verifyReservation: @escaping () throws -> Void, closeReservation: @escaping () -> Void,
                 capture: @escaping (XPCInvocationGuard, SignedReleaseEvidence) throws -> SetupRetainedCallerBinding) {
        self.peer = peer; self.incarnation = incarnation; acceptedPolicy = policy; self.capture = capture
        self.verifyRights = verifyRights; self.closeRights = closeRights
        self.verifyReservation = verifyReservation; self.closeReservation = closeReservation
    }
    /// Capture on the exported invocation after this owner exists. Failure keeps its reservation for cleanup.
    func callerBinding(invocation: XPCInvocationGuard, candidate: SignedReleaseEvidence) throws -> SetupRetainedCallerBinding {
        guard getpid() == processID else { throw AdministrativeSetupError.unavailable }
        return try lock.withLock {
            guard !active, !invoked, invocation.incarnation == incarnation else { throw XPCPeerPolicyError.wrongConnection }
            active = true; defer { active = false }
            try validateLifetime()
            guard try invocation.verifyInvocation() == peer else { throw XPCPeerPolicyError.wrongPeer }
            let value = try capture(invocation, candidate)
            guard value.incarnation == incarnation, value.peer == peer else { throw XPCPeerPolicyError.wrongPeer }
            try validateLifetime(); return value
        }
    }
    /// A foreign connection cannot cancel this invocation. Cancellation does not release resources.
    func cancel(incarnation: UUID) {
        guard incarnation == self.incarnation else { return }; cancellation.cancel()
    }
    func validateLifetime() throws {
        guard getpid() == processID else { throw AdministrativeSetupError.unavailable }
        try lock.withLock {
            guard !closed, getuid() == processOwner, geteuid() == processOwner else {
                throw SetupAdministratorAuthorizationError.closed
            }
            try cancellation.check(); try verifyRights(); try verifyReservation(); try cancellation.check()
        }
    }
    /// A single synchronous worker owns all work and its reply. A failure never permits body replay.
    func run<Value>(work: () throws -> Value, reply: (Value) throws -> Void) throws {
        guard getpid() == processID else { throw AdministrativeSetupError.unavailable }
        try lock.withLock {
            guard !active, !invoked, !closed else { throw AdministrativeSetupError.unavailable }
            active = true; invoked = true; defer { active = false }
            try validateLifetime(); let value = try work(); try validateLifetime()
            try reply(value)
        }
    }
    /// Call only after the outer operation has settled its resources. Expired rights cannot prevent cleanup.
    func close() throws {
        guard getpid() == processID else { throw AdministrativeSetupError.unavailable }
        try lock.withLock {
            guard !active else { throw AdministrativeSetupError.unavailable }
            guard !closed else { return }
            closed = true; closeRights(); closeReservation()
        }
    }
    deinit { if getpid() == processID { closeRightsIfNeeded() } }
    private func closeRightsIfNeeded() { if !closed { closed = true; closeRights(); closeReservation() } }
}
