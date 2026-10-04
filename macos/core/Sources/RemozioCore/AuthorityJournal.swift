import Foundation
import RemozioProtocol

/// Owns the authority's sole journal connection. Only Sendable results can leave a serialized transaction.
public final class AuthorityJournal: @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private let database: JournalDatabase
    private var requests: ApprovalRequestCoordinator?
    private var requestOperationActive = false

    /// Transfer exclusive ownership. The caller must not keep another user of this connection.
    public init(database: sending JournalDatabase) { self.database = database }

    /// Transfers the database and epoch writer into one serialization boundary.
    /// Recovery and admission-storage gates must pass before construction.
    public init(requests: sending ApprovalRequestCoordinator) {
        database = requests.database
        self.requests = requests
    }

    /// Runs synchronous request work under the journal lock. The coordinator cannot escape in the result.
    /// The callback must not await or reenter this owner.
    public func withRequests<Value: Sendable>(_ body: @Sendable (ApprovalRequestCoordinator) throws -> Value) throws -> Value {
        try lock.withLock {
            try requireNoRequestOperation()
            try database.read { _ in () } // Reject closed storage or entry from a transaction callback.
            guard let requests else { throw ApprovalCoordinatorError.unavailable }
            requestOperationActive = true
            defer { requestOperationActive = false }
            return try body(requests)
        }
    }

    private func requireNoRequestOperation() throws {
        guard !requestOperationActive else { throw JournalDatabaseError.transactionActive }
    }

    public func read<Value: Sendable>(_ body: @Sendable (JournalTransaction) throws -> Value) throws -> Value {
        try lock.withLock { try requireNoRequestOperation(); return try database.read(body) }
    }
    public func write<Value: Sendable>(_ body: @Sendable (JournalTransaction) throws -> Value) throws -> Value {
        try lock.withLock { try requireNoRequestOperation(); return try database.write(body) }
    }
    public func close() throws {
        try lock.withLock { try requireNoRequestOperation(); try database.close(); requests = nil }
    }

    public func trustSnapshot(maximumPayloadBytes: Int, minimumEnvelopeVersion: UInt64 = 1,
                              auditVersions: Set<UInt64> = []) throws -> DirectApprovalTrust {
        try read { try $0.directApprovalTrust(maximumPayloadBytes: maximumPayloadBytes,
            minimumEnvelopeVersion: minimumEnvelopeVersion, auditVersions: auditVersions) }
    }
    /// A current enrollment check, not permission to approve or execute a request.
    public func validatePeer(_ binding: AuthorityPeerBinding) throws -> Bool {
        do {
            try read { try $0.requireDirectApprovalBinding(binding) }
            return true
        } catch EnrollmentJournalError.staleRevision { return false }
          catch EnrollmentJournalError.unavailableEnrollment { return false }
    }
}
