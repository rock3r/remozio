import Foundation

/// Owns the authority's sole journal connection. Only Sendable results can leave a serialized transaction.
public final class AuthorityJournal: @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private let database: JournalDatabase

    /// Transfer exclusive ownership. The caller must not keep another user of this connection.
    public init(database: sending JournalDatabase) { self.database = database }

    public func read<Value: Sendable>(_ body: @Sendable (JournalTransaction) throws -> Value) throws -> Value {
        try lock.withLock { try database.read(body) }
    }
    public func write<Value: Sendable>(_ body: @Sendable (JournalTransaction) throws -> Value) throws -> Value {
        try lock.withLock { try database.write(body) }
    }
    public func close() throws { try lock.withLock { try database.close() } }

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
