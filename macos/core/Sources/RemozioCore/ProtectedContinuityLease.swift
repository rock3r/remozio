import Darwin
import Foundation

/// Holds the independent continuity store and its writer lock for one authority lifetime.
/// Provision this store outside the replaceable journal directory. Serialize all access.
/// The lease proves file ownership, not checkpoint contents or permission to dispatch.
public final class ProtectedContinuityLease {
    private let storage: ProtectedStorageLease
    public var databasePath: String { storage.databasePath }

    /// Setup must already have provisioned the root-owned directory and both 0600 files.
    public static func acquire(directoryPath: String) throws -> ProtectedContinuityLease {
        guard geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        guard directoryPath.hasPrefix("/") else { throw JournalLeaseError.invalidPath }
        return try ProtectedContinuityLease(anchor: "/", relativeDirectory: String(directoryPath.dropFirst()), owner: 0)
    }

    /// Internal fixture entry point. Production starts at / and requires UID 0 through acquire.
    init(anchor: String, relativeDirectory: String, owner: uid_t) throws {
        storage = try ProtectedStorageLease(anchor: anchor, relativeDirectory: relativeDirectory,
            owner: owner, ancestorOwner: owner, databaseName: "continuity.sqlite")
    }

    /// Call before opening SQLite and at continuity commit/recovery boundaries. Failure retires this lease.
    public func validate() throws { try storage.validate() }

    /// Close SQLite first. This releases ownership, not files or persisted recovery state.
    public func close() { storage.close() }
}
