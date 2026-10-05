import Darwin
import Foundation

public enum JournalLeaseError: Error, Equatable {
    case rootRequired, serviceIdentityRequired, invalidPath, busy, unsafeMetadata, identityChanged, invalidated, closed
    case system(Int32)
}

/// Holds the authority's existing directory, writer lock and database identities for one process lifetime.
/// Serialize access. This lease does not validate journal contents or permit dispatch.
public final class ProtectedJournalLease {
    private let storage: ProtectedStorageLease
    func directoryIdentities() throws -> [ProtectedStorageLease.DirectoryIdentity] {
        try storage.directoryIdentities()
    }
    public var databasePath: String { storage.databasePath }

    /// Setup must already have provisioned the root-owned directory and both 0600 files.
    public static func acquire(directoryPath: String) throws -> ProtectedJournalLease {
        guard geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        guard directoryPath.hasPrefix("/") else { throw JournalLeaseError.invalidPath }
        return try ProtectedJournalLease(anchor: "/", relativeDirectory: String(directoryPath.dropFirst()), owner: 0)
    }

    /// Internal fixture entry point. Production starts at / and requires UID 0 through acquire.
    init(anchor: String, relativeDirectory: String, owner: uid_t) throws {
        storage = try ProtectedStorageLease(anchor: anchor, relativeDirectory: relativeDirectory,
            owner: owner, ancestorOwner: owner, databaseName: "journal.sqlite")
    }

    /// Call before opening SQLite and at authority commit/recovery boundaries. Failure retires this lease.
    public func validate() throws { try storage.validate() }

    /// Close SQLite first. This releases ownership, not files or persisted recovery state.
    public func close() { storage.close() }
}
