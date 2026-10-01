import Darwin
import Foundation

public enum JournalLeaseError: Error, Equatable {
    case rootRequired, invalidPath, busy, unsafeMetadata, identityChanged, invalidated, closed
    case system(Int32)
}

/// Holds the authority's existing directory, writer lock and database identities for one process lifetime.
/// Serialize access. This lease coordinates cooperating writers; it does not validate journal contents or permit dispatch.
public final class ProtectedJournalLease {
    public let databasePath: String
    private struct Node {
        let fd: Int32
        let parent: Int32?
        let name: String
        let device: dev_t
        let inode: ino_t
        let directory: Bool
        let privateObject: Bool
    }
    private var nodes: [Node] = []
    private let owner: uid_t
    private let processID = getpid()
    private var invalidated = false
    private var isClosed = false

    /// Production entry point. Setup must already have provisioned the root-owned directory and both 0600 files.
    public static func acquire(directoryPath: String) throws -> ProtectedJournalLease {
        guard geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        guard directoryPath.hasPrefix("/") else { throw JournalLeaseError.invalidPath }
        return try ProtectedJournalLease(anchor: "/", relativeDirectory: String(directoryPath.dropFirst()), owner: 0)
    }

    /// Internal fixture entry point. Production always starts at / and requires UID 0 through acquire.
    init(anchor: String, relativeDirectory: String, owner: uid_t) throws {
        let components = relativeDirectory.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard !components.isEmpty, !anchor.utf8.contains(0),
              components.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." && !$0.utf8.contains(0) && $0.utf8.count <= 255 }) else {
            throw JournalLeaseError.invalidPath
        }
        self.owner = owner
        databasePath = (anchor == "/" ? "" : anchor) + "/" + relativeDirectory + "/journal.sqlite"
        guard databasePath.utf8.count < Int(PATH_MAX) else { throw JournalLeaseError.invalidPath }
        do {
            let anchorFD = open(anchor, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard anchorFD >= 0 else { throw JournalLeaseError.system(errno) }
            try add(anchorFD, parent: nil, name: anchor, directory: true, privateObject: false)
            var parent = anchorFD
            for (index, component) in components.enumerated() {
                let fd = openat(parent, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard fd >= 0 else { throw JournalLeaseError.system(errno) }
                try add(fd, parent: parent, name: component, directory: true, privateObject: index == components.count - 1)
                parent = fd
            }
            let lock = try openFile("writer.lock", parent: parent)
            guard flock(lock, LOCK_EX | LOCK_NB) == 0 else {
                throw errno == EWOULDBLOCK ? JournalLeaseError.busy : JournalLeaseError.system(errno)
            }
            _ = try openFile("journal.sqlite", parent: parent)
            try validate()
        } catch {
            close()
            throw error
        }
    }

    deinit { close() }

    /// Call before opening SQLite and at authority commit/recovery boundaries. Any failed check retires this lease.
    public func validate() throws {
        guard !isClosed else { throw JournalLeaseError.closed }
        guard !invalidated else { throw JournalLeaseError.invalidated }
        do {
            guard getpid() == processID, geteuid() == owner else { throw JournalLeaseError.unsafeMetadata }
            for node in nodes {
                var held = stat(), named = stat()
                guard fstat(node.fd, &held) == 0 else { throw JournalLeaseError.system(errno) }
                let rc = node.parent.map { fstatat($0, node.name, &named, AT_SYMLINK_NOFOLLOW) } ?? lstat(node.name, &named)
                guard rc == 0 else { throw JournalLeaseError.system(errno) }
                guard held.st_dev == node.device, held.st_ino == node.inode,
                      named.st_dev == node.device, named.st_ino == node.inode,
                      (named.st_mode & S_IFMT) == (node.directory ? S_IFDIR : S_IFREG) else { throw JournalLeaseError.identityChanged }
                try metadata(node.fd, held, directory: node.directory, privateObject: node.privateObject)
            }
        } catch {
            invalidated = true
            throw error
        }
    }

    /// Close SQLite before releasing the lease. This releases ownership, not files or persisted recovery state.
    public func close() {
        guard !isClosed else { return }
        isClosed = true
        for node in nodes.reversed() { _ = Darwin.close(node.fd) }
        nodes.removeAll()
    }

    private func openFile(_ name: String, parent: Int32) throws -> Int32 {
        // Nonblocking prevents a substituted FIFO from hanging acquisition before its type is checked.
        let fd = openat(parent, name, O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { throw JournalLeaseError.system(errno) }
        try add(fd, parent: parent, name: name, directory: false, privateObject: true)
        return fd
    }
    private func add(_ fd: Int32, parent: Int32?, name: String, directory: Bool, privateObject: Bool) throws {
        do {
            var info = stat()
            guard fstat(fd, &info) == 0 else { throw JournalLeaseError.system(errno) }
            try metadata(fd, info, directory: directory, privateObject: privateObject)
            nodes.append(Node(fd: fd, parent: parent, name: name, device: info.st_dev, inode: info.st_ino,
                              directory: directory, privateObject: privateObject))
        } catch { _ = Darwin.close(fd); throw error }
    }
    private func metadata(_ fd: Int32, _ info: stat, directory: Bool, privateObject: Bool) throws {
        guard info.st_uid == owner, (info.st_mode & S_IFMT) == (directory ? S_IFDIR : S_IFREG),
              info.st_mode & 0o7000 == 0,
              privateObject ? info.st_mode & 0o777 == (directory ? 0o700 : 0o600) : info.st_mode & 0o022 == 0,
              directory || info.st_nlink == 1 else { throw JournalLeaseError.unsafeMetadata }
        var filesystem = statfs()
        guard fstatfs(fd, &filesystem) == 0 else { throw JournalLeaseError.system(errno) }
        guard filesystem.f_flags & UInt32(MNT_LOCAL) != 0 else { throw JournalLeaseError.unsafeMetadata }
        try accessList(fd, privateObject: privateObject)
    }
    private func accessList(_ fd: Int32, privateObject: Bool) throws {
        guard let security = filesec_init() else { throw JournalLeaseError.system(errno) }
        defer { filesec_free(security) }
        var info = stat(), present: Int32 = 0
        guard fstatx_np(fd, &info, security) == 0,
              filesec_query_property(security, FILESEC_ACL, &present) == 0 else { throw JournalLeaseError.system(errno) }
        guard present != 0 else { return }
        var value: acl_t?
        guard filesec_get_property(security, FILESEC_ACL, &value) == 0, let acl = value else { throw JournalLeaseError.system(errno) }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        guard acl_valid(acl) == 0 else { throw JournalLeaseError.unsafeMetadata }
        let mutationPermissions: [acl_perm_t] = [ACL_WRITE_DATA, ACL_APPEND_DATA, ACL_DELETE, ACL_DELETE_CHILD,
            ACL_WRITE_ATTRIBUTES, ACL_WRITE_EXTATTRIBUTES, ACL_WRITE_SECURITY, ACL_CHANGE_OWNER]
        let mutationMask = mutationPermissions.reduce(UInt64(0)) { $0 | UInt64($1.rawValue) }
        for index in 0...Int(ACL_MAX_ENTRIES) {
            var entry: acl_entry_t?
            let selector = index == 0 ? ACL_FIRST_ENTRY : ACL_NEXT_ENTRY
            let rc = acl_get_entry(acl, selector.rawValue, &entry)
            if rc != 0 {
                guard errno == EINVAL else { throw JournalLeaseError.system(errno) }
                return // Darwin reports the end of a valid ACL as EINVAL, not the POSIX zero return.
            }
            guard index < ACL_MAX_ENTRIES, let entry else { throw JournalLeaseError.unsafeMetadata }
            var tag = ACL_UNDEFINED_TAG
            var permissions: acl_permset_mask_t = 0
            guard acl_get_tag_type(entry, &tag) == 0, acl_get_permset_mask_np(entry, &permissions) == 0 else {
                throw JournalLeaseError.system(errno)
            }
            guard tag == ACL_EXTENDED_ALLOW || tag == ACL_EXTENDED_DENY else { throw JournalLeaseError.unsafeMetadata }
            if tag == ACL_EXTENDED_ALLOW && (privateObject ? permissions != 0 : permissions & mutationMask != 0) {
                throw JournalLeaseError.unsafeMetadata
            }
        }
    }
}
