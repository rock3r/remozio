import Darwin

enum ProtectedStorageMetadata {
    static func validate(_ fd: Int32, _ info: stat, directory: Bool, privateObject: Bool, owner: uid_t, ancestorOwner: uid_t) throws {
        guard info.st_uid == (privateObject ? owner : ancestorOwner), (info.st_mode & S_IFMT) == (directory ? S_IFDIR : S_IFREG),
              info.st_mode & 0o7000 == 0,
              privateObject ? info.st_mode & 0o777 == (directory ? 0o700 : 0o600) : info.st_mode & 0o022 == 0,
              directory || info.st_nlink == 1 else { throw JournalLeaseError.unsafeMetadata }
        var filesystem = statfs()
        guard fstatfs(fd, &filesystem) == 0 else { throw JournalLeaseError.system(errno) }
        guard filesystem.f_flags & UInt32(MNT_LOCAL) != 0 else { throw JournalLeaseError.unsafeMetadata }
        try accessList(fd, privateObject: privateObject)
    }
    private static func accessList(_ fd: Int32, privateObject: Bool) throws {
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
