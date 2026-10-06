import Darwin
import Foundation
import RemozioMach
import RemozioProtocol

/// Internal sampling seam. Product callers enter through the retained, policy-checked caller.
enum CommandAncestryObservation {
    struct Process {
        let token: audit_token_t
        let parentPID: pid_t
        let path: Data?
        var pid: pid_t { audit_token_to_pid(token) }
    }
    struct Unavailable: Error { let reason: AncestryReason }

    static func capture(source: audit_token_t, maximumEntries: Int, checkCancellation: () throws -> Void = {},
                        read: (pid_t) throws -> Process = sample) throws -> CapturedAncestry {
        guard (0...64).contains(maximumEntries) else { throw MachCommandCallerError.configuration }
        var entries: [CapturedAncestor] = []
        func limited(_ reason: AncestryReason) -> CapturedAncestry {
            CapturedAncestry(completeness: entries.isEmpty ? .unavailable : .partial, entries: entries, reason: reason)
        }
        do {
            try checkCancellation()
            var child = try read(audit_token_to_pid(source))
            guard sameToken(child.token, source) else { throw MachCommandCallerError.wrongPeer }
            var seen: Set<pid_t> = [child.pid]
            while child.parentPID > 0 {
                try checkCancellation()
                guard entries.count < maximumEntries else { return limited(.truncated) }
                guard !seen.contains(child.parentPID) else { return limited(.unsupported) }
                let parent = try read(child.parentPID)
                let checked = try read(child.pid)
                if child.pid == audit_token_to_pid(source), !sameToken(checked.token, source) {
                    throw MachCommandCallerError.wrongPeer
                }
                guard sameToken(child.token, checked.token), checked.parentPID == parent.pid else {
                    let ended = audit_token_to_pidversion(child.token) != audit_token_to_pidversion(checked.token)
                    return limited(ended ? .exited : .unsupported)
                }
                entries.append(CapturedAncestor(pid: UInt32(parent.pid), pidVersion: UInt32(bitPattern: audit_token_to_pidversion(parent.token)),
                    executablePath: parent.path, uid: audit_token_to_euid(parent.token)))
                seen.insert(parent.pid)
                child = parent
            }
            try checkCancellation()
            return CapturedAncestry(completeness: .complete, entries: entries, reason: .none)
        } catch let failure as Unavailable { return limited(failure.reason) }
    }

    static func sameToken(_ a: audit_token_t, _ b: audit_token_t) -> Bool {
        var a = a, b = b
        return withUnsafeBytes(of: &a) { first in withUnsafeBytes(of: &b) { first.elementsEqual($0) } }
    }

    static func sample(_ pid: pid_t) throws -> Process {
        var token = audit_token_t()
        let result = remozio_pid_audit_token(pid, &token)
        guard result == KERN_SUCCESS else {
            throw Unavailable(reason: result == KERN_PROTECTION_FAILURE ? .permission : .unsupported)
        }
        var bsd = proc_bsdshortinfo()
        errno = 0
        let size = proc_pidinfo(pid, PROC_PIDT_SHORTBSDINFO, 0, &bsd, Int32(MemoryLayout<proc_bsdshortinfo>.size))
        guard size == MemoryLayout<proc_bsdshortinfo>.size else {
            let reason: AncestryReason = errno == ESRCH ? .exited : (errno == EACCES || errno == EPERM ? .permission : .unsupported)
            throw Unavailable(reason: reason)
        }
        guard bsd.pbsi_pid == UInt32(pid), bsd.pbsi_uid == audit_token_to_euid(token), bsd.pbsi_ppid <= Int32.max else {
            throw Unavailable(reason: .unsupported)
        }
        var bytes = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        let length = proc_pidpath_audittoken(&token, &bytes, UInt32(bytes.count))
        let path: Data?
        if length > 0, bytes.first == 0x2f, let end = bytes.firstIndex(of: 0) {
            path = Data(bytes[..<end].map { UInt8(bitPattern: $0) })
        } else { path = nil }
        var checked = audit_token_t()
        let checkedResult = remozio_pid_audit_token(pid, &checked)
        guard checkedResult == KERN_SUCCESS else {
            throw Unavailable(reason: checkedResult == KERN_PROTECTION_FAILURE ? .permission : .unsupported)
        }
        guard sameToken(token, checked) else {
            throw Unavailable(reason: audit_token_to_pidversion(token) != audit_token_to_pidversion(checked) ? .exited : .unsupported)
        }
        return Process(token: token, parentPID: pid_t(bsd.pbsi_ppid), path: path)
    }
}
