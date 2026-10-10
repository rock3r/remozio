#include "include/RemozioCommandStreamSource.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <string.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

int remozio_command_stream_source_is_terminal_alias(int source, bool *alias) {
    if (!alias) return EINVAL;
    *alias = false;
    struct stat original, dynamic;
    if (fstat(source, &original) < 0) return errno;
    if (!S_ISCHR(original.st_mode)) return 0;
    if (fstatat(AT_FDCWD, "/dev/tty", &dynamic, AT_SYMLINK_NOFOLLOW) < 0) return errno;
    if (!S_ISCHR(dynamic.st_mode)) return ENOTTY;
    *alias = original.st_rdev == dynamic.st_rdev;
    return 0;
}

static int caller_snapshot(struct proc_bsdinfo *info, pid_t *session) {
    memset(info, 0, sizeof(*info));
    int count = proc_pidinfo(getpid(), PROC_PIDTBSDINFO, 0, info, sizeof(*info));
    if (count != sizeof(*info)) return count < 0 ? errno : ESRCH;
    *session = getsid(0);
    if (*session < 0) return errno;
    return info->e_tdev == (uint32_t)-1 ? ENOTTY : 0;
}

static bool same_caller(const struct proc_bsdinfo *before, const struct proc_bsdinfo *after) {
    return before->pbi_pid == after->pbi_pid && before->pbi_start_tvsec == after->pbi_start_tvsec &&
        before->pbi_start_tvusec == after->pbi_start_tvusec && before->e_tdev == after->e_tdev;
}

/* Inspect only device metadata. A name never supplies the terminal identity. */
static int open_terminal(dev_t device, int flags, int *output) {
    int directory = open("/dev", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory < 0) return errno;
    struct stat directory_info;
    if (fstat(directory, &directory_info) < 0) { int error = errno; close(directory); return error; }
    if (directory_info.st_uid != 0 || (directory_info.st_mode & (S_IWGRP | S_IWOTH))) {
        close(directory); return EPERM;
    }
    DIR *entries = fdopendir(directory);
    if (!entries) { int error = errno; close(directory); return error; }
    int error = ENOENT;
    struct dirent *entry;
    while (true) {
        errno = 0;
        entry = readdir(entries);
        if (!entry) { if (errno) error = errno; break; }
        struct stat candidate;
        if (fstatat(directory, entry->d_name, &candidate, AT_SYMLINK_NOFOLLOW) < 0 ||
            !S_ISCHR(candidate.st_mode) || candidate.st_rdev != device) continue;
        int descriptor = openat(directory, entry->d_name, flags | O_CLOEXEC | O_NOFOLLOW | O_NOCTTY);
        if (descriptor < 0) { error = errno; break; }
        struct stat actual;
        if (fstat(descriptor, &actual) < 0) error = errno;
        else if (!S_ISCHR(actual.st_mode) || actual.st_dev != candidate.st_dev ||
            actual.st_ino != candidate.st_ino || actual.st_rdev != device) error = ESTALE;
        else { *output = descriptor; error = 0; break; }
        close(descriptor);
        break;
    }
    closedir(entries);
    return error;
}

int remozio_command_stream_source_retain(int source, int *output) {
    if (!output) return EINVAL;
    *output = -1;
    int retained = fcntl(source, F_DUPFD_CLOEXEC, 3);
    if (retained < 0) return errno;
    bool alias = false;
    int error = remozio_command_stream_source_is_terminal_alias(retained, &alias);
    if (error) { close(retained); return error; }
    if (!alias) { *output = retained; return 0; }
    struct proc_bsdinfo before, after;
    pid_t session = -1, final_session = -1;
    int original_flags = fcntl(retained, F_GETFL);
    if (original_flags < 0) error = errno;
    else if (original_flags & O_EVTONLY) error = EBADF;
    if (!error) error = caller_snapshot(&before, &session);
    int fixed = -1;
    const int io_flags = O_ACCMODE | O_NONBLOCK | O_APPEND | O_ASYNC | O_SYNC;
    if (!error) error = open_terminal((dev_t)before.e_tdev, original_flags & io_flags, &fixed);
    if (!error) {
        pid_t terminal_session = tcgetsid(fixed);
        if (terminal_session < 0) error = errno;
        else if (terminal_session != session) error = ESTALE;
    }
    if (!error) error = caller_snapshot(&after, &final_session);
    if (!error && (!same_caller(&before, &after) || session != final_session)) error = ESTALE;
    if (!error) {
        int current_flags = fcntl(retained, F_GETFL), fixed_flags = fcntl(fixed, F_GETFL);
        if (current_flags < 0 || fixed_flags < 0) error = errno;
        else if (current_flags != original_flags || (fixed_flags & io_flags) != (original_flags & io_flags)) error = ESTALE;
    }
    close(retained);
    if (error) { if (fixed >= 0) close(fixed); return error; }
    *output = fixed;
    return 0;
}
