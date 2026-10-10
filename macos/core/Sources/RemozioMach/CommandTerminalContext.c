#include "include/RemozioCommandTerminalContext.h"
#include "include/RemozioMach.h"
#include <bsm/libbsm.h>
#include <errno.h>
#include <libproc.h>
#include <string.h>
#include <unistd.h>

static int original_incarnation(const audit_token_t *caller) {
    audit_token_t actual = {0};
    bool missing = false;
    kern_return_t result = remozio_pid_audit_token(audit_token_to_pid(*caller), &actual, &missing);
    if (result != KERN_SUCCESS) return missing ? ESRCH : ENOTSUP;
    return memcmp(caller, &actual, sizeof(actual)) ? EAGAIN : 0;
}

static int sample(pid_t process, remozio_command_terminal_context_t *output) {
    struct proc_bsdinfo info = {0};
    errno = 0;
    int count = proc_pidinfo(process, PROC_PIDTBSDINFO, 0, &info, sizeof(info));
    if (count != sizeof(info)) return errno ? errno : ESRCH;
    pid_t session = getsid(process);
    if (session < 0) return errno;
    if (info.pbi_pid != (uint32_t)process || session == 0) return EAGAIN;
    /* Revocation can leave CONTROLT set after the session loses its terminal device. */
    bool terminal = (info.pbi_flags & PROC_FLAG_CONTROLT) != 0 && info.e_tdev != (uint32_t)-1;
    *output = (remozio_command_terminal_context_t) {
        .process = process, .session = session,
        .start_seconds = info.pbi_start_tvsec, .start_microseconds = info.pbi_start_tvusec,
        .has_terminal = terminal, .terminal_device = terminal ? info.e_tdev : (uint32_t)-1
    };
    return 0;
}

static bool same(const remozio_command_terminal_context_t *first, const remozio_command_terminal_context_t *second) {
    return first->process == second->process && first->session == second->session &&
        first->start_seconds == second->start_seconds && first->start_microseconds == second->start_microseconds &&
        first->has_terminal == second->has_terminal && first->terminal_device == second->terminal_device;
}

int remozio_command_terminal_context_capture(const audit_token_t *caller, remozio_command_terminal_context_t *output) {
    if (!output) return EINVAL;
    memset(output, 0, sizeof(*output));
    if (!caller || audit_token_to_pid(*caller) <= 0) return EINVAL;
    int error = original_incarnation(caller);
    if (error) return error;
    remozio_command_terminal_context_t first = {0}, second = {0};
    error = sample(audit_token_to_pid(*caller), &first);
    if (!error) error = original_incarnation(caller);
    if (!error) error = sample(audit_token_to_pid(*caller), &second);
    if (!error) error = original_incarnation(caller);
    if (!error && !same(&first, &second)) error = EAGAIN;
    if (error) return error;
    *output = second;
    return 0;
}

int remozio_command_terminal_context_recheck(const audit_token_t *caller,
    const remozio_command_terminal_context_t *original) {
    if (!original || !caller || original->process != audit_token_to_pid(*caller) || original->session <= 0) return EINVAL;
    remozio_command_terminal_context_t current = {0};
    int error = remozio_command_terminal_context_capture(caller, &current);
    if (error) return error;
    return same(original, &current) ? 0 : ESTALE;
}
