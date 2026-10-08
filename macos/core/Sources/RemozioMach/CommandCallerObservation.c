
#include "RemozioCommandCaller.h"
#include "RemozioMach.h"
#include <bsm/libbsm.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <unistd.h>
struct remozio_command_caller_observer { int events; pid_t pid; remozio_command_caller_observation_t state; };
static int check_binding(const audit_token_t *expected) {
    audit_token_t actual = {0}; bool missing = false;
    kern_return_t result = remozio_pid_audit_token(audit_token_to_pid(*expected), &actual, &missing);
    if (result != KERN_SUCCESS) return missing ? ESRCH : ENOTSUP;
    return memcmp(expected, &actual, sizeof(actual)) == 0 ? 0 : EAGAIN;
}
int remozio_command_caller_observer_create(const audit_token_t *token, remozio_command_caller_observer_t **output) {
    if (!output) return EINVAL;
    *output = NULL;
    if (!token || audit_token_to_pid(*token) <= 0) return EINVAL;
    int error = check_binding(token);
    if (error) return error;
    remozio_command_caller_observer_t *observer = calloc(1, sizeof(*observer));
    if (!observer) return ENOMEM;
    observer->events = kqueue(); observer->pid = audit_token_to_pid(*token);
    if (observer->events < 0) { error = errno; goto fail; }
    if (fcntl(observer->events, F_SETFD, FD_CLOEXEC) != 0) { error = errno; goto fail; }
    struct kevent change, receipt; struct timespec timeout = {0, 0};
    EV_SET(&change, observer->pid, EVFILT_PROC, EV_ADD | EV_ENABLE | EV_CLEAR | EV_RECEIPT, NOTE_EXEC | NOTE_EXIT, 0, NULL);
    int count = kevent(observer->events, &change, 1, &receipt, 1, &timeout);
    if (count != 1) { error = count < 0 ? errno : EPROTO; goto fail; }
    if (!(receipt.flags & EV_ERROR) || receipt.ident != (uintptr_t)observer->pid || receipt.filter != EVFILT_PROC) { error = EPROTO; goto fail; }
    if (receipt.data) { error = (int)receipt.data; goto fail; }
    error = check_binding(token);
    if (error) goto fail;
    *output = observer; return 0;
fail:
    remozio_command_caller_observer_close(observer); return error;
}
int remozio_command_caller_observer_poll(remozio_command_caller_observer_t *observer, remozio_command_caller_observation_t *state) {
    if (!observer || !state) return EINVAL;
    *state = observer->state;
    if (observer->state != REMOZIO_CALLER_UNCHANGED) return 0;
    struct kevent event; struct timespec timeout = {0, 0};
    int count = kevent(observer->events, NULL, 0, &event, 1, &timeout);
    if (count < 0 && errno == EINTR) return 0;
    int error = 0;
    if (count < 0) error = errno;
    else if (count > 0) {
        if (event.ident != (uintptr_t)observer->pid || event.filter != EVFILT_PROC) error = EPROTO;
        else if ((event.flags & EV_ERROR) && event.data) error = (int)event.data;
        else if (event.fflags & NOTE_EXEC) observer->state = REMOZIO_CALLER_CHANGED;
        else if (event.fflags & NOTE_EXIT) observer->state = REMOZIO_CALLER_EXITED;
    }
    if (error) observer->state = REMOZIO_CALLER_UNAVAILABLE;
    *state = observer->state; return error;
}
void remozio_command_caller_observer_close(remozio_command_caller_observer_t *observer) {
    if (!observer) return;
    if (observer->events >= 0) close(observer->events);
    free(observer);
}

