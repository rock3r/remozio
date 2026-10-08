/* This isolated fixture invalidates only its own observer descriptor. */
#include "CommandCallerObservation.c"
#include <signal.h>
int main(void) {
    audit_token_t token = {0}; bool missing = false;
    if (remozio_pid_audit_token(getpid(), &token, &missing) != KERN_SUCCESS || missing) return 1;
    remozio_command_caller_observer_t *observer = NULL;
    if (remozio_command_caller_observer_create(&token, &observer) || !observer) return 2;
    if (!(fcntl(observer->events, F_GETFD) & FD_CLOEXEC)) return 3;
    close(observer->events); observer->events = -1;
    remozio_command_caller_observation_t state = REMOZIO_CALLER_UNCHANGED;
    if (remozio_command_caller_observer_poll(observer, &state) != EBADF || state != REMOZIO_CALLER_UNAVAILABLE) return 4;
    if (remozio_command_caller_observer_poll(observer, &state) || state != REMOZIO_CALLER_UNAVAILABLE) return 5;
    remozio_command_caller_observer_close(observer);
    token.val[1] ^= 1;
    observer = NULL;
    if (remozio_command_caller_observer_create(&token, &observer) != EAGAIN || observer) return 6;
    return kill(getpid(), 0) == 0 ? 0 : 7;
}
