#ifndef REMOZIO_COMMAND_CALLER_H
#define REMOZIO_COMMAND_CALLER_H
#include <mach/mach.h>

typedef struct remozio_command_caller_observer remozio_command_caller_observer_t;
typedef enum {
    REMOZIO_CALLER_UNCHANGED,
    REMOZIO_CALLER_EXITED,
    REMOZIO_CALLER_CHANGED,
    REMOZIO_CALLER_UNAVAILABLE
} remozio_command_caller_observation_t;

/* Optional observation of the original audit token. This grants no signal, wait, or execution authority. */
int remozio_command_caller_observer_create(const audit_token_t * _Nonnull token,
    remozio_command_caller_observer_t * _Nullable * _Nonnull output);
/* A nonblocking observation. Exec takes precedence over exit; terminal states remain unchanged. */
int remozio_command_caller_observer_poll(remozio_command_caller_observer_t * _Nonnull observer,
    remozio_command_caller_observation_t * _Nonnull state);
void remozio_command_caller_observer_close(remozio_command_caller_observer_t * _Nullable observer);
#endif
