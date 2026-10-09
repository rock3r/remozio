#ifndef REMOZIO_COMMAND_MONITOR_H
#define REMOZIO_COMMAND_MONITOR_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include "RemozioCommandMonitorProtocol.h"
typedef struct remozio_command_monitor remozio_command_monitor_t;
typedef struct {
    pid_t monitor_pid;
    bool configured, prepared, release_attempted, cancelled;
    bool target_kernel_registered, target_exec_observed, target_exit_observed;
    bool monitor_exit_observed, monitor_reaped, monitor_ownership_lost;
    bool status_closed;
    int monitor_wait_status, fault;
    bool protocol_failed;
    remozio_monitor_stream_t status;
} remozio_command_monitor_observation_t;
/* Both absolute helper paths must be verified by the serialized Root owner.
 * Borrow stdio and the retained directory without touching their shared flags.
 * The monitor owns target waitpid; this parent exclusively owns monitor waitpid.
 * Return every successfully spawned monitor, even when subsequent setup fails. */
int remozio_command_monitor_spawn(const char *monitor_path, const char *child_path,
    const void *frame, size_t count, int input, int output, int error, int directory,
    remozio_command_monitor_t **monitor);
/* Bounded private-frame/status/control progress and nonblocking kernel/reap observations.
 * Register and independently bind the prepared target before making release available.
 * A status record, clean EOF or monitor exit alone is never a command outcome.
 * On failure, cancel and continue polling until the monitor retires. */
int remozio_command_monitor_poll(remozio_command_monitor_t *monitor,
    remozio_command_monitor_observation_t *observation);
/* Consumed before one byte write, including failure. Requires no fault or cancellation,
 * complete configuration, prepared target and independent target kernel registration.
 * Root must separately consume the durable permit and finish policy/capture/code checks. */
int remozio_command_monitor_release(remozio_command_monitor_t *monitor);
/* Private bounded controls only. The authenticated original caller is checked upstream.
 * Never directly signal or wait on the target from this Root-side owner.
 * Preserve cancellation before target preparation; no guessed PID or group. */
int remozio_command_monitor_signal(remozio_command_monitor_t *monitor, int signal);
int remozio_command_monitor_cancel(remozio_command_monitor_t *monitor);
/* Preserve ownership until actual monitor reaping or explicit ownership loss.
 * No blocking destructor, authority reuse, automatic retry or borrowed target signaling. */
int remozio_command_monitor_dispose(remozio_command_monitor_t *monitor);
#endif
