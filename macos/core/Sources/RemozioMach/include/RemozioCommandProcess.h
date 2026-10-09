#ifndef REMOZIO_COMMAND_PROCESS_H
#define REMOZIO_COMMAND_PROCESS_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
/* Private process mechanics only. The authority must verify installation and consume a durable permit before release. */
typedef struct remozio_command_process remozio_command_process_t;
typedef struct {
    pid_t pid;
    bool configured, prepared, release_attempted, exec_observed, exit_observed, reaped;
    bool preparation_failed, status_closed, ownership_lost;
    int preparation_error, wait_status;
    /* Latest observed stop state. Stop records never consume the child exit result. */
    bool stopped;
    /* Raw waitid evidence. Darwin stop codes do not classify debugger stops. */
    int stop_signal, stop_code;
    /* Current stopped-process snapshot. Unknown never establishes an ordinary job-control stop. */
    bool stop_tracing_known, stop_traced;
    uint64_t job_control_revision;
} remozio_command_process_observation_t;
/* Borrows stdio and directory. Output owns any successfully spawned child, including a later setup failure.
 * The caller must cancel, poll until reaped, and dispose every non-null output. The caller must be the exclusive waitpid owner. No operation waits for child exit.
 * The path must identify the protected, verified launcher. This function does not validate code identity or policy. */
int remozio_command_process_spawn(const char *path, const void *frame, size_t count,
    int input, int output, int error, int directory, remozio_command_process_t **process);
/* Only a dedicated session leader may call this API. PTY mode requires its owned foreground terminal.
 * The child keeps the monitor session and receives a separate process group before preparation resumes.
 * The same protected launcher, exclusive owner and durable release requirements apply. */
int remozio_command_process_spawn_in_session(const char *path, const void *frame, size_t count,
    int input, int output, int error, int directory, remozio_command_process_t **process);
/* Nonblocking progress, including at most four owned stop/continue records per poll.
 * A private status EOF never establishes exec. Exit status is meaningful only after reaping. */
int remozio_command_process_poll(remozio_command_process_t *process, remozio_command_process_observation_t *observation);
/* Single attempt, including a failed write. Only the serialized authority dispatch owner may call this after its final checks. */
int remozio_command_process_release(remozio_command_process_t *process);
/* The child leader stays owned and unreaped while signaling its process group. */
int remozio_command_process_signal(remozio_command_process_t *process, int signal);
int remozio_command_process_cancel(remozio_command_process_t *process);
/* EBUSY retains ownership. No PID or process group may be used after successful disposal. */
int remozio_command_process_dispose(remozio_command_process_t *process);
#endif
