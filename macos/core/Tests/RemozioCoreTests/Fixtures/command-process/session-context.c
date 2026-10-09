/* Disposable session owner. This fixture creates no service and requests no privilege. */
#include "RemozioCommandProcess.h"
#include "RemozioCommandPTY.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>

static int await_state(remozio_command_process_t *process, remozio_command_process_observation_t *state, int phase, uint64_t baseline) {
    for (unsigned attempt = 0; attempt < 8000; ++attempt) {
        int error = remozio_command_process_poll(process, state);
        if (error) return error;
        if ((phase == 0 && state->prepared) || (phase == 1 && state->exec_observed) ||
            (phase == 2 && state->stopped && state->job_control_revision > baseline) ||
            (phase == 3 && !state->stopped && state->job_control_revision > baseline) ||
            (phase == 4 && state->reaped)) return 0;
        usleep(1000);
    }
    return ETIMEDOUT;
}
static int run_owner(const char *launcher, const char *frame_path, const char *mode) {
    int result = 1, input[2] = {-1, -1}, output[2] = {-1, -1}, errors[2] = {-1, -1};
    int directory = -1, slave = -1;
    remozio_command_pty_t *terminal = NULL;
    remozio_command_process_t *process = NULL;
    remozio_command_process_observation_t state = {0};
    unsigned char *frame = NULL;
    bool pipe_mode = strcmp(mode, "pipes") == 0;
    bool reject = strcmp(mode, "unowned_terminal") == 0 || strcmp(mode, "not_session_leader") == 0;
    FILE *file = fopen(frame_path, "rb");
    if (!file || fseek(file, 0, SEEK_END) || ftell(file) <= 0) { if (file) fclose(file); return 2; }
    size_t count = (size_t)ftell(file);
    rewind(file); frame = malloc(count);
    if (!frame || fread(frame, 1, count, file) != count) { fclose(file); free(frame); return 3; }
    fclose(file);
    if (strcmp(mode, "not_session_leader") == 0) pipe_mode = true;
    if (pipe_mode) {
        if (pipe(input) || pipe(output) || pipe(errors) || write(input[1], "unread", 6) != 6) goto cleanup;
        slave = input[0];
    } else {
        if (remozio_command_pty_create(NULL, NULL, &terminal) || remozio_command_pty_borrow_slave(terminal, &slave)) goto cleanup;
        if (!reject && ioctl(slave, TIOCSCTTY, 0)) goto cleanup;
    }
    directory = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory < 0) goto cleanup;
    int flags = fcntl(slave, F_GETFL);
    int error = remozio_command_process_spawn_in_session(launcher, frame, count, slave,
        pipe_mode ? output[1] : slave, pipe_mode ? errors[1] : slave, directory, &process);
    if (reject) {
        if (error != EINVAL || process != NULL || fcntl(slave, F_GETFL) != flags) goto cleanup;
        if (pipe_mode) {
            char bytes[6]; int available = 0;
            if (ioctl(slave, FIONREAD, &available) || available != 6 || read(slave, bytes, 6) != 6 || memcmp(bytes, "unread", 6)) goto cleanup;
        }
        result = 0; goto cleanup;
    }
    if (error || !process || await_state(process, &state, 0, 0)) goto cleanup;
    if (state.exec_observed || state.release_attempted || fcntl(slave, F_GETFL) != flags) goto cleanup;
    if (getsid(state.pid) != getpid() || getpgid(state.pid) != state.pid || state.pid == getpid()) goto cleanup;
    if (pipe_mode) {
        int available = 0;
        if (ioctl(slave, FIONREAD, &available) || available != 6) goto cleanup;
    } else if (tcgetsid(slave) != getpid() || tcgetpgrp(slave) != state.pid) goto cleanup;
    if (remozio_command_process_release(process) || remozio_command_process_release(process) != EALREADY || await_state(process, &state, 1, 0)) goto cleanup;
    uint64_t revision = state.job_control_revision;
    if (strcmp(mode, "terminal_character") == 0) {
        struct termios attributes; size_t written = 0;
        if (tcgetattr(slave, &attributes) || !(attributes.c_lflag & ISIG) || attributes.c_cc[VSUSP] == _POSIX_VDISABLE) goto cleanup;
        unsigned char byte = attributes.c_cc[VSUSP];
        if (remozio_command_pty_write(terminal, &byte, 1, &written) || written != 1) goto cleanup;
    } else if (remozio_command_process_signal(process, SIGTSTP)) goto cleanup;
    if (await_state(process, &state, 2, revision) || state.stop_signal != SIGTSTP || state.reaped) goto cleanup;
    if (strcmp(mode, "stopped_cancel") != 0) {
        revision = state.job_control_revision;
        if (remozio_command_process_signal(process, SIGCONT) || await_state(process, &state, 3, revision)) goto cleanup;
    }
    if (remozio_command_process_cancel(process) || await_state(process, &state, 4, 0)) goto cleanup;
    if (!state.exec_observed || !state.exit_observed || !WIFSIGNALED(state.wait_status) || WTERMSIG(state.wait_status) != SIGKILL || state.stopped) goto cleanup;
    if (remozio_command_process_signal(process, SIGCONT) != ESRCH) goto cleanup;
    if (pipe_mode) {
        char bytes[6];
        if (read(slave, bytes, 6) != 6 || memcmp(bytes, "unread", 6)) goto cleanup;
    }
    result = 0;
cleanup:
    if (process) {
        (void)remozio_command_process_cancel(process);
        for (unsigned attempt = 0; attempt < 8000; ++attempt) {
            (void)remozio_command_process_poll(process, &state);
            if (state.reaped || state.ownership_lost) break;
            usleep(1000);
        }
        if (remozio_command_process_dispose(process)) result = 1;
    }
    /* The fixture alone owns this disposable terminal. */
    signal(SIGHUP, SIG_IGN);
    if (terminal) remozio_command_pty_close(terminal);
    for (unsigned i = 0; i < 2; ++i) {
        if (input[i] >= 0) close(input[i]);
        if (output[i] >= 0) close(output[i]);
        if (errors[i] >= 0) close(errors[i]);
    }
    if (directory >= 0) close(directory);
    free(frame);
    if (result) fprintf(stderr, "Session fixture failed: %s, pid=%d, prepared=%d, exec=%d, stopped=%d, revision=%llu, reaped=%d\n",
        mode, state.pid, state.prepared, state.exec_observed, state.stopped, (unsigned long long)state.job_control_revision, state.reaped);
    return result;
}
int main(int argc, char **argv) {
    if (argc == 5 && strcmp(argv[4], "--session-owner") == 0) {
        if (getsid(0) != getpid() || getpgrp() != getpid()) return 4;
        signal(SIGTTOU, SIG_IGN);
        return run_owner(argv[1], argv[2], argv[3]);
    }
    if (argc != 4) return 5;
    if (strcmp(argv[3], "not_session_leader") == 0) {
        if (getsid(0) == getpid()) return 6;
        return run_owner(argv[1], argv[2], argv[3]);
    }
    posix_spawnattr_t attributes;
    if (posix_spawnattr_init(&attributes)) return 7;
    sigset_t empty, defaults; sigemptyset(&empty); sigfillset(&defaults);
    int error = posix_spawnattr_setsigmask(&attributes, &empty);
    if (!error) error = posix_spawnattr_setsigdefault(&attributes, &defaults);
    if (!error) error = posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETSID | POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF);
    pid_t owner = -1;
    char *arguments[] = {argv[0], argv[1], argv[2], argv[3], "--session-owner", NULL};
    char *environment[] = {NULL};
    if (!error) error = posix_spawn(&owner, argv[0], NULL, &attributes, arguments, environment);
    posix_spawnattr_destroy(&attributes);
    if (error) return 8;
    int status = 0;
    while (waitpid(owner, &status, 0) < 0) if (errno != EINTR) return 9;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 10;
}
