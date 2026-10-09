/* Disposable private-terminal experiment. No installed service or user terminal. */
#include "RemozioCommandMonitor.h"
/* Fixture-only access to the private master. Compile the current PTY implementation once. */
#include "CommandPTY.c"
#include <stdio.h>
#include <libproc.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>

static unsigned shell_stop_records;
int fixture_observe_record(remozio_monitor_stream_t *stream, const remozio_monitor_record_t *record) {
    int error = remozio_monitor_stream_accept(stream, record);
    if (!error && record->tag == REMOZIO_MONITOR_JOB_STATE && (record->flags & REMOZIO_MONITOR_STOPPED)) {
        ++shell_stop_records;
    }
    return error;
}
static int verify_record_observer(void) {
    remozio_monitor_stream_t stream;
    remozio_monitor_stream_init(&stream);
    remozio_monitor_record_t record = {.tag = REMOZIO_MONITOR_PREPARED, .target_pid = 123, .sequence = 1};
    if (fixture_observe_record(&stream, &record) || remozio_monitor_stream_note_release(&stream)) return 1;
    record = (remozio_monitor_record_t){.tag = REMOZIO_MONITOR_JOB_STATE,
        .flags = REMOZIO_MONITOR_TARGET_RELEASE_ATTEMPTED | REMOZIO_MONITOR_STOPPED,
        .target_pid = 123, .detail = SIGTSTP, .stop_code = CLD_STOPPED, .sequence = 2, .job_revision = 1};
    if (fixture_observe_record(&stream, &record)) return 1;
    record.flags = REMOZIO_MONITOR_TARGET_RELEASE_ATTEMPTED;
    record.detail = record.stop_code = 0; record.sequence = 3; record.job_revision = 2;
    if (fixture_observe_record(&stream, &record)) return 1;
    bool latest_continued = !(stream.latest.flags & REMOZIO_MONITOR_STOPPED);
    printf("{\"stopRecords\":%u,\"latestContinued\":%s}", shell_stop_records, latest_continued ? "true" : "false");
    return shell_stop_records == 1 && latest_continued ? 0 : 1;
}
static volatile sig_atomic_t interrupted;
static void interrupt_probe(int number) { (void)number; interrupted = 1; }
static uint64_t now_ms(void) {
    struct timespec time;
    clock_gettime(CLOCK_MONOTONIC, &time);
    return (uint64_t)time.tv_sec * 1000 + (uint64_t)time.tv_nsec / 1000000;
}
static int send_input(remozio_command_pty_t *pty, const char *text) {
    size_t count = 0;
    int error = remozio_command_pty_write(pty, text, strlen(text), &count);
    return error ? error : count == strlen(text) ? 0 : EIO;
}
static int send_signal(remozio_command_pty_t *pty, int number, bool typed) {
    if (!typed) return remozio_command_pty_signal(pty, number);
    struct termios attributes;
    if (tcgetattr(pty->master, &attributes)) return errno;
    unsigned char byte = attributes.c_cc[number == SIGTSTP ? VSUSP : VINTR];
    if (!(attributes.c_lflag & ISIG) || byte == _POSIX_VDISABLE) return EINVAL;
    size_t written = 0;
    int error = remozio_command_pty_write(pty, &byte, 1, &written);
    return error ? error : written == 1 ? 0 : EIO;
}
static bool foreground_sleep(pid_t group) {
    char path[PROC_PIDPATHINFO_MAXSIZE] = {0};
    if (group <= 0 || proc_pidpath(group, path, sizeof(path)) <= 0) return false;
    char *name = strrchr(path, '/');
    return name && !strcmp(name + 1, "sleep");
}
static int progress(remozio_command_monitor_t *monitor, remozio_command_monitor_observation_t *state,
                    remozio_command_pty_t *pty, char *output, size_t *used) {
    int error = remozio_command_monitor_poll(monitor, state);
    if (error) return error;
    for (unsigned turn = 0; turn < 4; ++turn) {
        size_t count = 0;
        bool eof = false;
        char bytes[4096];
        error = remozio_command_pty_read(pty, bytes, sizeof(bytes), &count, &eof);
        if (error) return error;
        if (!count) break;
        if (*used + count >= 32768) return EOVERFLOW;
        memcpy(output + *used, bytes, count);
        *used += count;
        output[*used] = 0;
    }
    return 0;
}
int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "record-regression")) return verify_record_observer();
    if (argc != 5 || (strcmp(argv[4], "typed") && strcmp(argv[4], "signal"))) return 1;
    struct sigaction action = {0};
    action.sa_handler = interrupt_probe;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) || sigaction(SIGINT, &action, NULL)) return 1;
    bool typed = !strcmp(argv[4], "typed");
    FILE *file = fopen(argv[3], "rb");
    if (!file) return 2;
    unsigned char frame[8192];
    size_t count = fread(frame, 1, sizeof(frame), file);
    fclose(file);
    remozio_command_pty_t *pty = NULL;
    remozio_command_monitor_t *monitor = NULL;
    remozio_command_monitor_observation_t state = {0};
    int failure = 0, directory = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC), slave = -1;
    char output[32768] = {0};
    size_t used = 0;
    bool nested_stop = false, nested_resume = false, interrupt = false;
    pid_t foreground = 0;
    if (directory < 0 || remozio_command_pty_create(NULL, NULL, &pty) ||
        remozio_command_pty_borrow_slave(pty, &slave)) { failure = 3; goto cleanup; }
    int spawn_error = remozio_command_monitor_spawn(argv[1], argv[2], frame, count,
                                                    slave, slave, slave, directory, &monitor);
    if (spawn_error || !monitor) {
        fprintf(stderr, "spawn_error=%d\n", spawn_error);
        failure = 4; goto cleanup;
    }
    remozio_command_pty_seal_slave(pty);
    uint64_t deadline = now_ms() + 12000;
    unsigned phase = 0;
    while (!interrupted && now_ms() < deadline && phase < 7) {
        if (progress(monitor, &state, pty, output, &used)) { failure = 5; goto cleanup; }
        pid_t group = tcgetpgrp(pty->master);
        if (phase == 0 && state.prepared) {
            if (!state.target_kernel_registered || remozio_command_monitor_release(monitor)) {
                failure = 6; goto cleanup;
            }
            phase = 1;
        } else if (phase == 1 && strstr(output, "READY_MARKER")) {
            if (send_input(pty, "/bin/sleep 60\n")) { failure = 7; goto cleanup; }
            phase = 2;
        } else if (phase == 2 && group > 0 && group != (pid_t)state.status.latest.target_pid && foreground_sleep(group)) {
            foreground = group;
            if (getsid(group) != state.monitor_pid || send_signal(pty, SIGTSTP, typed)) {
                failure = 8; goto cleanup;
            }
            phase = 3;
        } else if (phase == 3 && group == (pid_t)state.status.latest.target_pid && strstr(output, "Stopped")) {
            nested_stop = true;
            if (state.monitor_reaped || (state.status.latest.flags & REMOZIO_MONITOR_STOPPED)) {
                failure = 9; goto cleanup;
            }
            if (send_input(pty, "fg\n")) { failure = 10; goto cleanup; }
            phase = 4;
        } else if (phase == 4 && group == foreground) {
            nested_resume = true;
            if (send_signal(pty, SIGINT, typed)) { failure = 11; goto cleanup; }
            phase = 5;
        } else if (phase == 5 && group == (pid_t)state.status.latest.target_pid) {
            interrupt = true;
            if (send_input(pty, "printf 'DONE_MARKER:%s\\n' \"$?\"; exit 7\n")) { failure = 12; goto cleanup; }
            phase = 6;
        } else if (phase == 6 && state.monitor_reaped && state.status_closed) { phase = 7; }
        usleep(1000);
    }
    if (phase != 7 || !nested_stop || !nested_resume || !interrupt || !state.target_exec_observed ||
        !state.target_exit_observed || !state.status.reaped || state.status.failed || shell_stop_records ||
        state.status.latest.detail != (7 << 8) || state.monitor_wait_status || !strstr(output, "DONE_MARKER:130")) {
        failure = 13;
    }
cleanup:
    if (monitor) {
        if (!state.monitor_reaped) {
            if (pty) (void)remozio_command_pty_signal(pty, SIGKILL);
            (void)remozio_command_monitor_cancel(monitor);
            uint64_t end = now_ms() + 10000;
            while (!state.monitor_reaped && !state.monitor_ownership_lost && now_ms() < end) {
                (void)progress(monitor, &state, pty, output, &used);
                usleep(1000);
            }
        }
        if (remozio_command_monitor_dispose(monitor)) failure = 14;
    }
    remozio_command_pty_close(pty);
    if (directory >= 0) close(directory);
    printf("{\"failure\":%d,\"nestedStopped\":%s,\"nestedResumed\":%s,\"foregroundInterrupted\":%s,"
           "\"shellExecObserved\":%s,\"shellExitObserved\":%s,\"monitorReaped\":%s,\"targetWait\":%u,\"shellStopRecords\":%u}",
           failure, nested_stop ? "true" : "false", nested_resume ? "true" : "false", interrupt ? "true" : "false",
           state.target_exec_observed ? "true" : "false", state.target_exit_observed ? "true" : "false",
           state.monitor_reaped ? "true" : "false", state.status.latest.detail, shell_stop_records);
    if (failure) fprintf(stderr, "private terminal transcript:\n%s\n", output);
    return failure ? 1 : 0;
}
