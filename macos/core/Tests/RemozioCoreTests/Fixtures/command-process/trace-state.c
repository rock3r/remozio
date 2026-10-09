/* Trace only disposable children created and exclusively owned by this fixture. */
#include "RemozioCommandProcess.h"
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <sys/proc.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
static unsigned metadata_fault, metadata_calls;
static int fixture_pidinfo(int pid, int flavor, uint64_t argument, void *buffer, int size);
#define proc_pidinfo fixture_pidinfo
#include "CommandProcess.c"
#undef proc_pidinfo
static int fixture_pidinfo(int pid, int flavor, uint64_t argument, void *buffer, int size) {
    ++metadata_calls;
    if (metadata_calls == 1) {
        if (metadata_fault == 7) { errno = EPERM; return 0; }
        return proc_pidinfo(pid, flavor, argument, buffer, size);
    }
    int result = proc_pidinfo(pid, flavor, argument, buffer, size);
    if (!metadata_fault || metadata_fault == 7 || result != sizeof(struct proc_bsdinfo)) return result;
    if (metadata_fault == 1) { errno = EPERM; return 0; }
    struct proc_bsdinfo *details = buffer;
    if (metadata_fault == 2) ++details->pbi_pid;
    if (metadata_fault == 3) details->pbi_status = SRUN;
    if (metadata_fault == 4) details->pbi_flags |= PROC_FLAG_INEXIT;
    if (metadata_fault == 6) details->pbi_start_tvusec = (details->pbi_start_tvusec + 1) % 1000000;
    return metadata_fault == 5 ? result - 4 : result;
}
static int await_state(remozio_command_process_t *process, remozio_command_process_observation_t *state, int phase) {
    for (unsigned turn = 0; turn < 8000; ++turn) {
        int error = remozio_command_process_poll(process, state);
        if (error) return error;
        if ((phase == 0 && state->prepared) || (phase == 1 && state->stopped) || (phase == 2 && state->reaped)) return 0;
        usleep(1000);
    }
    return ETIMEDOUT;
}
int main(int argc, char **argv) {
    if (argc != 4) return 1;
    if (strstr(argv[3], "birth_unavailable")) metadata_fault = 7;
    else if (strstr(argv[3], "birth_mismatch")) metadata_fault = 6;
    else if (strstr(argv[3], "unavailable")) metadata_fault = 1;
    else if (strstr(argv[3], "mismatch")) metadata_fault = 2;
    else if (strstr(argv[3], "not_stopped")) metadata_fault = 3;
    else if (strstr(argv[3], "in_exit")) metadata_fault = 4;
    else if (strstr(argv[3], "partial")) metadata_fault = 5;
    bool expect_known = strncmp(argv[3], "metadata_", 9) != 0;
    bool target_traced = strstr(argv[3], "traced") != NULL || (expect_known && strcmp(argv[3], "plain_stop") != 0);
    bool traced = expect_known && target_traced;
    int number = strstr(argv[3], "trap") != NULL ? SIGTRAP : SIGSTOP;
    FILE *file = fopen(argv[2], "rb"); if (!file) return 2;
    unsigned char frame[8192]; size_t count = fread(frame, 1, sizeof(frame), file); fclose(file);
    int input[2] = {-1, -1};
    if (pipe(input) || write(input[1], "unread", 6) != 6) return 12;
    int input_flags = fcntl(input[0], F_GETFL);
    int sink = open("/dev/null", O_RDWR | O_CLOEXEC), directory = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    remozio_command_process_t *process = NULL;
    remozio_command_process_observation_t state = {0};
    int failure = remozio_command_process_spawn(argv[1], frame, count, input[0], sink, sink, directory, &process);
    if (failure || !process) goto cleanup;
    if (await_state(process, &state, 0) || fcntl(input[0], F_GETFL) != input_flags) { failure = 3; goto cleanup; }
    if (remozio_command_process_release(process) || await_state(process, &state, 1)) { failure = 4; goto cleanup; }
    if (!state.exec_observed || state.reaped || state.stop_tracing_known != expect_known || state.stop_traced != traced || state.stop_signal != number) { failure = 5; goto cleanup; }
    uint64_t stopped_revision = state.job_control_revision;
    for (unsigned turn = 0; turn < 10; ++turn) {
        if (remozio_command_process_poll(process, &state) || !state.stopped || state.job_control_revision != stopped_revision ||
            state.stop_tracing_known != expect_known || state.stop_traced != traced) { failure = 11; goto cleanup; }
    }
    int raw_code = state.stop_code;
    bool snapshot_known = state.stop_tracing_known, snapshot_traced = state.stop_traced;
    if (target_traced) {
        if (ptrace(PT_CONTINUE, state.pid, (caddr_t)1, 0)) { failure = 6; goto cleanup; }
    } else if (remozio_command_process_signal(process, SIGCONT)) { failure = 7; goto cleanup; }
    if (await_state(process, &state, 2) || !WIFEXITED(state.wait_status) || WEXITSTATUS(state.wait_status) != 7 || state.stopped || state.stop_tracing_known || state.stop_traced) { failure = 8; goto cleanup; }
    char input_bytes[6];
    if (fcntl(input[0], F_GETFL) != input_flags || read(input[0], input_bytes, sizeof(input_bytes)) != sizeof(input_bytes) || memcmp(input_bytes, "unread", sizeof(input_bytes))) { failure = 13; goto cleanup; }
    if (remozio_command_process_signal(process, SIGCONT) != ESRCH) { failure = 9; goto cleanup; }
    printf("{\"case\":\"%s\",\"rawStopCode\":%d,\"targetSelfTraced\":%s,\"snapshotKnown\":%s,\"snapshotTraced\":%s,\"actualExit7\":true,\"clearedAfterReap\":true}\n", argv[3], raw_code, target_traced ? "true" : "false", snapshot_known ? "true" : "false", snapshot_traced ? "true" : "false");
cleanup:
    if (process) {
        (void)remozio_command_process_cancel(process);
        for (unsigned turn = 0; turn < 8000; ++turn) {
            (void)remozio_command_process_poll(process, &state);
            if (state.reaped || state.ownership_lost) break;
            usleep(1000);
        }
        if (remozio_command_process_dispose(process)) failure = 10;
    }
    if (sink >= 0) close(sink); if (directory >= 0) close(directory);
    for (unsigned index = 0; index < 2; ++index) if (input[index] >= 0) close(input[index]);
    if (failure) fprintf(stderr, "Native tracing probe failed=%d, pid=%d, stopped=%d, signal=%d, known=%d, traced=%d, reaped=%d\n",
        failure, state.pid, state.stopped, state.stop_signal, state.stop_tracing_known, state.stop_traced, state.reaped);
    return failure ? 1 : 0;
}
