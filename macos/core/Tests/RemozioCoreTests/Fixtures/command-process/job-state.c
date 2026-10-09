/* Disposable native observation regression. It grants no command approval. */
#include "RemozioCommandProcess.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
static uint64_t milliseconds(void) {
    struct timespec time; clock_gettime(CLOCK_MONOTONIC, &time);
    return (uint64_t)time.tv_sec * 1000 + (uint64_t)time.tv_nsec / 1000000;
}
static int await_state(remozio_command_process_t *process, remozio_command_process_observation_t *state, int expected, uint64_t revision) {
    uint64_t deadline = milliseconds() + 5000;
    do {
        int error = remozio_command_process_poll(process, state);
        if (error) return error;
        bool matched = expected == 0 ? state->prepared : expected == 1 ? state->exec_observed :
            expected == 2 ? state->stopped : expected == 3 ? !state->stopped && state->job_control_revision > revision : state->reaped;
        if (matched) return 0;
        usleep(1000);
    } while (milliseconds() < deadline);
    return ETIMEDOUT;
}
int main(int argc, char **argv) {
    if (argc != 4) return 1;
    bool resume = !strcmp(argv[3], "resume"), ownership_loss = !strcmp(argv[3], "ownership_loss");
    if (!resume && !ownership_loss && strcmp(argv[3], "cancel")) return 1;
    FILE *file = fopen(argv[2], "rb"); if (!file) return 2;
    unsigned char frame[8192]; size_t count = fread(frame, 1, sizeof(frame), file); fclose(file);
    int input[2] = {-1, -1}, sink = -1, directory = -1, failure = 0;
    remozio_command_process_t *process = NULL;
    if (pipe(input)) return 3;
    sink = open("/dev/null", O_RDWR | O_CLOEXEC); directory = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int flags = fcntl(input[0], F_GETFL);
    if (sink < 0 || directory < 0 || write(input[1], "unread", 6) != 6) { failure = 4; goto cleanup; }
    if (remozio_command_process_spawn(argv[1], frame, count, input[0], sink, sink, directory, &process) || !process) { failure = 5; goto cleanup; }
    remozio_command_process_observation_t state = {0};
    if (await_state(process, &state, 0, 0) || remozio_command_process_release(process) || await_state(process, &state, 1, 0)) { failure = 6; goto cleanup; }
    if (state.stopped || state.stop_signal || state.stop_code) { failure = 7; goto cleanup; }
    uint64_t baseline = state.job_control_revision;
    if (remozio_command_process_signal(process, SIGSTOP) || await_state(process, &state, 2, 0)) { failure = 8; goto cleanup; }
    if (state.stop_signal != SIGSTOP || state.stop_code != CLD_STOPPED || state.job_control_revision <= baseline || state.reaped || state.ownership_lost) { failure = 9; goto cleanup; }
    uint64_t revision = state.job_control_revision;
    for (int turn = 0; turn < 10; ++turn) {
        if (remozio_command_process_poll(process, &state) || !state.stopped || state.job_control_revision != revision || state.reaped) { failure = 10; goto cleanup; }
    }
    if (resume) {
        if (remozio_command_process_signal(process, SIGCONT) || await_state(process, &state, 3, revision)) { failure = 11; goto cleanup; }
        if (state.stop_signal || state.stop_code || state.reaped || state.ownership_lost) { failure = 12; goto cleanup; }
        revision = state.job_control_revision;
        if (remozio_command_process_signal(process, SIGSTOP) || await_state(process, &state, 2, 0) || state.job_control_revision <= revision) { failure = 13; goto cleanup; }
    }
    if (ownership_loss) {
        if (remozio_command_process_signal(process, SIGKILL)) { failure = 14; goto cleanup; }
        int status = 0; pid_t ended = 0; uint64_t deadline = milliseconds() + 5000;
        while (!(ended = waitpid(state.pid, &status, WNOHANG)) && milliseconds() < deadline) usleep(1000);
        if (ended != state.pid || !WIFSIGNALED(status) || WTERMSIG(status) != SIGKILL) { failure = 15; goto cleanup; }
        int error = remozio_command_process_poll(process, &state);
        if (error != ECHILD || !state.ownership_lost || state.reaped || state.stopped || state.stop_signal || state.stop_code ||
            remozio_command_process_signal(process, SIGCONT) != ESRCH) { failure = 16; goto cleanup; }
    } else {
        if (remozio_command_process_cancel(process) || await_state(process, &state, 4, 0)) { failure = 17; goto cleanup; }
        if (!state.exec_observed || state.stopped || state.stop_signal || state.stop_code || state.ownership_lost ||
            !WIFSIGNALED(state.wait_status) || WTERMSIG(state.wait_status) != SIGKILL) { failure = 18; goto cleanup; }
        if (remozio_command_process_signal(process, SIGCONT) != ESRCH) { failure = 19; goto cleanup; }
    }
    int available = 0; char bytes[6];
    if (ioctl(input[0], FIONREAD, &available) || available != 6 || read(input[0], bytes, sizeof(bytes)) != 6 ||
        memcmp(bytes, "unread", 6) || fcntl(input[0], F_GETFL) != flags) failure = 20;
cleanup:
    if (process) {
        remozio_command_process_cancel(process);
        remozio_command_process_observation_t state = {0}; uint64_t deadline = milliseconds() + 5000;
        while (remozio_command_process_dispose(process)) {
            remozio_command_process_poll(process, &state);
            if (milliseconds() >= deadline) { failure = 21; break; }
            usleep(1000);
        }
    }
    if (input[0] >= 0) close(input[0]); if (input[1] >= 0) close(input[1]);
    if (sink >= 0) close(sink); if (directory >= 0) close(directory);
    printf("{\"case\":\"%s\",\"verified\":%s,\"failureCode\":%d}\n", argv[3], failure ? "false" : "true", failure);
    return failure ? 1 : 0;
}
