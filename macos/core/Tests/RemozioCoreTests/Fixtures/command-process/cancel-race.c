
/* Disposable fixture retains its native owner and injects a live permission failure. */
#include "RemozioCommandProcess.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>
static pid_t denied_pid = -1;
static bool deny_kill;
static int fixture_signal(pid_t pid, int number);
#define kill fixture_signal
#include "CommandProcess.c"
#undef kill
static int fixture_signal(pid_t pid, int number) {
    if (deny_kill && pid == -denied_pid && number == SIGKILL) { errno = EPERM; return -1; }
    return kill(pid, number);
}
static uint64_t fixture_time(void) {
    struct timespec value; clock_gettime(CLOCK_MONOTONIC, &value);
    return (uint64_t)value.tv_sec * 1000 + (uint64_t)value.tv_nsec / 1000000;
}
static int poll_until(remozio_command_process_t *process, remozio_command_process_observation_t *observation, bool exec) {
    uint64_t deadline = fixture_time() + 5000;
    do {
        int error = remozio_command_process_poll(process, observation);
        if (error) return error;
        if (exec ? observation->exec_observed : observation->prepared) return 0;
        usleep(1000);
    } while (fixture_time() < deadline);
    return ETIMEDOUT;
}
static int await_unreaped_exit(pid_t pid) {
    uint64_t deadline = fixture_time() + 5000;
    do {
        siginfo_t info = {0};
        if (waitid(P_PID, (id_t)pid, &info, WEXITED | WNOHANG | WNOWAIT)) return errno;
        if (info.si_pid == pid && info.si_code == CLD_EXITED && info.si_status == 70) return 0;
        usleep(1000);
    } while (fixture_time() < deadline);
    return ETIMEDOUT;
}
int main(int argc, char **argv) {
    if (argc != 4) return 1;
    bool live_failure = !strcmp(argv[3], "live_permission_failure");
    bool normal_prepared = !strcmp(argv[3], "normal_prepared");
    if (!live_failure && !normal_prepared && strcmp(argv[3], "prepared_exit")) return 1;
    FILE *file = fopen(argv[2], "rb"); if (!file) return 2;
    if (fseek(file, 0, SEEK_END)) return 3;
    long size = ftell(file);
    if (size <= 0 || size > REMOZIO_CHILD_MAX_BYTES || fseek(file, 0, SEEK_SET)) return 3;
    void *frame = malloc((size_t)size);
    if (!frame || fread(frame, 1, (size_t)size, file) != (size_t)size) return 4;
    fclose(file);
    int input[2] = {-1, -1}, sink = -1, directory = -1, failure = 0;
    remozio_command_process_t *process = NULL;
    if (pipe(input)) { free(frame); return 5; }
    sink = open("/dev/null", O_RDWR | O_CLOEXEC);
    directory = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int original_flags = fcntl(input[0], F_GETFL);
    if (sink < 0 || directory < 0 || write(input[1], "unread", 6) != 6) { failure = 6; goto cleanup; }
    failure = remozio_command_process_spawn(argv[1], frame, (size_t)size, input[0], sink, sink, directory, &process);
    if (failure || !process) { failure = 7; goto cleanup; }
    remozio_command_process_observation_t observation = {0};
    if (poll_until(process, &observation, false)) { failure = 8; goto cleanup; }
    if (live_failure) {
        if (remozio_command_process_release(process) || poll_until(process, &observation, true)) { failure = 9; goto cleanup; }
        denied_pid = observation.pid; deny_kill = true;
        int cancelled = remozio_command_process_cancel(process);
        int observed = remozio_command_process_poll(process, &observation);
        bool retained = !observed && !observation.reaped && !observation.ownership_lost && kill(observation.pid, 0) == 0;
        if (cancelled != EPERM || !retained) failure = 10;
        deny_kill = false;
        if (remozio_command_process_cancel(process)) failure = 11;
        uint64_t deadline = fixture_time() + 5000;
        while (!observation.reaped && fixture_time() < deadline) {
            remozio_command_process_poll(process, &observation); usleep(1000);
        }
        if (!observation.reaped || !observation.exec_observed || observation.wait_status != SIGKILL) failure = 12;
    } else if (normal_prepared) {
        if (remozio_command_process_cancel(process)) { failure = 18; goto cleanup; }
        uint64_t deadline = fixture_time() + 5000;
        while (!observation.reaped && fixture_time() < deadline) {
            remozio_command_process_poll(process, &observation); usleep(1000);
        }
        if (!observation.reaped || observation.exec_observed || observation.release_attempted ||
            (observation.wait_status != SIGKILL && observation.wait_status != 70 << 8)) failure = 19;
    } else {
        close_descriptor(&process->configuration); close_descriptor(&process->release); clear_frame(process);
        if (await_unreaped_exit(observation.pid)) { failure = 13; goto cleanup; }
        int cancelled = remozio_command_process_cancel(process);
        int observed = remozio_command_process_poll(process, &observation);
        if (cancelled || observed || !observation.reaped ||
            observation.exec_observed || observation.release_attempted || observation.wait_status != 70 << 8) failure = 14;
        if (remozio_command_process_signal(process, SIGTERM) != ESRCH || remozio_command_process_release(process) != ECANCELED) failure = 15;
    }
    int available = 0; char bytes[6] = {0};
    if (ioctl(input[0], FIONREAD, &available) || available != 6 || read(input[0], bytes, sizeof(bytes)) != 6 ||
        memcmp(bytes, "unread", 6) || fcntl(input[0], F_GETFL) != original_flags) failure = 16;
cleanup:
    deny_kill = false; free(frame);
    if (process) {
        remozio_command_process_cancel(process);
        remozio_command_process_observation_t state = {0}; uint64_t deadline = fixture_time() + 5000;
        while (remozio_command_process_dispose(process)) {
            remozio_command_process_poll(process, &state);
            if (fixture_time() >= deadline) { failure = 17; break; }
            usleep(1000);
        }
    }
    if (input[0] >= 0) close(input[0]); if (input[1] >= 0) close(input[1]);
    if (sink >= 0) close(sink); if (directory >= 0) close(directory);
    printf("{\"case\":\"%s\",\"verified\":%s,\"failureCode\":%d}\n", argv[3], failure ? "false" : "true", failure);
    return failure ? 1 : 0;
}
