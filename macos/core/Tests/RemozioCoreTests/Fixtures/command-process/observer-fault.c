/* Isolated fixture owns its native implementation and deliberately invalidates its own event descriptor. */
#include "CommandProcess.c"
#include <stdio.h>
#include <time.h>
#include <sys/stat.h>
static uint64_t fixture_time(void) {
    struct timespec value;
    clock_gettime(CLOCK_MONOTONIC, &value);
    return (uint64_t)value.tv_sec * 1000 + (uint64_t)value.tv_nsec / 1000000;
}
int main(int argc, char **argv) {
    if (argc != 3) return 1;
    FILE *file = fopen(argv[2], "rb");
    if (!file) return 2;
    if (fseek(file, 0, SEEK_END)) return 3;
    long size = ftell(file);
    if (size <= 0 || size > REMOZIO_CHILD_MAX_BYTES || fseek(file, 0, SEEK_SET)) return 3;
    void *frame = malloc((size_t)size);
    if (!frame || fread(frame, 1, (size_t)size, file) != (size_t)size) return 4;
    fclose(file);
    int stream = open("/dev/null", O_RDWR | O_CLOEXEC), directory = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    remozio_command_process_t *process = NULL;
    int failure = remozio_command_process_spawn(argv[1], frame, (size_t)size, stream, stream, stream, directory, &process);
    free(frame); close(stream); close(directory);
    if (failure || !process) return 5;
    remozio_command_process_observation_t observation = {0};
    uint64_t deadline = fixture_time() + 5000;
    while (!observation.prepared && fixture_time() < deadline) {
        failure = remozio_command_process_poll(process, &observation);
        if (failure || observation.reaped) break;
        usleep(1000);
    }
    if (failure || !observation.prepared || remozio_command_process_release(process)) failure = 6;
    uint64_t released = fixture_time();
    close_descriptor(&process->events);
    deadline = released + 3000;
    while (!failure && !observation.reaped && fixture_time() < deadline) {
        int error = remozio_command_process_poll(process, &observation);
        if (error != EBADF) { failure = 7; break; }
        usleep(1000);
    }
    if (!observation.reaped || observation.exec_observed || observation.exit_observed ||
        observation.wait_status != 0 || fixture_time() - released < 200) failure = 8;
    if (failure) {
        remozio_command_process_cancel(process);
        deadline = fixture_time() + 3000;
        while (!observation.reaped && !observation.ownership_lost && fixture_time() < deadline) {
            remozio_command_process_poll(process, &observation); usleep(1000);
        }
    }
    if (remozio_command_process_dispose(process)) failure = 9;
    return failure;
}
