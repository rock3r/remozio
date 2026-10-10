/* Disposable standalone owner. Credential changes are mocked by the test's product child wrapper. */
#include "RemozioCommandProcess.h"
#include "RemozioCommandPTY.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
typedef struct { unsigned char bytes[64]; size_t count; bool eof; } buffer_t;
static uint64_t milliseconds(void) {
    struct timespec value; clock_gettime(CLOCK_MONOTONIC, &value);
    return (uint64_t)value.tv_sec * 1000 + (uint64_t)value.tv_nsec / 1000000;
}
static int drain_terminal(remozio_command_pty_t *pty, buffer_t *buffer) {
    if (buffer->eof) return 0;
    size_t count = 0; bool eof = false;
    int error = remozio_command_pty_read(pty, buffer->bytes + buffer->count, sizeof(buffer->bytes) - buffer->count, &count, &eof);
    buffer->count += count; buffer->eof = eof;
    return error;
}
static int drain_pipe(int fd, buffer_t *buffer) {
    if (buffer->eof) return 0;
    struct pollfd item = {.fd = fd, .events = POLLIN};
    int ready = poll(&item, 1, 0);
    if (ready < 0) return errno;
    if (!ready) return 0;
    ssize_t count = read(fd, buffer->bytes + buffer->count, sizeof(buffer->bytes) - buffer->count);
    if (count < 0) return errno == EINTR ? 0 : errno;
    buffer->count += (size_t)count; buffer->eof = count == 0;
    return 0;
}
static bool matches(const buffer_t *buffer, const void *bytes, size_t count) {
    return buffer->count == count && !memcmp(buffer->bytes, bytes, count);
}
int main(int argc, char **argv) {
    if (argc != 6) return 1;
    unsigned mask = (unsigned)atoi(argv[4]);
    FILE *file = fopen(argv[3], "rb"); if (!file) return 2;
    unsigned char frame[8192]; size_t count = fread(frame, 1, sizeof(frame), file); fclose(file);
    int input[2], output[2], errors[2]; if (pipe(input) || pipe(output) || pipe(errors)) return 3;
    int directory = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC), slave = -1, inspection = -1;
    remozio_command_pty_t *pty = NULL;
    remozio_command_process_t *child = NULL; remozio_command_process_observation_t state = {0};
    buffer_t terminal_bytes = {0}, out = {0}, err = {0};
    int failure = 0, native_error = 0;
    if (directory < 0 || remozio_command_pty_create(NULL, NULL, &pty) || remozio_command_pty_borrow_slave(pty, &slave)) { failure = 4; goto cleanup; }
    struct termios attributes;
    if (tcgetattr(slave, &attributes)) { failure = 5; goto cleanup; }
    cfmakeraw(&attributes); if (tcsetattr(slave, TCSANOW, &attributes)) { failure = 5; goto cleanup; }
    int streams[3] = {mask & 1 ? slave : input[0], mask & 2 ? slave : output[1], mask & 4 ? slave : errors[1]};
    int initial_flags[3];
    for (int index = 0; index < 3; ++index) initial_flags[index] = fcntl(streams[index], F_GETFL);
    inspection = fcntl(streams[0], F_DUPFD_CLOEXEC, 32);
    const unsigned char input_bytes[] = {'I', 0, 0xfd, '\n'};
    if (mask & 1) {
        size_t written = 0;
        if (remozio_command_pty_write(pty, input_bytes, sizeof(input_bytes), &written) || written != sizeof(input_bytes)) { failure = 6; goto cleanup; }
    } else if (write(input[1], input_bytes, sizeof(input_bytes)) != sizeof(input_bytes)) { failure = 6; goto cleanup; }
    close(input[1]); input[1] = -1;
    native_error = remozio_command_process_spawn_with_terminal(argv[2], frame, count, streams[0], streams[1], streams[2], directory, slave, &child);
    if (native_error || !child) { failure = 7; goto cleanup; }
    for (int index = 0; index < 3; ++index)
        if (fcntl(streams[index], F_GETFL) != initial_flags[index]) { failure = 8; goto cleanup; }
    remozio_command_pty_seal_slave(pty);
    close(output[1]); output[1] = -1; close(errors[1]); errors[1] = -1;
    uint64_t deadline = milliseconds() + 8000;
    while (!state.prepared && milliseconds() < deadline) {
        native_error = remozio_command_process_poll(child, &state);
        if (native_error) { failure = 9; goto cleanup; }
        usleep(1000);
    }
    if (!state.prepared || state.exec_observed || state.release_attempted) { failure = 10; goto cleanup; }
    int available = 0;
    if (inspection < 0 || ioctl(inspection, FIONREAD, &available) || available != sizeof(input_bytes)) { failure = 11; goto cleanup; }
    close(inspection); inspection = -1;
    if (drain_terminal(pty, &terminal_bytes) || terminal_bytes.eof || terminal_bytes.count) { failure = 12; goto cleanup; }
    if (remozio_command_process_release(child) || remozio_command_process_release(child) != EALREADY) { failure = 13; goto cleanup; }
    bool sent = false;
    deadline = milliseconds() + 10000;
    while (!state.reaped && milliseconds() < deadline) {
        native_error = remozio_command_process_poll(child, &state);
        if (native_error || drain_terminal(pty, &terminal_bytes) || drain_pipe(output[0], &out) || drain_pipe(errors[0], &err)) { failure = 14; goto cleanup; }
        if (!sent && terminal_bytes.count >= 8 && !memcmp(terminal_bytes.bytes + terminal_bytes.count - 8, "CONTROL\n", 8)) {
            struct winsize size = {.ws_row = 53, .ws_col = 143};
            if (terminal_bytes.eof || remozio_command_pty_resize(pty, &size) || remozio_command_pty_signal(pty, SIGUSR1) || remozio_command_process_signal(child, SIGUSR2)) { failure = 15; goto cleanup; }
            sent = true;
        }
        usleep(1000);
    }
    if (!sent || !state.reaped || !state.exec_observed || !state.exit_observed || state.ownership_lost || !WIFEXITED(state.wait_status) || WEXITSTATUS(state.wait_status) != 7) { failure = 16; goto cleanup; }
    if (remozio_command_process_dispose(child)) { failure = 17; goto cleanup; }
    child = NULL;
    deadline = milliseconds() + 1000;
    while ((!terminal_bytes.eof || !out.eof || !err.eof) && milliseconds() < deadline) {
        if (drain_terminal(pty, &terminal_bytes) || drain_pipe(output[0], &out) || drain_pipe(errors[0], &err)) { failure = 18; goto cleanup; }
        usleep(1000);
    }
    const unsigned char expected_out[] = {'O', 'U', 'T', 0, 0xff, '\n'}, expected_err[] = {'E', 'R', 'R', 0, 0xfe, '\n'};
    unsigned char expected_terminal[20]; size_t expected_count = 0;
    if (mask & 2) { memcpy(expected_terminal + expected_count, expected_out, sizeof(expected_out)); expected_count += sizeof(expected_out); }
    if (mask & 4) { memcpy(expected_terminal + expected_count, expected_err, sizeof(expected_err)); expected_count += sizeof(expected_err); }
    memcpy(expected_terminal + expected_count, "CONTROL\n", 8); expected_count += 8;
    if (!terminal_bytes.eof || !out.eof || !err.eof || !matches(&terminal_bytes, expected_terminal, expected_count) ||
        !matches(&out, expected_out, mask & 2 ? 0 : sizeof(expected_out)) || !matches(&err, expected_err, mask & 4 ? 0 : sizeof(expected_err))) { failure = 19; goto cleanup; }
cleanup:
    if (child) {
        (void)remozio_command_process_cancel(child); uint64_t cleanup_deadline = milliseconds() + 10000;
        while (!state.reaped && !state.ownership_lost && milliseconds() < cleanup_deadline) {
            (void)remozio_command_process_poll(child, &state); (void)drain_terminal(pty, &terminal_bytes); usleep(1000);
        }
        if (remozio_command_process_dispose(child)) failure = 20;
    }
    if (inspection >= 0) close(inspection);
    remozio_command_pty_close(pty);
    close(input[0]); if (input[1] >= 0) close(input[1]); close(output[0]); close(errors[0]);
    if (output[1] >= 0) close(output[1]); if (errors[1] >= 0) close(errors[1]); if (directory >= 0) close(directory);
    printf("{\"mask\":%u,\"mode\":\"standalone\",\"failure\":%d,\"nativeError\":%d,\"waitStatus\":%d,\"independentExec\":%s,\"independentExit\":%s,\"childActuallyReaped\":%s,\"terminalEOF\":%s}\n",
        mask, failure, native_error, state.wait_status, state.exec_observed ? "true" : "false", state.exit_observed ? "true" : "false",
        state.reaped ? "true" : "false", terminal_bytes.eof ? "true" : "false");
    return failure ? 1 : 0;
}
