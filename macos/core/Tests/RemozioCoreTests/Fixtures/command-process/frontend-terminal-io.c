#include "RemozioFrontendTerminal.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <util.h>
#define TOTAL (1024 * 1024)
static const unsigned char input[] = {0, 255, '\r', '\n', 3, 4, 26, 127, 128, 'x'};
static void route(int number) { (void)number; }
static long now(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
static unsigned char expected(size_t index) { return (unsigned char)((index * 73 + index / 251) & 255); }
static int worker(int slave, int report, int resume) {
    if (setsid() < 0 || ioctl(slave, TIOCSCTTY, 0)) return 10;
    struct sigaction action = {0}; action.sa_handler = route; sigemptyset(&action.sa_mask);
    if (sigaction(SIGTTIN, &action, NULL) || sigaction(SIGTTOU, &action, NULL)) return 11;
    sigset_t signals; sigemptyset(&signals); sigaddset(&signals, SIGTTIN); sigaddset(&signals, SIGTTOU);
    if (sigprocmask(SIG_UNBLOCK, &signals, NULL)) return 12;
    struct winsize expected_size = {.ws_row = 37, .ws_col = 119, .ws_xpixel = 320, .ws_ypixel = 240};
    if (ioctl(slave, TIOCSWINSZ, &expected_size)) return 33;
    struct termios original, seen;
    int flags = fcntl(slave, F_GETFL);
    if (tcgetattr(slave, &original)) return 13;
    remozio_frontend_terminal_t *terminal = NULL;
    if (remozio_frontend_terminal_open(slave, &terminal) || remozio_frontend_terminal_activate(terminal)) return 14;
    struct winsize dimensions;
    if (remozio_frontend_terminal_dimensions(terminal, &dimensions) ||
        dimensions.ws_row != expected_size.ws_row || dimensions.ws_col != expected_size.ws_col ||
        dimensions.ws_xpixel != expected_size.ws_xpixel || dimensions.ws_ypixel != expected_size.ws_ypixel) return 15;
    unsigned char received[sizeof(input)];
    size_t initial_count = 7;
    if (remozio_frontend_terminal_read(terminal, received, sizeof(received), &initial_count) != EAGAIN || initial_count) return 17;
    if (write(report, "R", 1) != 1) return 18;
    size_t used = 0; long end = now() + 5000;
    while (used < sizeof(received) && now() < end) {
        size_t count = 0;
        int error = remozio_frontend_terminal_read(terminal, received + used, sizeof(received) - used, &count);
        if (!error && count) used += count;
        else if (error == EAGAIN || error == EINTR) usleep(1000);
        else return 19;
    }
    if (used != sizeof(input) || memcmp(received, input, used)) return 20;
    // Output has its own fixture budget, independent of input and CI scheduling.
    end = now() + 30000;
    unsigned char chunk[4096]; size_t sent = 0; bool blocked = false;
    while (sent < TOTAL && now() < end) {
        size_t length = TOTAL - sent; if (length > sizeof(chunk)) length = sizeof(chunk);
        for (size_t i = 0; i < length; ++i) chunk[i] = expected(sent + i);
        size_t count = 0;
        int error = remozio_frontend_terminal_write(terminal, chunk, length, &count);
        if (!error && count) sent += count;
        else if (error == EAGAIN) {
            if (!blocked) {
                if (write(report, "B", 1) != 1) return 21;
                char command;
                if (read(resume, &command, 1) != 1) return 22;
                blocked = true;
            }
            struct pollfd ready = {.fd = slave, .events = POLLOUT};
            int waited = poll(&ready, 1, 100);
            if (waited < 0 && errno != EINTR) return 36;
        } else if (error == EINTR) continue;
        else return 23;
    }
    if (sent != TOTAL) {
        fprintf(stderr, "Terminal fixture output deadline: sent=%zu expected=%d blocked=%d\n", sent, TOTAL, blocked);
        return 24;
    }
    if (!blocked) return 35;
    if (fcntl(slave, F_GETFL) != flags) return 34;
    if (remozio_frontend_terminal_restore(terminal) || tcgetattr(slave, &seen)) return 25;
    if (seen.c_iflag != original.c_iflag || seen.c_oflag != original.c_oflag ||
        seen.c_cflag != original.c_cflag || (seen.c_lflag & ~PENDIN) != (original.c_lflag & ~PENDIN) ||
        memcmp(seen.c_cc, original.c_cc, sizeof(seen.c_cc))) return 26;
    size_t inactive_count = 7;
    if (remozio_frontend_terminal_read(terminal, received, sizeof(received), &inactive_count) != ENOTCONN || inactive_count) return 27;
    if (remozio_frontend_terminal_write(terminal, input, sizeof(input), &inactive_count) != ENOTCONN || inactive_count) return 31;
    if (remozio_frontend_terminal_close(terminal)) return 32;
 close(slave); close(report); close(resume); return 0;
}
int main(void) {
    if (getuid() == 0 || signal(SIGCHLD, SIG_DFL) == SIG_ERR) return 2;
    int master, slave, report[2], resume[2];
    if (openpty(&master, &slave, NULL, NULL, NULL) || pipe(report) || pipe(resume)) return 3;
    pid_t child = fork(); if (child < 0) return 4;
    if (!child) { close(master); close(report[0]); close(resume[1]); _exit(worker(slave, report[1], resume[0])); }
    close(report[1]); close(resume[0]); close(slave);
    if (fcntl(master, F_SETFL, fcntl(master, F_GETFL) | O_NONBLOCK) ||
        fcntl(report[0], F_SETFL, fcntl(report[0], F_GETFL) | O_NONBLOCK)) {
        close(master); kill(child, SIGKILL);
        int cleanup_status; pid_t reaped;
        do { reaped = waitpid(child, &cleanup_status, 0); } while (reaped < 0 && errno == EINTR);
        close(report[0]); close(resume[1]); return 5;
    }
    bool ready = false, blocked = false, mismatch = false; size_t received = 0;
    long end = now() + 45000; int status = 0, error = 0; pid_t result = 0;
    while (now() < end) {
        char marker;
        ssize_t report_count = read(report[0], &marker, 1);
        if (report_count == 1) {
            if (marker == 'R' && !ready) {
                ready = true;
                if (write(master, input, sizeof(input)) != sizeof(input)) { error = 6; break; }
            } else if (marker == 'B' && ready && !blocked) {
                blocked = true;
                if (write(resume[1], "G", 1) != 1) { error = 7; break; }
            } else { error = 8; break; }
        }
        if (blocked) {
            unsigned char bytes[8192]; ssize_t count;
            while ((count = read(master, bytes, sizeof(bytes))) > 0) {
                for (ssize_t i = 0; i < count; ++i) {
                    if (received >= TOTAL || bytes[i] != expected(received)) mismatch = true;
                    received++;
                }
            }
        }
        result = waitpid(child, &status, WNOHANG);
        if (result == child) {
            if (!WIFEXITED(status) || WEXITSTATUS(status)) { error = WIFEXITED(status) ? WEXITSTATUS(status) : 9; break; }
            if (received == TOTAL) break;
            // The child is reaped. Drain remaining queued output without waiting for it again.
            while (received < TOTAL && now() < end) {
                unsigned char byte; ssize_t count = read(master, &byte, 1);
                if (count == 1) { if (byte != expected(received)) mismatch = true; received++; }
                else if (count < 0 && errno == EAGAIN) usleep(1000);
                else break;
            }
            break;
        }
        if (result < 0 && errno != EINTR) { error = 28; break; }
        struct pollfd ready[2] = {
            {.fd = report[0], .events = POLLIN},
            {.fd = blocked ? master : -1, .events = POLLIN},
        };
        if (poll(ready, 2, 100) < 0 && errno != EINTR) { error = 37; break; }
    }
    if (result != child) {
        if (!error) error = 29;
        close(master); master = -1;
        kill(child, SIGKILL);
        do { result = waitpid(child, &status, 0); } while (result < 0 && errno == EINTR);
    }
    if (!error && (!blocked || mismatch || received != TOTAL)) error = 30;
    if (master >= 0) close(master);
    close(report[0]); close(resume[1]);
    printf("{\"failure\":%d,\"idleReadWouldBlock\":%s,\"binaryInputPreserved\":%s,\"outputBackpressureObserved\":%s,\"exactOutputBytes\":%zu,\"outputMatched\":%s,\"sessionOwnerReaped\":%s}\n",
        error, ready ? "true" : "false", blocked ? "true" : "false", blocked ? "true" : "false", received,
        !mismatch && received == TOTAL ? "true" : "false", result == child ? "true" : "false");
    return error;
}
