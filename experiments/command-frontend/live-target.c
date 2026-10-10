/* Owned target for the joined frontend/authority job experiment. Never reads the user's terminal. */
#ifndef REMOZIO_OWNED_LIVE_FIXTURE
#error "This target requires an explicit disposable fixture build."
#endif
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>
static unsigned long long milliseconds(void) {
    struct timespec value; clock_gettime(CLOCK_MONOTONIC, &value);
    return (unsigned long long)value.tv_sec * 1000 + value.tv_nsec / 1000000;
}
static volatile sig_atomic_t continued;
static void note_continuation(int number) { (void)number; continued = 1; }
static int nested(void) {
    struct sigaction action = {0}; action.sa_handler = note_continuation; sigemptyset(&action.sa_mask);
    if (sigaction(SIGCONT, &action, NULL) || write(STDOUT_FILENO, "NESTED_RUNNING\n", 15) != 15) return 71;
    unsigned long long deadline = milliseconds() + 30000;
    while (!continued && milliseconds() < deadline) {
        struct pollfd input = {.fd = STDIN_FILENO, .events = POLLIN};
        int result = poll(&input, 1, 100);
        if (result > 0 || (result < 0 && errno != EINTR)) return 72;
    }
    if (!continued || write(STDOUT_FILENO, "NESTED_RESUMED\n", 15) != 15) return 73;
    while (milliseconds() < deadline) {
        struct pollfd input = {.fd = STDIN_FILENO, .events = POLLIN};
        int result = poll(&input, 1, 100);
        if (result < 0 && errno != EINTR) return 74;
        if (result > 0) {
            char bytes[16] = {0};
            ssize_t count = read(STDIN_FILENO, bytes, sizeof(bytes));
            if (count != 8 || memcmp(bytes, "RELEASE\n", 8)) return 75;
            return write(STDOUT_FILENO, "NESTED_DONE\n", 12) == 12 ? 0 : 76;
        }
    }
    return 77;
}
int main(int argc, char **argv) {
    if (argc != 3 || (strcmp(argv[1], "job") && strcmp(argv[1], "stale") && strcmp(argv[1], "nested")) || argv[2][0] != '/' || geteuid() == 0 ||
        getpgrp() != getpid() || getsid(0) != getsid(getppid()) || getsid(0) == getpid() ||
        !isatty(STDIN_FILENO) || tcgetpgrp(STDIN_FILENO) != getpgrp()) return 64;
    if (!strcmp(argv[1], "nested")) return nested();
    if (raise(SIGTSTP)) return 65;
    int marker = open(argv[2], O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (marker < 0 || write(marker, "TARGET_RESUMED", 14) != 14 || close(marker)) return 69;
    if (write(STDOUT_FILENO, "TARGET_RESUMED\n", 15) != 15) return 66;
    if (!strcmp(argv[1], "stale")) {
        char bytes[8] = {0};
        ssize_t count = read(STDIN_FILENO, bytes, sizeof(bytes));
        return count == 7 && !memcmp(bytes, "FINISH\n", 7) ? 13 : 70;
    }
    unsigned long long deadline = milliseconds() + 10000;
    while (milliseconds() < deadline) {
        struct winsize size;
        if (ioctl(STDIN_FILENO, TIOCGWINSZ, &size)) return 67;
        if (size.ws_row == 79 && size.ws_col == 121) return 13;
        usleep(1000);
    }
    return 68;
}
