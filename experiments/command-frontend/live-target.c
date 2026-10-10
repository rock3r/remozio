/* Owned target for the joined frontend/authority job experiment. Never reads the user's terminal. */
#ifndef REMOZIO_OWNED_LIVE_FIXTURE
#error "This target requires an explicit disposable fixture build."
#endif
#include <signal.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>
static unsigned long long milliseconds(void) {
    struct timespec value; clock_gettime(CLOCK_MONOTONIC, &value);
    return (unsigned long long)value.tv_sec * 1000 + value.tv_nsec / 1000000;
}
int main(int argc, char **argv) {
    if (argc != 3 || (strcmp(argv[1], "job") && strcmp(argv[1], "stale")) || argv[2][0] != '/' || geteuid() == 0 ||
        getpgrp() != getpid() || getsid(0) != getsid(getppid()) || getsid(0) == getpid() ||
        !isatty(STDIN_FILENO) || tcgetpgrp(STDIN_FILENO) != getpgrp()) return 64;
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
