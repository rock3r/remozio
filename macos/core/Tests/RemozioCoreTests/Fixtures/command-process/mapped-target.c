/* Disposable target. The test launcher mocks credential operations, not terminal or exec operations. */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <time.h>
#include <termios.h>
#include <unistd.h>
static volatile sig_atomic_t resized, foreground_signal, monitor_signal;
static void receive(int number) {
    if (number == SIGWINCH) resized = 1;
    if (number == SIGUSR1) foreground_signal = 1;
    if (number == SIGUSR2) monitor_signal = 1;
}
static uint64_t milliseconds(void) {
    struct timespec value; clock_gettime(CLOCK_MONOTONIC, &value);
    return (uint64_t)value.tv_sec * 1000 + (uint64_t)value.tv_nsec / 1000000;
}
static int exact(int fd, const void *bytes, size_t count) {
    size_t used = 0;
    while (used < count) {
        ssize_t n = write(fd, (const char *)bytes + used, count - used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return 1;
        used += (size_t)n;
    }
    return 0;
}
int main(int argc, char **argv) {
    if (argc != 5 || (unsigned char)argv[0][0] != 0xff || argv[0][1] || argv[1][0] ||
        (unsigned char)argv[2][0] != 0xfe || argv[2][1]) return 91;
    unsigned mask = (unsigned)atoi(argv[3]);
    bool distinct = !strcmp(argv[4], "distinct");
    char *raw = getenv("RAW"), *empty = getenv("EMPTY"), *cwd = getenv("CWD");
    if (!raw || (unsigned char)raw[0] != 0xfd || raw[1] || !empty || *empty || !cwd || getenv("PATH")) return 92;
    for (int fd = 3; fd < 256; ++fd) if (fcntl(fd, F_GETFD) >= 0) return 93;
    if (getpgrp() != getpid()) return 94;
    if (!strcmp(argv[4], "standalone")) {
        if (getsid(0) != getpid()) return 94;
    } else if (getsid(0) == getpid() || getsid(0) != getsid(getppid())) return 94;
    for (unsigned fd = 0; fd < 3; ++fd)
        if (!!isatty((int)fd) != (!!(mask & (1U << fd)) || (distinct && fd == 1))) return 95;
    int terminal = open("/dev/tty", O_RDWR | O_CLOEXEC);
    if (terminal < 0 || tcgetsid(terminal) != getsid(0) || tcgetpgrp(terminal) != getpgrp()) return 96;
    struct stat held, named;
    if (stat(".", &held) || stat(cwd, &named) || held.st_ino != named.st_ino || held.st_dev != named.st_dev) return 97;
    struct sigaction action = {0}; action.sa_handler = receive; sigemptyset(&action.sa_mask);
    if (sigaction(SIGWINCH, &action, NULL) || sigaction(SIGUSR1, &action, NULL) || sigaction(SIGUSR2, &action, NULL)) return 98;
    unsigned char input[4]; size_t used = 0; uint64_t deadline = milliseconds() + 8000;
    while (used < sizeof(input) && milliseconds() < deadline) {
        struct pollfd item = {.fd = 0, .events = POLLIN};
        int ready = poll(&item, 1, 20);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) return 99;
        if (!ready) continue;
        ssize_t n = read(0, input + used, sizeof(input) - used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return 100;
        used += (size_t)n;
    }
    const unsigned char expected[] = {'I', 0, 0xfd, '\n'};
    const unsigned char out[] = {'O', 'U', 'T', 0, 0xff, '\n'};
    const unsigned char err[] = {'E', 'R', 'R', 0, 0xfe, '\n'};
    if (used != sizeof(input) || memcmp(input, expected, sizeof(input))) return 101;
    if (exact(1, out, sizeof(out)) || exact(2, err, sizeof(err)) || exact(terminal, "CONTROL\n", 8)) return 102;
    if (!strcmp(argv[4], "cancel")) for (;;) pause();
    if (!strcmp(argv[4], "stop") && raise(SIGSTOP)) return 103;
    deadline = milliseconds() + 8000;
    while ((!resized || !foreground_signal || !monitor_signal) && milliseconds() < deadline) usleep(1000);
    struct winsize size;
    if (!resized || !foreground_signal || !monitor_signal || ioctl(terminal, TIOCGWINSZ, &size) ||
        size.ws_row != 53 || size.ws_col != 143) return 104;
    close(terminal);
    return 7;
}
