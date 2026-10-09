#include "RemozioFrontendTerminal.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <util.h>

/* Only the check is replaced. The raced tcsetattr still reaches the real kernel. */
int fixture_fake_foreground;
static volatile sig_atomic_t saw_ttou;
static void receive_ttou(int number) { if (number == SIGTTOU) saw_ttou = 1; }
static int route_ttou(int flags) {
    struct sigaction action = {0};
    action.sa_handler = receive_ttou; action.sa_flags = flags;
    sigemptyset(&action.sa_mask);
    return sigaction(SIGTTOU, &action, NULL);
}
static long now(void) {
    struct timespec value; clock_gettime(CLOCK_MONOTONIC, &value);
    return value.tv_sec * 1000 + value.tv_nsec / 1000000;
}
static pid_t wait_owned(pid_t child, int *status, int flags) {
    long deadline = now() + 5000;
    while (now() < deadline) {
        pid_t result = waitpid(child, status, flags | WNOHANG);
        if (result > 0 || (result < 0 && errno != EINTR)) return result;
        usleep(1000);
    }
    return 0;
}
static bool same(const struct termios *a, const struct termios *b) {
    return a->c_iflag == b->c_iflag && a->c_oflag == b->c_oflag && a->c_cflag == b->c_cflag &&
        (a->c_lflag & ~PENDIN) == (b->c_lflag & ~PENDIN) && a->c_ispeed == b->c_ispeed &&
        a->c_ospeed == b->c_ospeed && !memcmp(a->c_cc, b->c_cc, sizeof(a->c_cc));
}
static int signal_guards(remozio_frontend_terminal_t *terminal) {
    sigset_t blocked; sigemptyset(&blocked); sigaddset(&blocked, SIGTTOU);
    if (signal(SIGTTOU, SIG_IGN) == SIG_ERR || remozio_frontend_terminal_activate(terminal) != ENOTSUP) return 20;
    if (signal(SIGTTOU, SIG_DFL) == SIG_ERR || remozio_frontend_terminal_activate(terminal) != ENOTSUP) return 21;
    if (route_ttou(SA_RESTART) || remozio_frontend_terminal_activate(terminal) != ENOTSUP) return 22;
    if (route_ttou(0) || sigprocmask(SIG_BLOCK, &blocked, NULL) ||
        remozio_frontend_terminal_activate(terminal) != ENOTSUP) return 23;
    if (sigprocmask(SIG_UNBLOCK, &blocked, NULL) || remozio_frontend_terminal_needs_restore(terminal)) return 24;
    return 0;
}
static int target(int slave, int start, const char *mode) {
    if (setpgid(0, 0) || route_ttou(0)) return 30;
    sigset_t unblocked; sigemptyset(&unblocked); sigaddset(&unblocked, SIGTTOU);
    if (sigprocmask(SIG_UNBLOCK, &unblocked, NULL)) return 31;
    char byte;
    if (read(start, &byte, 1) != 1) return 32;
    close(start);
    for (int i = 0; i < 3; ++i) if (dup2(slave, i) < 0) return 33;
    int original_flags = fcntl(slave, F_GETFL);
    struct termios original;
    if (tcgetattr(slave, &original)) return 34;
    remozio_frontend_terminal_t *terminal = NULL;
    if (remozio_frontend_terminal_open(0, &terminal) || !terminal) return 35;
    if (remozio_frontend_terminal_needs_restore(terminal) || remozio_frontend_terminal_restore(terminal)) return 36;
    for (int i = 0; i < 3; ++i) if (fcntl(i, F_GETFL) != original_flags) return 37;
    struct termios seen;
    if (tcgetattr(slave, &seen) || !same(&original, &seen)) return 38;
    if (!strcmp(mode, "signal-guards")) { int error = signal_guards(terminal); if (error) return error; }
    if (!strcmp(mode, "fork-owner")) {
        pid_t child = fork(); if (child < 0) return 39;
        if (!child) {
            bool rejected = remozio_frontend_terminal_activate(terminal) == EPERM &&
                remozio_frontend_terminal_restore(terminal) == EPERM && remozio_frontend_terminal_close(terminal) == EPERM;
            remozio_frontend_terminal_abandon(terminal); _exit(rejected ? 0 : 40);
        }
        int status; pid_t result = wait_owned(child, &status, 0);
        if (result != child) {
            if (!result) { kill(child, SIGKILL); do { result = waitpid(child, &status, 0); } while (result < 0 && errno == EINTR); }
            return 41;
        }
        if (!WIFEXITED(status) || WEXITSTATUS(status)) return 42;
    }
    if (!strcmp(mode, "source-reuse")) {
        int descriptors[2]; if (pipe(descriptors)) return 43;
        for (int i = 0; i < 3; ++i) if (dup2(descriptors[0], i) < 0) return 44;
        close(descriptors[0]); close(descriptors[1]);
    }
    if (remozio_frontend_terminal_activate(terminal) || !remozio_frontend_terminal_needs_restore(terminal) ||
        remozio_frontend_terminal_activate(terminal) != EALREADY) return 45;
    if (tcgetattr(slave, &seen) || (seen.c_lflag & (ICANON | ECHO | ISIG))) return 46;
    if (fcntl(slave, F_GETFL) != original_flags || remozio_frontend_terminal_restore(terminal) ||
        remozio_frontend_terminal_needs_restore(terminal)) return 47;
    if (raise(SIGSTOP)) return 48;

    if (!strcmp(mode, "background")) {
        if (remozio_frontend_terminal_activate(terminal) != EAGAIN ||
            remozio_frontend_terminal_needs_restore(terminal)) return 49;
    } else if (!strcmp(mode, "kernel-race")) {
        fixture_fake_foreground = 1;
        int error = remozio_frontend_terminal_activate(terminal);
        fixture_fake_foreground = 0;
        if (error != EINTR || !saw_ttou || !remozio_frontend_terminal_needs_restore(terminal)) return 50;
        if (remozio_frontend_terminal_close(terminal) != EAGAIN ||
            !remozio_frontend_terminal_needs_restore(terminal)) return 51;
    } else {
        if (remozio_frontend_terminal_activate(terminal) || remozio_frontend_terminal_restore(terminal)) return 52;
    }
    if (raise(SIGSTOP)) return 53;
    if (!strcmp(mode, "kernel-race")) {
        if (remozio_frontend_terminal_restore(terminal)) return 54;
    } else if (!strcmp(mode, "background")) {
        if (remozio_frontend_terminal_activate(terminal) || remozio_frontend_terminal_restore(terminal)) return 55;
    }
    struct pollfd readiness = {.fd = slave, .events = POLLIN};
    if (poll(&readiness, 1, 1000) != 1) return 56;
    char pending[10];
    if (read(slave, pending, sizeof(pending)) != sizeof(pending) || memcmp(pending, "untouched\n", sizeof(pending))) return 57;
    if (fcntl(slave, F_GETFL) != original_flags || remozio_frontend_terminal_close(terminal)) return 58;
    close(slave);
    return 0;
}
static int supervise(int slave, const char *mode) {
    /* The private fixture shell changes foreground groups. The product never does. */
    if (setsid() < 0 || ioctl(slave, TIOCSCTTY, 0) || signal(SIGTTOU, SIG_IGN) == SIG_ERR) return 60;
    int start[2]; if (pipe(start)) return 61;
    struct termios original, fresh, seen;
    if (tcgetattr(slave, &original)) return 62;
    int flags = fcntl(slave, F_GETFL);
    pid_t child = fork(); if (child < 0) return 63;
    if (!child) { close(start[1]); _exit(target(slave, start[0], mode)); }
    close(start[0]);
    bool owned = true; int status = 0, error = 0;
    if ((setpgid(child, child) < 0 && errno != EACCES) || tcsetpgrp(slave, child) || write(start[1], "S", 1) != 1) error = 64;
    close(start[1]);
    for (int phase = 0; !error && phase < 2; ++phase) {
        pid_t result = wait_owned(child, &status, WUNTRACED);
        if (result < 0) { owned = false; error = 65; break; }
        if (result != child) { error = 66; break; }
        if (!WIFSTOPPED(status)) { owned = false; error = WIFEXITED(status) ? WEXITSTATUS(status) : 67; if (!error) error = 68; break; }
        if (WSTOPSIG(status) != SIGSTOP) { error = 69; break; }
        if (tcgetattr(slave, &seen) || !same(phase ? &fresh : &original, &seen) || fcntl(slave, F_GETFL) != flags) { error = 70; break; }
        if (!phase) {
            fresh = original; fresh.c_cc[VERASE] = original.c_cc[VERASE] == 127 ? 8 : 127;
            if (tcsetattr(slave, TCSANOW, &fresh)) { error = 71; break; }
            if ((!strcmp(mode, "background") || !strcmp(mode, "kernel-race")) && tcsetpgrp(slave, getpgrp())) { error = 72; break; }
        } else if (tcsetpgrp(slave, child)) { error = 73; break; }
        if (kill(child, SIGCONT)) { error = 74; break; }
    }
    if (!error) {
        pid_t result = wait_owned(child, &status, 0);
        if (result == child) { owned = false; error = WIFEXITED(status) ? WEXITSTATUS(status) : 75; }
        else if (result < 0) { owned = false; error = 76; } else error = 77;
    }
    if (owned) {
        kill(child, SIGKILL);
        pid_t result; do { result = waitpid(child, &status, 0); } while (result < 0 && errno == EINTR);
    }
    if (error) fprintf(stderr, "terminal fixture %s failed: %d\n", mode, error);
    close(slave);
    return error;
}
int main(int argc, char **argv) {
    if (argc != 2 || getuid() == 0 || signal(SIGCHLD, SIG_DFL) == SIG_ERR) return 2;
    remozio_frontend_terminal_t *invalid = NULL;
    if (remozio_frontend_terminal_open(-1, &invalid) != EBADF || invalid) return 3;
    int descriptors[2]; if (pipe(descriptors)) return 4;
    if (remozio_frontend_terminal_open(descriptors[0], &invalid) != ENOTTY || invalid) return 5;
    close(descriptors[0]); close(descriptors[1]);
    int master, slave; if (openpty(&master, &slave, NULL, NULL, NULL)) return 6;
    if (write(master, "untouched\n", 10) != 10) return 7;
    pid_t child = fork(); if (child < 0) return 8;
    if (!child) { close(master); _exit(supervise(slave, argv[1])); }
    int flags = fcntl(master, F_GETFL);
    if (flags >= 0) fcntl(master, F_SETFL, flags | O_NONBLOCK);
    int status = 0, error = 0; pid_t result = 0;
    long deadline = now() + 5000;
    while (now() < deadline) {
        char ignored[256];
        while (read(master, ignored, sizeof(ignored)) > 0) {}
        result = waitpid(child, &status, WNOHANG);
        if (result > 0 || (result < 0 && errno != EINTR)) break;
        usleep(1000);
    }
    if (result == child) error = WIFEXITED(status) ? WEXITSTATUS(status) : 9;
    else if (result < 0) error = 10;
    else {
        error = 11; close(master); master = -1; close(slave); slave = -1; kill(child, SIGKILL);
        do { result = waitpid(child, &status, 0); } while (result < 0 && errno == EINTR);
    }
    if (master >= 0) close(master);
    if (slave >= 0) close(slave);
    printf("{\"failure\":%d,\"mode\":\"%s\",\"sessionOwnerReaped\":%s}\n", error, argv[1], result == child ? "true" : "false");
    return error;
}
