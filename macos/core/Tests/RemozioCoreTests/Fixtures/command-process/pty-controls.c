/* Finite unprivileged foreground job fixture. This program is never installed. */
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>
static volatile sig_atomic_t interrupted, resized;
static void resize(int signal) { (void)signal; resized = 1; }
static void interrupt(int signal) { (void)signal; interrupted = 1; }
static long milliseconds(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec*1000+t.tv_nsec/1000000; }
static int phase_byte(int fd, char byte) {
    ssize_t count; do { count = write(fd,&byte,1); } while (count < 0 && errno == EINTR);
    return count == 1;
}
static int await_phase(int fd, char expected, pid_t poke, long deadline) {
    while (milliseconds() < deadline) {
        if (poke > 0 && kill(poke,SIGWINCH)) return 0;
        struct pollfd input = {fd,POLLIN,0};
        int remaining = (int)(deadline-milliseconds());
        if (remaining <= 0) break;
        int available = poll(&input,1,remaining < 10 ? remaining : 10);
        if (available < 0) { if (errno == EINTR) continue; return 0; }
        if (!available) continue;
        if (input.revents & (POLLIN|POLLHUP)) {
            char byte; ssize_t count; do { count = read(fd,&byte,1); } while (count < 0 && errno == EINTR);
            return count == 1 && byte == expected;
        }
        return 0;
    }
    return 0;
}
static int stop_owned_child(pid_t child, int code) {
    (void)kill(child,SIGKILL);
    while (waitpid(child,NULL,0) < 0 && errno == EINTR) {}
    return code;
}
int main(int argc, char **argv) {
    if (argc != 2 || !isatty(0)) return 40;
    if (signal(SIGINT,SIG_IGN) == SIG_ERR || signal(SIGTTOU,SIG_IGN) == SIG_ERR) return 41;
    int inject = !strcmp(argv[1],"interrupt-ready");
    if (inject) {
        struct sigaction action;
        if (sigaction(SIGCHLD,NULL,&action) || action.sa_handler == SIG_IGN || (action.sa_flags & SA_NOCLDWAIT)) return 63;
    }
    int phase[2] = {-1,-1}; if (inject && pipe(phase)) return 64;
    int ready[2]; if (pipe(ready)) return 42;
    pid_t child = fork(); if (child < 0) return 43;
    if (!child) {
        close(ready[1]);
        if (setpgid(0,0)) _exit(44);
        struct sigaction action = {0}; action.sa_handler = interrupt; sigemptyset(&action.sa_mask);
        if (sigaction(SIGINT,&action,NULL)) _exit(45);
        action.sa_handler = resize; if (sigaction(SIGWINCH,&action,NULL)) _exit(58);
        if (inject) { close(phase[0]); if (!phase_byte(phase[1],'I')) _exit(65); }
        char byte; ssize_t received; int reported_interrupt = 0;
        do {
            received = read(ready[0],&byte,1);
            if (received < 0 && errno == EINTR && inject && !reported_interrupt) {
                if (!phase_byte(phase[1],'E')) _exit(66);
                reported_interrupt = 1;
                errno = EINTR;
            }
        } while (received < 0 && errno == EINTR);
        if (received != 1) _exit(46);
        if (inject) close(phase[1]);
        resized = 0;
        close(ready[0]);
        if (tcgetpgrp(0) != getpgrp() || getsid(0) == getpgrp()) _exit(47);
        if (write(1,"READY\n",6) != 6) _exit(48);
        long deadline = milliseconds()+5000;
        while (!resized && milliseconds()<deadline) usleep(1000);
        struct winsize size;
        if (!resized || ioctl(0,TIOCGWINSZ,&size) || size.ws_row!=53 || size.ws_col!=143) _exit(59);
        if (write(1,"RESIZED\n",8)!=8) _exit(60);
        while (!interrupted && milliseconds()<deadline) usleep(1000);
        if (!interrupted) _exit(49);
        if (write(1,"CHILD_INT\n",10) != 10) _exit(50);
        _exit(0);
    }
    close(ready[0]);
    if (setpgid(child,child) && errno != EACCES) return 51;
    if (tcsetpgrp(0,child)) return 52;
    if (inject) {
        close(phase[1]); long deadline = milliseconds()+1000;
        if (!await_phase(phase[0],'I',0,deadline) || !await_phase(phase[0],'E',child,deadline)) return stop_owned_child(child,67);
        close(phase[0]);
    }
    if (write(ready[1],"R",1) != 1) return 53;
    close(ready[1]); int status;
    if (waitpid(child,&status,0) != child) return 54;
    if (!strcmp(argv[1],"cancel") || !strcmp(argv[1],"cancel-gap")) {
        if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGKILL) return 55;
        if (!strcmp(argv[1],"cancel-gap") && write(1,"CHILD_KILLED\n",13) != 13) return 62;
        long deadline = milliseconds()+5000;
        while (milliseconds()<deadline) usleep(1000);
        return 61;
    }
    if ((strcmp(argv[1],"interrupt") && !inject) || status != 0) return 55;
    if (tcsetpgrp(0,getpgrp())) return 56;
    if (write(1,"LEADER_END\n",11) != 11) return 57;
    return 7;
}
