/* Finite unprivileged foreground job fixture. This program is never installed. */
#include <errno.h>
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
int main(int argc, char **argv) {
    if (argc != 2 || !isatty(0)) return 40;
    if (signal(SIGINT,SIG_IGN) == SIG_ERR || signal(SIGTTOU,SIG_IGN) == SIG_ERR) return 41;
    int ready[2]; if (pipe(ready)) return 42;
    pid_t child = fork(); if (child < 0) return 43;
    if (!child) {
        close(ready[1]);
        if (setpgid(0,0)) _exit(44);
        struct sigaction action = {0}; action.sa_handler = interrupt; sigemptyset(&action.sa_mask);
        if (sigaction(SIGINT,&action,NULL)) _exit(45);
        action.sa_handler = resize; if (sigaction(SIGWINCH,&action,NULL)) _exit(58);
        char byte; if (read(ready[0],&byte,1) != 1) _exit(46);
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
    if (write(ready[1],"R",1) != 1) return 53;
    close(ready[1]); int status;
    if (waitpid(child,&status,0) != child) return 54;
    if (strcmp(argv[1],"interrupt") || status != 0) return 55;
    if (tcsetpgrp(0,getpgrp())) return 56;
    if (write(1,"LEADER_END\n",11) != 11) return 57;
    return 7;
}
