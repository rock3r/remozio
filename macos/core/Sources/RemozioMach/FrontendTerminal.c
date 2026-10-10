#include "include/RemozioFrontendTerminal.h"
#include "include/RemozioCommandStreamSource.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

struct remozio_frontend_terminal {
    int descriptor;
    pid_t process;
    struct termios saved;
    bool needs_restore;
};

static int foreground(remozio_frontend_terminal_t *terminal) {
    if (getpid() != terminal->process) return EPERM;
    pid_t session = tcgetsid(terminal->descriptor);
    if (session < 0) return errno;
    if (session != getsid(0)) return ENOTTY;
    pid_t group = tcgetpgrp(terminal->descriptor);
    if (group < 0) return errno;
    return group == getpgrp() ? 0 : EAGAIN;
}

static int signal_route(void) {
    struct sigaction action;
    sigset_t mask;
    if (sigaction(SIGTTOU, NULL, &action) < 0) return errno;
    int error = pthread_sigmask(SIG_SETMASK, NULL, &mask);
    if (error) return error;
    if (sigismember(&mask, SIGTTOU) || action.sa_handler == SIG_IGN ||
        action.sa_handler == SIG_DFL || (action.sa_flags & SA_RESTART)) return ENOTSUP;
    return 0;
}

int remozio_frontend_terminal_open(int source, remozio_frontend_terminal_t **output) {
    if (!output) return EINVAL;
    *output = NULL;
    int retained = -1;
    int source_error = remozio_command_stream_source_retain(source, &retained);
    if (source_error) return source_error;
    struct stat original, reopened;
    char path[PATH_MAX];
    int descriptor = -1, error = 0;
    if (fstat(retained, &original) < 0) error = errno;
    if (!error && !S_ISCHR(original.st_mode)) error = ENOTTY;
    if (!error) error = ttyname_r(retained, path, sizeof(path));
    if (!error) {
        descriptor = open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NOCTTY | O_NONBLOCK);
        if (descriptor < 0) error = errno;
    }
    if (!error && fstat(descriptor, &reopened) < 0) error = errno;
    if (!error && (!S_ISCHR(reopened.st_mode) || original.st_dev != reopened.st_dev ||
        original.st_ino != reopened.st_ino || original.st_rdev != reopened.st_rdev)) error = ESTALE;
    if (!error) {
        pid_t session = tcgetsid(descriptor);
        if (session < 0) error = errno;
        else if (session != getsid(0)) error = ENOTTY;
    }
    close(retained);
    if (error) { if (descriptor >= 0) close(descriptor); return error; }
    remozio_frontend_terminal_t *terminal = calloc(1, sizeof(*terminal));
    if (!terminal) { close(descriptor); return ENOMEM; }
    terminal->descriptor = descriptor;
    terminal->process = getpid();
    *output = terminal;
    return 0;
}

int remozio_frontend_terminal_activate(remozio_frontend_terminal_t *terminal) {
    if (!terminal) return EINVAL;
    if (getpid() != terminal->process) return EPERM;
    if (terminal->needs_restore) return EALREADY;
    int error = foreground(terminal);
    if (!error) error = signal_route();
    if (error) return error;
    if (tcgetattr(terminal->descriptor, &terminal->saved) < 0) return errno;
    struct termios raw = terminal->saved;
    cfmakeraw(&raw);
    /* An interrupted ioctl can have an uncertain outcome. Keep the saved settings. */
    terminal->needs_restore = true;
    if (tcsetattr(terminal->descriptor, TCSANOW, &raw) < 0) return errno;
    return 0;
}

int remozio_frontend_terminal_restore(remozio_frontend_terminal_t *terminal) {
    if (!terminal) return EINVAL;
    if (getpid() != terminal->process) return EPERM;
    if (!terminal->needs_restore) return 0;
    int error = foreground(terminal);
    if (!error) error = signal_route();
    if (error) return error;
    if (tcsetattr(terminal->descriptor, TCSANOW, &terminal->saved) < 0) return errno;
    terminal->needs_restore = false;
    return 0;
}

bool remozio_frontend_terminal_needs_restore(const remozio_frontend_terminal_t *terminal) {
    return terminal && terminal->needs_restore;
}

int remozio_frontend_terminal_close(remozio_frontend_terminal_t *terminal) {
    if (!terminal) return EINVAL;
    int error = remozio_frontend_terminal_restore(terminal);
    if (error) return error;
    remozio_frontend_terminal_abandon(terminal);
    return 0;
}

void remozio_frontend_terminal_abandon(remozio_frontend_terminal_t *terminal) {
    if (!terminal) return;
    close(terminal->descriptor);
    free(terminal);
}
