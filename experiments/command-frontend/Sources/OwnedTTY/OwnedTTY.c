#include "OwnedTTY.h"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <util.h>

static int fixture_descriptor(const char *name) {
    const char *text = getenv(name); if (!text || !text[0]) return -1;
    char *end = NULL; long number = strtol(text, &end, 10);
    return end && !*end && number >= 3 && number <= 1024 ? (int)number : -1;
}
int remozio_fixture_adopt_tty(int *master, int *slave) {
    if (!master || !slave) return EINVAL;
    *master = *slave = -1;
    int input_master = fixture_descriptor("REMOZIO_FIXTURE_TTY_MASTER"), input_slave = fixture_descriptor("REMOZIO_FIXTURE_TTY_SLAVE");
    if (geteuid() == 0 || input_master < 0 || input_slave < 0 || input_master == input_slave ||
        getsid(0) != getppid() || getpgrp() != getpid() || !isatty(input_master) || !isatty(input_slave) ||
        tcgetsid(input_slave) != getsid(0) || tcgetpgrp(input_slave) != getpgrp()) return EPERM;
    *master = fcntl(input_master, F_DUPFD_CLOEXEC, 128);
    *slave = fcntl(input_slave, F_DUPFD_CLOEXEC, 128);
    int error = *master < 0 || *slave < 0 ? errno : 0;
    close(input_master); close(input_slave);
    if (error) { if (*master >= 0) close(*master); if (*slave >= 0) close(*slave); *master = *slave = -1; }
    return error;
}

int remozio_fixture_open_tty(int *master, int *slave) {
    if (!master || !slave) return EINVAL;
    *master = -1; *slave = -1;
    /* The runner creates this process's private session. Never acquire or modify an existing calling terminal. */
    if (geteuid() == 0 || getsid(0) != getpid()) return EPERM;
    int existing = open("/dev/tty", O_RDWR | O_CLOEXEC | O_NOCTTY);
    if (existing >= 0) { close(existing); return EBUSY; }
    if (errno != ENXIO && errno != ENODEV && errno != ENOTTY && errno != ENOENT) return errno;
    if (openpty(master, slave, NULL, NULL, NULL)) return errno;
    int error = 0;
    if (fcntl(*master, F_SETFL, O_NONBLOCK) || fcntl(*master, F_SETFD, FD_CLOEXEC) ||
        fcntl(*slave, F_SETFD, FD_CLOEXEC) || ioctl(*slave, TIOCSCTTY, 0) || tcsetpgrp(*slave, getpgrp())) error = errno;
    if (error) { close(*master); close(*slave); *master = -1; *slave = -1; }
    return error;
}
