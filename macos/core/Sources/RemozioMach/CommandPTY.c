#include "include/RemozioCommandPTY.h"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <util.h>

struct remozio_command_pty { int master, slave; bool eof; };
static void close_descriptor(int *descriptor) {
    if (*descriptor >= 0) { close(*descriptor); *descriptor = -1; }
}
static int private_descriptor(int descriptor, bool nonblocking) {
    int flags = fcntl(descriptor, F_GETFD);
    if (flags < 0 || fcntl(descriptor, F_SETFD, flags | FD_CLOEXEC) < 0) return errno;
    if (nonblocking) {
        flags = fcntl(descriptor, F_GETFL);
        if (flags < 0 || fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) < 0) return errno;
    }
    return 0;
}
int remozio_command_pty_create(const struct termios *attributes, const struct winsize *size,
    remozio_command_pty_t **output) {
    if (!output) return EINVAL;
    *output = NULL;
    remozio_command_pty_t *pty = calloc(1, sizeof(*pty));
    if (!pty) return ENOMEM;
    pty->master = pty->slave = -1;
    struct termios copied_attributes; struct winsize copied_size;
    if (attributes) copied_attributes = *attributes;
    if (size) copied_size = *size;
    int error = 0;
    if (openpty(&pty->master, &pty->slave, NULL, attributes ? &copied_attributes : NULL, size ? &copied_size : NULL)) error = errno;
    if (!error) error = private_descriptor(pty->master, true);
    if (!error) error = private_descriptor(pty->slave, false);
    if (error) { remozio_command_pty_close(pty); return error; }
    *output = pty; return 0;
}
int remozio_command_pty_borrow_slave(remozio_command_pty_t *pty, int *descriptor) {
    if (!pty || !descriptor) return EINVAL;
    *descriptor = -1;
    if (pty->slave < 0) return EBADF;
    *descriptor = pty->slave; return 0;
}
void remozio_command_pty_seal_slave(remozio_command_pty_t *pty) {
    if (pty) close_descriptor(&pty->slave);
}
int remozio_command_pty_read(remozio_command_pty_t *pty, void *bytes, size_t capacity, size_t *count, bool *eof) {
    if (!pty || !bytes || !count || !eof || !capacity || capacity > REMOZIO_PTY_MAX_CHUNK) return EINVAL;
    *count = 0; *eof = pty->eof;
    if (pty->eof) return 0;
    ssize_t result = read(pty->master, bytes, capacity);
    if (result > 0) { *count = (size_t)result; return 0; }
    if (result == 0 || (result < 0 && errno == EIO)) { pty->eof = true; *eof = true; return 0; }
    if (errno == EAGAIN || errno == EINTR) return 0;
    return errno;
}
int remozio_command_pty_write(remozio_command_pty_t *pty, const void *bytes, size_t count, size_t *written) {
    if (!pty || !written || (!bytes && count) || count > REMOZIO_PTY_MAX_CHUNK) return EINVAL;
    *written = 0;
    if (pty->eof) return EPIPE;
    if (!count) return 0;
    ssize_t result = write(pty->master, bytes, count);
    if (result >= 0) { *written = (size_t)result; return 0; }
    if (errno == EAGAIN || errno == EINTR) return 0;
    return errno;
}
int remozio_command_pty_resize(remozio_command_pty_t *pty, const struct winsize *size) {
    if (!pty || !size) return EINVAL;
    if (pty->eof) return EPIPE;
    return ioctl(pty->master, TIOCSWINSZ, size) < 0 ? errno : 0;
}
void remozio_command_pty_close(remozio_command_pty_t *pty) {
    if (!pty) return;
    close_descriptor(&pty->slave); close_descriptor(&pty->master); free(pty);
}

int remozio_command_pty_signal(remozio_command_pty_t *pty, int number) {
    if (!pty || number <= 0 || number >= NSIG) return EINVAL;
    if (pty->eof) return EPIPE;
    return ioctl(pty->master, TIOCSIG, number) < 0 ? errno : 0;
}
int remozio_command_pty_eof_sequence(remozio_command_pty_t *pty, unsigned char bytes[2], size_t *count) {
    if (!pty || !bytes || !count) return EINVAL;
    *count = 0;
    if (pty->eof) return EPIPE;
    struct termios current;
    if (tcgetattr(pty->master, &current) < 0) return errno;
    if (!(current.c_lflag & ICANON) || current.c_cc[VEOF] == _POSIX_VDISABLE) return 0;
    bytes[0] = bytes[1] = current.c_cc[VEOF]; *count = 2;
    return 0;
}
