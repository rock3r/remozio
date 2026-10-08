#ifndef REMOZIO_COMMAND_PTY_H
#define REMOZIO_COMMAND_PTY_H
#include <stdbool.h>
#include <stddef.h>
#include <sys/ioctl.h>
#include <termios.h>

#define REMOZIO_PTY_MAX_CHUNK 65536
typedef struct remozio_command_pty remozio_command_pty_t;
/* Creates only a private terminal. No caller, child, execution or control permission is established. */
int remozio_command_pty_create(const struct termios * _Nullable attributes, const struct winsize * _Nullable size,
    remozio_command_pty_t * _Nullable * _Nonnull output);
/* Borrow the slave only for spawning the bound child; never close or retain this descriptor. */
int remozio_command_pty_borrow_slave(remozio_command_pty_t * _Nonnull pty, int * _Nonnull descriptor);
/* Close the owner's slave after spawning. The child owns its separate copies. */
void remozio_command_pty_seal_slave(remozio_command_pty_t * _Nonnull pty);
/* Nonblocking bounded reads. EOF refers only to the stream and never establishes child exit or execution. */
int remozio_command_pty_read(remozio_command_pty_t * _Nonnull pty, void * _Nonnull bytes, size_t capacity,
    size_t * _Nonnull count, bool * _Nonnull eof);
/* Nonblocking bounded writes. A short write or zero count retains the caller's unsent bytes. */
int remozio_command_pty_write(remozio_command_pty_t * _Nonnull pty, const void * _Nullable bytes, size_t count,
    size_t * _Nonnull written);
int remozio_command_pty_resize(remozio_command_pty_t * _Nonnull pty, const struct winsize * _Nonnull size);
/* Closing the master can hang up a live slave. Retain the owner through child cleanup and output drain. */
void remozio_command_pty_close(remozio_command_pty_t * _Nullable pty);
#endif
