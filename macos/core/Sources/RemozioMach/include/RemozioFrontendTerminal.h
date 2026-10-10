#ifndef REMOZIO_FRONTEND_TERMINAL_H
#define REMOZIO_FRONTEND_TERMINAL_H
#include <stdbool.h>
#include <stddef.h>
#include <sys/ioctl.h>

typedef struct remozio_frontend_terminal remozio_frontend_terminal_t;
/* Reopens the supplied terminal independently and checks its device and session.
 * No input, terminal attributes, shared descriptor flags or signal handlers change.
 * The caller must serialize this owner and keep its session unchanged. */
int remozio_frontend_terminal_open(int source, remozio_frontend_terminal_t * _Nullable * _Nonnull output);
/* Enter raw mode only after authenticated stream opening. Each activation captures
 * fresh settings. EAGAIN means background: wait for foreground without taking it.
 * A non-restarting SIGTTOU handler must return to the caller's signal loop. It must
 * neither stop inside the handler nor ignore the signal. SIGTTOU must be unblocked.
 * After an interrupted apply, restoration remains required; do not activate again. */
int remozio_frontend_terminal_activate(remozio_frontend_terminal_t * _Nonnull terminal);
/* Restore before suspension, disconnect or exit. This does not flush input.
 * Errors retain the saved settings for a later foreground retry. */
int remozio_frontend_terminal_restore(remozio_frontend_terminal_t * _Nonnull terminal);
/* This is a cleanup obligation, not proof that raw mode was applied successfully. */
bool remozio_frontend_terminal_needs_restore(const remozio_frontend_terminal_t * _Nonnull terminal);
/* Restore and free. On error, ownership remains with the caller for retry. */
int remozio_frontend_terminal_close(remozio_frontend_terminal_t * _Nonnull terminal);
enum { REMOZIO_FRONTEND_TERMINAL_MAX_CHUNK = 4096 };
/* Serialized, nonblocking IO on the independently retained terminal. Successful
 * activation is required. The read also requires a safe SIGTTIN route, and the
 * write requires a safe SIGTTOU route. EINTR and EAGAIN consume no bytes.
 * Each call accepts 1..4096 bytes. A successful zero-byte read means EOF.
 * Keep the unsent suffix after a partial write. No shared flags change. */
int remozio_frontend_terminal_read(remozio_frontend_terminal_t * _Nonnull terminal,
    void * _Nonnull bytes, size_t capacity, size_t * _Nonnull count);
int remozio_frontend_terminal_write(remozio_frontend_terminal_t * _Nonnull terminal,
    const void * _Nonnull bytes, size_t length, size_t * _Nonnull count);
/* A fresh foreground check grants no foreground takeover or execution authority. */
int remozio_frontend_terminal_check_foreground(remozio_frontend_terminal_t * _Nonnull terminal);
/* Borrows the independent descriptor for serialized readiness observation only. */
int remozio_frontend_terminal_descriptor(remozio_frontend_terminal_t * _Nonnull terminal,
    int * _Nonnull output);
/* Copies current dimensions without changing them or taking foreground. */
int remozio_frontend_terminal_dimensions(remozio_frontend_terminal_t * _Nonnull terminal,
    struct winsize * _Nonnull size);
/* Close without changing terminal attributes. Use only when restoration cannot be
 * completed, and report that fact. This grants no signal or execution authority. */
void remozio_frontend_terminal_abandon(remozio_frontend_terminal_t * _Nullable terminal);
#endif
