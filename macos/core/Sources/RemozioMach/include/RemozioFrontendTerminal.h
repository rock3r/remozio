#ifndef REMOZIO_FRONTEND_TERMINAL_H
#define REMOZIO_FRONTEND_TERMINAL_H
#include <stdbool.h>

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
/* Close without changing terminal attributes. Use only when restoration cannot be
 * completed, and report that fact. This grants no signal or execution authority. */
void remozio_frontend_terminal_abandon(remozio_frontend_terminal_t * _Nullable terminal);
#endif
