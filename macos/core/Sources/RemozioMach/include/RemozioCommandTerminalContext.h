#ifndef REMOZIO_COMMAND_TERMINAL_CONTEXT_H
#define REMOZIO_COMMAND_TERMINAL_CONTEXT_H
#include <mach/mach.h>
#include <stdbool.h>
#include <stdint.h>

typedef struct {
    int32_t process;
    int32_t session;
    uint64_t start_seconds;
    uint64_t start_microseconds;
    bool has_terminal;
    uint32_t terminal_device;
} remozio_command_terminal_context_t;

/* Observes the original audit incarnation. No input, terminal settings or process state changes.
 * Device/session metadata grants no authorization, signal, wait or execution authority. */
int remozio_command_terminal_context_capture(const audit_token_t * _Nonnull caller,
    remozio_command_terminal_context_t * _Nonnull output);
/* Samples that same incarnation again. A changed session or terminal returns ESTALE. */
int remozio_command_terminal_context_recheck(const audit_token_t * _Nonnull caller,
    const remozio_command_terminal_context_t * _Nonnull original);
#endif
