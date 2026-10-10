#ifndef REMOZIO_FRONTEND_RUNTIME_H
#define REMOZIO_FRONTEND_RUNTIME_H
#include <mach/mach.h>
#include <stdbool.h>
#include <stddef.h>

size_t remozio_frontend_service_name_capacity(void);
/* Lookup transfers one send reference. A registered name does not authenticate its receiver. */
kern_return_t remozio_frontend_lookup_service(const char * _Nonnull name,
    mach_port_t * _Nonnull output, bool * _Nonnull unavailable);

#include <stdint.h>
typedef struct remozio_frontend_runtime remozio_frontend_runtime_t;
enum {
    REMOZIO_FRONTEND_INTERRUPT = 1u << 0, REMOZIO_FRONTEND_TERMINATE = 1u << 1,
    REMOZIO_FRONTEND_HANGUP = 1u << 2, REMOZIO_FRONTEND_QUIT = 1u << 3,
    REMOZIO_FRONTEND_RESIZE = 1u << 4, REMOZIO_FRONTEND_SUSPEND = 1u << 5,
    REMOZIO_FRONTEND_CONTINUE = 1u << 6, REMOZIO_FRONTEND_BACKGROUND_READ = 1u << 7,
    REMOZIO_FRONTEND_BACKGROUND_WRITE = 1u << 8, REMOZIO_FRONTEND_BROKEN_PIPE = 1u << 9,
    REMOZIO_FRONTEND_MACH_READY = 1u << 0, REMOZIO_FRONTEND_READ_READY = 1u << 1,
    REMOZIO_FRONTEND_WRITE_READY = 1u << 2, REMOZIO_FRONTEND_SIGNAL_READY = 1u << 3
};
/* CLI main-thread owner only. It never operates a terminal or consumes Mach messages. */
int remozio_frontend_runtime_open(remozio_frontend_runtime_t * _Nullable * _Nonnull output);
/* Attach one private reply receive right. Destroying this owner detaches it without closing the source. */
int remozio_frontend_runtime_attach(remozio_frontend_runtime_t * _Nonnull owner, mach_port_t receive_port,
    int terminal_descriptor);
int remozio_frontend_runtime_take_signals(remozio_frontend_runtime_t * _Nonnull owner, uint32_t * _Nonnull signals);
/* Call only after successful terminal restoration and an observed local SUSPEND event. Never use a target job snapshot.
   Cooperatively stops this process with SIGTSTP, unless a returning SIGCONT handler cancelled that intent.
   A positive 1..60000 ms bound applies to signal delivery, not the stopped process or command lifetime.
   Failure requires owner cleanup. The kernel preserves ordinary orphaned-group behavior. */
int remozio_frontend_runtime_suspend(remozio_frontend_runtime_t * _Nonnull owner, uint32_t milliseconds);
/* Capture local signal generation before a fresh authenticated job query. The ticket grants no remote authority. */
int remozio_frontend_runtime_job_ticket(remozio_frontend_runtime_t * _Nonnull owner, uint64_t * _Nonnull ticket);
/* After fresh verified ordinary stop confirmation and terminal restoration, queue cooperative SIGTSTP only if
   the ticket is unchanged and the attached local terminal is still foreground. Reconcile entered handlers again
   after queuing. Check the continuous-clock deadline in milliseconds before and after queuing.
   False queued means cancellation; true is not proof of suspension in an orphaned group.
   Tickets saturate rather than wrap. This never substitutes SIGSTOP or signals a foreign group. */
int remozio_frontend_runtime_suspend_confirmed(remozio_frontend_runtime_t * _Nonnull owner, uint64_t ticket,
    uint64_t deadline_milliseconds, uint32_t milliseconds, bool * _Nonnull queued);
/* -1 waits indefinitely. Other values bound this single wait, never the command lifetime. */
int remozio_frontend_runtime_wait(remozio_frontend_runtime_t * _Nonnull owner, bool mach_interest,
    bool read_interest, bool write_interest, int64_t milliseconds, uint32_t * _Nonnull events);
/* Failed route restoration retains the owner and its descriptors for retry. */
int remozio_frontend_runtime_close(remozio_frontend_runtime_t * _Nonnull owner);
#endif
