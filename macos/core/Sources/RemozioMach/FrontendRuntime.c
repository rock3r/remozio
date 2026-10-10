#include "include/RemozioFrontendRuntime.h"
#include <servers/bootstrap.h>
#include <string.h>

size_t remozio_frontend_service_name_capacity(void) { return sizeof(name_t); }

kern_return_t remozio_frontend_lookup_service(const char *name, mach_port_t *output, bool *unavailable) {
    if (!output || !unavailable) return KERN_INVALID_ARGUMENT;
    *output = MACH_PORT_NULL; *unavailable = false;
    if (!name || !name[0] || strnlen(name, sizeof(name_t)) >= sizeof(name_t)) return KERN_INVALID_ARGUMENT;
    kern_return_t status = bootstrap_look_up(bootstrap_port, name, output);
    *unavailable = status == BOOTSTRAP_UNKNOWN_SERVICE;
    return status;
}

#include <errno.h>
#include <fcntl.h>
#include <mach/mach_time.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <sys/event.h>
#include <sys/select.h>
#include <unistd.h>

static const int routed_signals[] = {SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGWINCH,
    SIGTSTP, SIGCONT, SIGTTIN, SIGTTOU, SIGPIPE};
#define ROUTE_COUNT (sizeof(routed_signals) / sizeof(routed_signals[0]))
static _Atomic bool occupied;
static _Atomic int wake_destination = -1, route_process;
static _Atomic unsigned handlers;
static _Atomic uint64_t pending_signals;
#define EVENT_BITS ((1u << ROUTE_COUNT) - 1)
#define JOB_HISTORY_SHIFT 16
#define LOCAL_GENERATION_SHIFT 32

struct remozio_frontend_runtime {
    pid_t process;
    int queue, wake[2], terminal;
    mach_port_t set;
    bool attached, attachment_failed, captured_mask, stop_requested, installed[ROUTE_COUNT];
    sigset_t mask, previous_mask;
    mach_timebase_info_data_t timebase;
    struct sigaction previous[ROUTE_COUNT];
};

static void signal_route(int number) {
    int saved = errno;
    if (getpid() == atomic_load_explicit(&route_process, memory_order_relaxed)) {
        atomic_fetch_add_explicit(&handlers, 1, memory_order_seq_cst);
        int descriptor = atomic_load_explicit(&wake_destination, memory_order_seq_cst);
        if (descriptor >= 0) {
            for (unsigned i = 0; i < ROUTE_COUNT; i++) {
                if (number == routed_signals[i]) {
                    unsigned bit = 1u << i;
                    unsigned job = REMOZIO_FRONTEND_SUSPEND | REMOZIO_FRONTEND_CONTINUE;
                    uint64_t previous = atomic_load_explicit(&pending_signals, memory_order_relaxed), next;
                    do {
                        uint64_t generation = previous >> LOCAL_GENERATION_SHIFT;
                        if (generation < UINT32_MAX) generation++;
                        next = (previous & UINT32_MAX) | ((uint64_t)bit) | (generation << LOCAL_GENERATION_SHIFT);
                        if (bit & job) next = (next & ~((uint64_t)job | ((uint64_t)job << JOB_HISTORY_SHIFT))) |
                            bit | ((uint64_t)bit << JOB_HISTORY_SHIFT);
                    } while (!atomic_compare_exchange_weak_explicit(&pending_signals, &previous, next,
                        memory_order_seq_cst, memory_order_relaxed));
                    unsigned char byte = 1;
                    ssize_t sent;
                    do { sent = write(descriptor, &byte, 1); } while (sent < 0 && errno == EINTR);
                    break;
                }
            }
        }
        atomic_fetch_sub_explicit(&handlers, 1, memory_order_seq_cst);
    }
    errno = saved;
}

static int check_owner(const remozio_frontend_runtime_t *owner) {
    return owner && owner->process == getpid() && pthread_main_np() ? 0 : EPERM;
}
static int interest(int queue, uintptr_t source, int16_t filter, bool enabled) {
    struct kevent change;
    /* Level readiness preserves every unread message. Disable sources that the relay cannot consume. */
    EV_SET(&change, source, filter, EV_ADD | (enabled ? EV_ENABLE : EV_DISABLE), 0, 0, NULL);
    return kevent(queue, &change, 1, NULL, 0, NULL) < 0 ? errno : 0;
}

int remozio_frontend_runtime_close(remozio_frontend_runtime_t *owner) {
    int error = check_owner(owner);
    if (error) return error;
    if (owner->captured_mask) {
        error = pthread_sigmask(SIG_BLOCK, &owner->mask, NULL);
        if (error) return error;
    }
    atomic_store_explicit(&wake_destination, -1, memory_order_seq_cst);
    for (unsigned i = 0; i < ROUTE_COUNT; i++) {
        if (owner->installed[i]) {
            if (sigaction(routed_signals[i], &owner->previous[i], NULL)) { if (!error) error = errno; }
            else owner->installed[i] = false;
        }
    }
    if (error) return error;
    /* A handler that captured the old descriptor must finish before its number can be reused. */
    while (atomic_load_explicit(&handlers, memory_order_seq_cst)) usleep(1000);
    if (owner->captured_mask) {
        error = pthread_sigmask(SIG_SETMASK, &owner->previous_mask, NULL);
        if (error) return error;
    }
    if (owner->queue >= 0) close(owner->queue);
    /* Set destruction detaches its own members. Do not look up a potentially recycled borrowed port name. */
    if (owner->set) mach_port_mod_refs(mach_task_self(), owner->set, MACH_PORT_RIGHT_PORT_SET, -1);
    if (owner->wake[0] >= 0) close(owner->wake[0]);
    if (owner->wake[1] >= 0) close(owner->wake[1]);
    atomic_store_explicit(&pending_signals, 0, memory_order_relaxed);
    atomic_store_explicit(&route_process, 0, memory_order_relaxed);
    atomic_store_explicit(&occupied, false, memory_order_release);
    free(owner); return 0;
}

int remozio_frontend_runtime_open(remozio_frontend_runtime_t **output) {
    if (!output) return EINVAL;
    *output = NULL;
    if (!pthread_main_np()) return EPERM;
    if (!atomic_is_lock_free(&occupied) || !atomic_is_lock_free(&wake_destination) ||
        !atomic_is_lock_free(&route_process) || !atomic_is_lock_free(&handlers) ||
        !atomic_is_lock_free(&pending_signals)) return ENOTSUP;
    bool expected = false;
    if (!atomic_compare_exchange_strong_explicit(&occupied, &expected, true, memory_order_acquire, memory_order_relaxed)) return EBUSY;
    remozio_frontend_runtime_t *owner = calloc(1, sizeof(*owner));
    if (!owner) { atomic_store(&occupied, false); return ENOMEM; }
    owner->process = getpid(); owner->queue = -1; owner->wake[0] = owner->wake[1] = -1; owner->terminal = -1;
    *output = owner;
    int error = 0;
    if (mach_timebase_info(&owner->timebase) != KERN_SUCCESS || !owner->timebase.numer || !owner->timebase.denom) {
        error = EINVAL; goto failed;
    }
    if (pipe(owner->wake)) { error = errno; goto failed; }
    for (unsigned i = 0; i < 2; i++) {
        if (fcntl(owner->wake[i], F_SETFL, O_NONBLOCK) || fcntl(owner->wake[i], F_SETFD, FD_CLOEXEC)) {
            error = errno; goto failed;
        }
    }
    owner->queue = kqueue();
    if (owner->queue < 0) { error = errno; goto failed; }
    if (fcntl(owner->queue, F_SETFD, FD_CLOEXEC)) { error = errno; goto failed; }
    error = interest(owner->queue, owner->wake[0], EVFILT_READ, true);
    if (error) goto failed;
    sigemptyset(&owner->mask);
    for (unsigned i = 0; i < ROUTE_COUNT; i++) sigaddset(&owner->mask, routed_signals[i]);
    error = pthread_sigmask(SIG_BLOCK, &owner->mask, &owner->previous_mask);
    if (error) goto failed;
    owner->captured_mask = true;
    atomic_store_explicit(&route_process, owner->process, memory_order_relaxed);
    atomic_store_explicit(&wake_destination, owner->wake[1], memory_order_seq_cst);
    struct sigaction action = {0}; action.sa_handler = signal_route; action.sa_mask = owner->mask;
    for (unsigned i = 0; i < ROUTE_COUNT; i++) {
        if (sigaction(routed_signals[i], &action, &owner->previous[i])) { error = errno; goto failed; }
        owner->installed[i] = true;
    }
    sigset_t unblocked = owner->previous_mask;
    for (unsigned i = 0; i < ROUTE_COUNT; i++) sigdelset(&unblocked, routed_signals[i]);
    error = pthread_sigmask(SIG_SETMASK, &unblocked, NULL);
    if (!error) return 0;
failed:
    if (!remozio_frontend_runtime_close(owner)) *output = NULL;
    return error;
}

int remozio_frontend_runtime_attach(remozio_frontend_runtime_t *owner, mach_port_t receive_port, int terminal_descriptor) {
    int error = check_owner(owner);
    if (error) return error;
    if (owner->attached || owner->attachment_failed || !receive_port || terminal_descriptor < -1) return EINVAL;
    mach_port_status_t status = {0};
    mach_msg_type_number_t count = MACH_PORT_RECEIVE_STATUS_COUNT;
    kern_return_t result = mach_port_get_attributes(mach_task_self(), receive_port, MACH_PORT_RECEIVE_STATUS,
        (mach_port_info_t)&status, &count);
    if (result != KERN_SUCCESS || count != MACH_PORT_RECEIVE_STATUS_COUNT) return EINVAL;
    if (status.mps_pset) return EBUSY;
    result = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_PORT_SET, &owner->set);
    if (result != KERN_SUCCESS) return ENOMEM;
    result = mach_port_move_member(mach_task_self(), receive_port, owner->set);
    if (result != KERN_SUCCESS) { error = EIO; goto failed; }
    error = interest(owner->queue, owner->set, EVFILT_MACHPORT, false);
    if (error) goto failed;
    if (terminal_descriptor >= 0) {
        error = interest(owner->queue, terminal_descriptor, EVFILT_READ, false);
        if (!error) error = interest(owner->queue, terminal_descriptor, EVFILT_WRITE, false);
        if (error) goto failed;
    }
    owner->terminal = terminal_descriptor; owner->attached = true; return 0;
failed:
    /* Retire this wait owner after a failed attachment; partial queue registrations must not be reused. */
    owner->attachment_failed = true;
    return error;
}

int remozio_frontend_runtime_take_signals(remozio_frontend_runtime_t *owner, uint32_t *signals) {
    int error = check_owner(owner);
    if (error || !signals) return error ? error : EINVAL;
    unsigned char bytes[256]; ssize_t count;
    do { count = read(owner->wake[0], bytes, sizeof(bytes)); } while (count > 0 || (count < 0 && errno == EINTR));
    if (count < 0 && errno != EAGAIN) return errno;
    *signals = (uint32_t)(atomic_fetch_and_explicit(&pending_signals, ~((uint64_t)EVENT_BITS), memory_order_seq_cst) & EVENT_BITS);
    if (*signals & REMOZIO_FRONTEND_SUSPEND) owner->stop_requested = true;
    if (*signals & REMOZIO_FRONTEND_CONTINUE) owner->stop_requested = false;
    return 0;
}

int remozio_frontend_runtime_job_ticket(remozio_frontend_runtime_t *owner, uint64_t *ticket) {
    int error = check_owner(owner);
    if (error || !ticket) return error ? error : EINVAL;
    *ticket = 0;
    while (atomic_load_explicit(&handlers, memory_order_seq_cst)) usleep(1000);
    uint64_t generation = atomic_load_explicit(&pending_signals, memory_order_seq_cst) >> LOCAL_GENERATION_SHIFT;
    if (generation == UINT32_MAX) return EOVERFLOW;
    *ticket = generation; return 0;
}
static bool confirmation_fresh(remozio_frontend_runtime_t *owner, uint64_t deadline) {
    __uint128_t milliseconds = (__uint128_t)mach_continuous_time() * owner->timebase.numer /
        ((__uint128_t)owner->timebase.denom * 1000000);
    return milliseconds < deadline;
}
static bool suspend_intent(remozio_frontend_runtime_t *owner, bool confirmed, uint64_t ticket, uint64_t deadline) {
    uint64_t signals = atomic_load_explicit(&pending_signals, memory_order_seq_cst);
    if (!confirmed) return (signals & ((REMOZIO_FRONTEND_SUSPEND | REMOZIO_FRONTEND_CONTINUE) << JOB_HISTORY_SHIFT)) ==
        (REMOZIO_FRONTEND_SUSPEND << JOB_HISTORY_SHIFT);
    if (ticket >= UINT32_MAX || (signals >> LOCAL_GENERATION_SHIFT) != ticket) return false;
    return (owner->terminal < 0 || tcgetpgrp(owner->terminal) == getpgrp()) && confirmation_fresh(owner, deadline);
}
static int cooperative_suspend(remozio_frontend_runtime_t *owner, uint32_t milliseconds, bool confirmed,
                               uint64_t ticket, uint64_t deadline, bool *queued) {
    int error = check_owner(owner);
    if (error) return error;
    if (milliseconds == 0 || milliseconds > 60000 || (confirmed ? ticket >= UINT32_MAX : !owner->stop_requested)) return EINVAL;
    if (!confirmed) owner->stop_requested = false;
    if (queued) *queued = false;
    sigset_t block, before, wait_mask;
    sigemptyset(&block); sigaddset(&block, SIGTSTP); sigaddset(&block, SIGCONT);
    error = pthread_sigmask(SIG_BLOCK, &block, &before);
    if (error) return error;
    struct sigaction routed, action = {0};
    action.sa_handler = SIG_DFL; sigemptyset(&action.sa_mask);
    bool replaced = false;
    /* Returning handlers may run on other threads. Reconcile their recorded intent before and after queuing the stop. */
    while (atomic_load_explicit(&handlers, memory_order_seq_cst)) usleep(1000);
    if (!suspend_intent(owner, confirmed, ticket, deadline)) goto restore;
    if (sigaction(SIGTSTP, &action, &routed)) { error = errno; goto restore; }
    replaced = true;
    /* A thread-directed pending stop cannot act before this main thread atomically unmasks it. */
    error = pthread_kill(pthread_self(), SIGTSTP);
    if (error) goto restore;
    while (atomic_load_explicit(&handlers, memory_order_seq_cst)) usleep(1000);
    if (!suspend_intent(owner, confirmed, ticket, deadline)) {
        /* SIGCONT cancels the pending stop, including one queued after an earlier returning CONT handler. */
        error = pthread_kill(pthread_self(), SIGCONT);
        if (error) goto restore;
    } else if (queued) *queued = true;
    wait_mask = before; sigdelset(&wait_mask, SIGTSTP); sigdelset(&wait_mask, SIGCONT);
    struct timespec timeout = {.tv_sec = milliseconds / 1000, .tv_nsec = (milliseconds % 1000) * 1000000};
    /* A positive bound lets the kernel deliver a pending thread signal and avoids hanging in an orphaned group. */
    if (pselect(0, NULL, NULL, NULL, &timeout, &wait_mask) < 0 && errno != EINTR) error = errno;
restore:
    if (replaced && sigaction(SIGTSTP, &routed, NULL) && !error) error = errno;
    int mask_error = pthread_sigmask(SIG_SETMASK, &before, NULL);
    return error ? error : mask_error;
}

int remozio_frontend_runtime_suspend(remozio_frontend_runtime_t *owner, uint32_t milliseconds) {
    return cooperative_suspend(owner, milliseconds, false, 0, 0, NULL);
}
int remozio_frontend_runtime_suspend_confirmed(remozio_frontend_runtime_t *owner, uint64_t ticket,
                                              uint64_t deadline, uint32_t milliseconds, bool *queued) {
    if (!queued) return EINVAL;
    *queued = false;
    return cooperative_suspend(owner, milliseconds, true, ticket, deadline, queued);
}

int remozio_frontend_runtime_wait(remozio_frontend_runtime_t *owner, bool mach_interest,
    bool read_interest, bool write_interest, int64_t milliseconds, uint32_t *events) {
    int error = check_owner(owner);
    if (error || !events || milliseconds < -1 || milliseconds > UINT32_MAX) return error ? error : EINVAL;
    *events = 0;
    if (owner->attachment_failed || (!owner->attached && (mach_interest || read_interest || write_interest)) ||
        (owner->attached && owner->terminal < 0 && (read_interest || write_interest))) return EINVAL;
    if (owner->attached) {
        error = interest(owner->queue, owner->set, EVFILT_MACHPORT, mach_interest);
        if (!error && owner->terminal >= 0) error = interest(owner->queue, owner->terminal, EVFILT_READ, read_interest);
        if (!error && owner->terminal >= 0) error = interest(owner->queue, owner->terminal, EVFILT_WRITE, write_interest);
        if (error) return error;
    }
    if (atomic_load_explicit(&pending_signals, memory_order_relaxed) & EVENT_BITS) { *events = REMOZIO_FRONTEND_SIGNAL_READY; return 0; }
    struct timespec timeout = {.tv_sec = milliseconds / 1000, .tv_nsec = (milliseconds % 1000) * 1000000};
    struct kevent ready[4] = {0};
    int count = kevent(owner->queue, NULL, 0, ready, 4, milliseconds < 0 ? NULL : &timeout);
    if (count < 0) return errno;
    for (int i = 0; i < count; i++) {
        if (ready[i].flags & EV_ERROR) return ready[i].data ? (int)ready[i].data : EIO;
        if (ready[i].filter == EVFILT_MACHPORT) *events |= REMOZIO_FRONTEND_MACH_READY;
        else if (ready[i].ident == (uintptr_t)owner->wake[0]) *events |= REMOZIO_FRONTEND_SIGNAL_READY;
        else if (ready[i].filter == EVFILT_READ) *events |= REMOZIO_FRONTEND_READ_READY;
        else if (ready[i].filter == EVFILT_WRITE) *events |= REMOZIO_FRONTEND_WRITE_READY;
    }
    return 0;
}
