/* Compile the actual owner into this disposable process. Internal descriptors are inspected only by this fixture. */
#include <unistd.h>
#include <stdatomic.h>
#include <time.h>
static ssize_t delayed_write(int descriptor, const void *bytes, size_t count);
#define write delayed_write
#include "FrontendRuntime.c"
#undef write
static _Atomic bool pause_write, captured_write, release_write, held_descriptor;
static ssize_t delayed_write(int descriptor, const void *bytes, size_t count) {
    if (atomic_load_explicit(&pause_write, memory_order_relaxed)) {
        atomic_store_explicit(&captured_write, true, memory_order_release);
        while (!atomic_load_explicit(&release_write, memory_order_acquire)) {}
    }
    return write(descriptor, bytes, count);
}
static long now(void) {
    struct timespec value; clock_gettime(CLOCK_MONOTONIC, &value);
    return value.tv_sec * 1000 + value.tv_nsec / 1000000;
}
static void *release_worker(void *value) {
    int descriptor = *(int *)value;
    long deadline = now() + 5000;
    while (atomic_load_explicit(&wake_destination, memory_order_seq_cst) >= 0 && now() < deadline) usleep(1000);
    usleep(50000);
    bool held = fcntl(descriptor, F_GETFD) >= 0 && atomic_load_explicit(&handlers, memory_order_seq_cst) == 1;
    atomic_store_explicit(&held_descriptor, held, memory_order_release);
    atomic_store_explicit(&release_write, true, memory_order_release);
    return (void *)(intptr_t)!held;
}
#include <stdio.h>
#include <sys/socket.h>

static volatile sig_atomic_t original_calls;
static void previous_route(int number) { if (number == SIGWINCH) original_calls++; }
struct packet { mach_msg_header_t header; unsigned char bytes[8]; };
static int send_packet(mach_port_t port, unsigned index) {
    struct packet packet = {0};
    packet.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    packet.header.msgh_size = sizeof(packet); packet.header.msgh_remote_port = port; packet.header.msgh_id = 900 + index;
    for (unsigned i = 0; i < 8; i++) packet.bytes[i] = (unsigned char)(index * 31 + i);
    return mach_msg(&packet.header, MACH_SEND_MSG | MACH_SEND_TIMEOUT, sizeof(packet), 0, MACH_PORT_NULL, 1000, MACH_PORT_NULL);
}
static int receive_packet(mach_port_t port, unsigned index) {
    struct { struct packet packet; unsigned char trailer[512]; } received = {0};
    if (mach_msg(&received.packet.header, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(received), port, 1000, MACH_PORT_NULL)) return 0;
    unsigned char expected[8]; for (unsigned i = 0; i < 8; i++) expected[i] = (unsigned char)(index * 31 + i);
    int good = received.packet.header.msgh_id == 900 + (int)index && !memcmp(received.packet.bytes, expected, 8);
    mach_msg_destroy(&received.packet.header); return good;
}
static void *signal_worker(void *unused) {
    (void)unused; usleep(20000); errno = EDOM;
    int error = pthread_kill(pthread_self(), SIGWINCH);
    return (void *)(intptr_t)(error || errno != EDOM);
}
static int probe(void) {
    struct sigaction action = {0}, original = {0}, restored = {0};
    action.sa_handler = previous_route; sigemptyset(&action.sa_mask);
    if (sigaction(SIGWINCH, &action, &original)) return 3;
    remozio_frontend_runtime_t *owner = NULL, *second = NULL;
    if (remozio_frontend_runtime_open(&owner)) return 4;
    if (remozio_frontend_runtime_open(&second) != EBUSY || second) return 5;
    mach_port_t port = 0;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port) ||
        mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND)) return 6;
    int io[2]; if (socketpair(AF_UNIX, SOCK_STREAM, 0, io)) return 7;
    mach_port_t foreign_set = 0;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_PORT_SET, &foreign_set) ||
        mach_port_move_member(mach_task_self(), port, foreign_set)) return 38;
    if (remozio_frontend_runtime_attach(owner, port, io[0]) != EBUSY) return 39;
    mach_port_status_t status = {0}; mach_msg_type_number_t size = MACH_PORT_RECEIVE_STATUS_COUNT;
    if (mach_port_get_attributes(mach_task_self(), port, MACH_PORT_RECEIVE_STATUS, (mach_port_info_t)&status, &size) ||
        status.mps_pset != 1) return 40;
    if (mach_port_move_member(mach_task_self(), port, MACH_PORT_NULL) ||
        mach_port_mod_refs(mach_task_self(), foreign_set, MACH_PORT_RIGHT_PORT_SET, -1)) return 41;
    if (remozio_frontend_runtime_attach(owner, port, io[0])) return 8;
    if (remozio_frontend_runtime_attach(owner, port, io[0]) != EINVAL) return 42;
    if (send_packet(port, 0) || send_packet(port, 1)) return 9;
    uint32_t events = 0, signals = 0;
    if (remozio_frontend_runtime_wait(owner, true, false, false, 1000, &events) || events != REMOZIO_FRONTEND_MACH_READY) return 10;
    const unsigned char input[] = {0, 255, 13, 10}; unsigned char copied[4];
    if (write(io[1], input, 4) != 4) return 11;
    if (remozio_frontend_runtime_wait(owner, false, true, false, 1000, &events) || events != REMOZIO_FRONTEND_READ_READY) return 12;
    if (read(io[0], copied, 4) != 4 || memcmp(input, copied, 4)) return 13;
    if (remozio_frontend_runtime_wait(owner, false, true, false, 0, &events) || events) return 14;
    if (remozio_frontend_runtime_wait(owner, true, false, false, 1000, &events) || events != REMOZIO_FRONTEND_MACH_READY || !receive_packet(port, 0)) return 15;
    if (remozio_frontend_runtime_wait(owner, true, false, false, 1000, &events) || events != REMOZIO_FRONTEND_MACH_READY || !receive_packet(port, 1)) return 16;
    if (remozio_frontend_runtime_wait(owner, true, false, false, 0, &events) || events) return 17;
    pthread_t worker; void *result = NULL;
    if (pthread_create(&worker, NULL, signal_worker, NULL)) return 18;
    int error = remozio_frontend_runtime_wait(owner, false, false, false, 1000, &events);
    if (error == EINTR) error = remozio_frontend_runtime_wait(owner, false, false, false, 1000, &events);
    if (pthread_join(worker, &result) || result || error || events != REMOZIO_FRONTEND_SIGNAL_READY) return 19;
    if (remozio_frontend_runtime_take_signals(owner, &signals) || signals != REMOZIO_FRONTEND_RESIZE) return 20;
    unsigned char padding[4096]; memset(padding, 1, sizeof(padding));
    size_t filled = 0; ssize_t count;
    while ((count = write(owner->wake[1], padding, sizeof(padding))) > 0) filled += (size_t)count;
    if (count >= 0 || errno != EAGAIN || !filled || filled > 1048576) return 21;
    errno = EDOM;
    if (pthread_kill(pthread_self(), SIGWINCH) || errno != EDOM) return 22;
    if (remozio_frontend_runtime_wait(owner, false, false, false, 1000, &events) || events != REMOZIO_FRONTEND_SIGNAL_READY) return 23;
    if (remozio_frontend_runtime_take_signals(owner, &signals) || signals != REMOZIO_FRONTEND_RESIZE) return 24;
    if (remozio_frontend_runtime_wait(owner, true, false, false, 0, &events) || events) return 25;
    if (pthread_kill(pthread_self(), SIGTSTP) || pthread_kill(pthread_self(), SIGCONT)) return 43;
    if (remozio_frontend_runtime_take_signals(owner, &signals) || signals != REMOZIO_FRONTEND_CONTINUE) return 44;
    if (remozio_frontend_runtime_wait(owner, false, false, false, 0, &events) || events) return 47;
    if (remozio_frontend_runtime_suspend(owner, 50) != EINVAL) return 48;
    if (pthread_kill(pthread_self(), SIGCONT) || pthread_kill(pthread_self(), SIGTSTP)) return 45;
    if (remozio_frontend_runtime_take_signals(owner, &signals) || signals != REMOZIO_FRONTEND_SUSPEND) return 46;
    if (remozio_frontend_runtime_wait(owner, false, false, false, 0, &events) || events) return 49;
    int read_number = owner->wake[0], write_number = owner->wake[1];
    atomic_store_explicit(&pause_write, true, memory_order_relaxed);
    if (pthread_create(&worker, NULL, signal_worker, NULL)) return 34;
    long deadline = now() + 5000;
    while (!atomic_load_explicit(&captured_write, memory_order_acquire) && now() < deadline) usleep(1000);
    if (!atomic_load_explicit(&captured_write, memory_order_acquire)) return 35;
    pthread_t releaser;
    if (pthread_create(&releaser, NULL, release_worker, &write_number)) return 36;
    if (remozio_frontend_runtime_close(owner)) return 26;
    void *released = NULL;
    if (pthread_join(worker, &result) || pthread_join(releaser, &released) || result || released ||
        !atomic_load_explicit(&held_descriptor, memory_order_acquire)) return 37;
    if (sigaction(SIGWINCH, NULL, &restored) || restored.sa_handler != previous_route) return 27;
    if (fcntl(read_number, F_GETFD) != -1 || errno != EBADF || fcntl(write_number, F_GETFD) != -1 || errno != EBADF) return 28;
    int replacement[2]; if (pipe(replacement) || fcntl(replacement[0], F_SETFL, O_NONBLOCK) ||
        replacement[0] != read_number || replacement[1] != write_number) return 29;
    if (pthread_kill(pthread_self(), SIGWINCH) || original_calls != 1) return 30;
    if (read(replacement[0], padding, sizeof(padding)) != -1 || errno != EAGAIN) return 31;
    if (send_packet(port, 2) || !receive_packet(port, 2) || fcntl(io[0], F_GETFD) < 0) return 32;
    close(replacement[0]); close(replacement[1]); close(io[0]); close(io[1]);
    mach_port_deallocate(mach_task_self(), port); mach_port_mod_refs(mach_task_self(), port, MACH_PORT_RIGHT_RECEIVE, -1);
    if (sigaction(SIGWINCH, &original, NULL)) return 33;
    printf("{\"failure\":0,\"queuedMessagesPreserved\":true,\"disabledSourceIdle\":true,\"binaryInputPreserved\":true,"
        "\"latestJobControlIntentPreserved\":true,\"foreignMembershipPreserved\":true,\"threadDirectedSignalWake\":true,\"saturatedSignalPreserved\":true,\"saturatedBytes\":%zu,"
        "\"handlerErrnoPreserved\":true,\"previousHandlerRestored\":true,\"closedDescriptors\":true,"
        "\"inFlightHandlerKeepsDescriptorAlive\":true,\"descriptorNumbersActuallyReused\":true,\"replacementPipeUntouched\":true,\"queueClosurePreservesSources\":true,\"workerJoined\":true}\n", filled);
    return 0;
}
int main(void) {
    if (geteuid() == 0) return 2;
    int error = probe();
    if (error) fprintf(stderr, "frontend runtime fixture failed at stage %d\n", error);
    return error;
}
