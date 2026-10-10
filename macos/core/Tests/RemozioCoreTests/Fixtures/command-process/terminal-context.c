#include "RemozioMach.h"
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <mach/mach.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/fileport.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
#include <util.h>
#include <stdlib.h>

static pid_t owned = -1;
static void cleanup(void) {
    if (owned <= 0) return;
    pid_t result;
    do { result = waitpid(owned, NULL, WNOHANG); } while (result < 0 && errno == EINTR);
    if (!result) {
        kill(owned, SIGKILL);
        do { result = waitpid(owned, NULL, 0); } while (result < 0 && errno == EINTR);
    }
    owned = -1;
}
static int exchange(int descriptor, char value) {
    struct pollfd wait = {.fd = descriptor, .events = POLLIN};
    if (write(descriptor, &value, 1) != 1 || poll(&wait, 1, 5000) <= 0) return 1;
    char response;
    return read(descriptor, &response, 1) == 1 && response == value ? 0 : 1;
}
typedef struct { mach_msg_header_t header; mach_msg_body_t body; mach_msg_port_descriptor_t port; } message_t;
int main(void) {
    if (atexit(cleanup)) return 1;
    int master[2], slave[2], channel[2];
    if (openpty(&master[0], &slave[0], NULL, NULL, NULL) ||
        openpty(&master[1], &slave[1], NULL, NULL, NULL) || socketpair(AF_UNIX, SOCK_DGRAM, 0, channel)) return 2;
    struct stat first, second;
    if (fstat(slave[0], &first) || fstat(slave[1], &second)) return 3;
    mach_port_t inbox = MACH_PORT_NULL, saved = MACH_PORT_NULL;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &inbox) != KERN_SUCCESS ||
        mach_port_insert_right(mach_task_self(), inbox, inbox, MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS ||
        task_get_bootstrap_port(mach_task_self(), &saved) != KERN_SUCCESS ||
        task_set_bootstrap_port(mach_task_self(), inbox) != KERN_SUCCESS) return 4;
    pid_t child = fork();
    if (child < 0) return 5;
    if (!child) {
        close(channel[0]); close(master[0]); close(master[1]);
        signal(SIGHUP, SIG_IGN);
        if (setsid() < 0 || ioctl(slave[0], TIOCSCTTY, 0)) _exit(6);
        mach_port_t destination = MACH_PORT_NULL, carried = MACH_PORT_NULL;
        if (task_get_bootstrap_port(mach_task_self(), &destination) != KERN_SUCCESS || fileport_makeport(slave[0], &carried)) _exit(7);
        message_t message = {0};
        message.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
        message.header.msgh_size = sizeof(message); message.header.msgh_remote_port = destination;
        message.body.msgh_descriptor_count = 1;
        message.port.name = carried; message.port.disposition = MACH_MSG_TYPE_COPY_SEND; message.port.type = MACH_MSG_PORT_DESCRIPTOR;
        if (mach_msg(&message.header, MACH_SEND_MSG | MACH_SEND_TIMEOUT, sizeof(message), 0, 0, 5000, 0) != KERN_SUCCESS) _exit(8);
        mach_port_deallocate(mach_task_self(), carried); mach_port_deallocate(mach_task_self(), destination);
        if (exchange(channel[1], '0')) _exit(9);
        char original_path[128];
        if (ttyname_r(slave[0], original_path, sizeof(original_path))) _exit(10);
        errno = 0;
        int detached = revoke(original_path), detach_error = errno;
        fprintf(stderr, "private original terminal revoke: result=%d error=%d\n", detached, detach_error);
        if (detached || exchange(channel[1], '1')) _exit(10);
        errno = 0;
        int acquired = ioctl(slave[1], TIOCSCTTY, 0), acquire_error = errno;
        fprintf(stderr, "private replacement terminal acquire: result=%d error=%d\n", acquired, acquire_error);
        if (acquired || exchange(channel[1], '2')) _exit(11);
        char path[128];
        if (ttyname_r(slave[1], path, sizeof(path))) _exit(12);
        errno = 0;
        int revoked = revoke(path), revoke_error = errno;
        fprintf(stderr, "private replacement terminal revoke: result=%d error=%d\n", revoked, revoke_error);
        if (revoked || exchange(channel[1], '3')) _exit(13);
        close(slave[0]); close(slave[1]); close(channel[1]); _exit(0);
    }
    owned = child;
    if (task_set_bootstrap_port(mach_task_self(), saved) != KERN_SUCCESS) return 14;
    mach_port_deallocate(mach_task_self(), saved);
    close(channel[1]);
    struct { message_t message; unsigned char trailer[MAX_TRAILER_SIZE]; } received = {0};
    if (mach_msg(&received.message.header, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(received), inbox, 5000, 0) != KERN_SUCCESS) return 15;
    int original = fileport_makefd(received.message.port.name);
    mach_port_deallocate(mach_task_self(), received.message.port.name);
    if (original < 0) return 16;
    struct proc_bsdinfo captured = {0};
    audit_token_t original_token = {0};
    bool missing = false;
    if (remozio_pid_audit_token(child, &original_token, &missing) != KERN_SUCCESS || missing) return 20;
    remozio_command_terminal_context_t context = {0};
    int context_error = remozio_command_terminal_context_capture(&original_token, &context);
    if (context_error) { fprintf(stderr, "context capture error=%d\n", context_error); return 21; }
    if (context.process != child || context.session != child || !context.has_terminal ||
        context.terminal_device != (uint32_t)first.st_rdev) return 25;
    audit_token_t wrong = original_token;
    wrong.val[0] ^= 1;
    remozio_command_terminal_context_t rejected = {0};
    if (remozio_command_terminal_context_capture(&wrong, &rejected) != EAGAIN || rejected.process) return 22;
    for (int stage = 0; stage < 4; stage++) {
        struct pollfd wait = {.fd = channel[0], .events = POLLIN};
        char value;
        if (poll(&wait, 1, 5000) <= 0 || read(channel[0], &value, 1) != 1 || value != '0' + stage) return 17;
        struct proc_bsdinfo current = {0};
        int count = proc_pidinfo(child, PROC_PIDTBSDINFO, 0, &current, sizeof(current));
        if (stage == 0) captured = current;
        errno = 0;
        pid_t terminal_session = tcgetsid(original);
        int terminal_error = errno;
        printf("{\"stage\":%d,\"kernelSnapshotAvailable\":%s,\"callerIncarnationUnchanged\":%s,\"callerSessionUnchanged\":%s,\"callerTTYStillOriginal\":%s,\"callerTTYIsReplacement\":%s,\"retainedTerminalStillCallerSession\":%s,\"retainedTerminalSession\":%d,\"retainedTerminalError\":%d}\n", stage,
            count == sizeof(current) ? "true" : "false",
            current.pbi_pid == captured.pbi_pid && current.pbi_start_tvsec == captured.pbi_start_tvsec && current.pbi_start_tvusec == captured.pbi_start_tvusec ? "true" : "false",
            getsid(child) == child ? "true" : "false",
            current.e_tdev == (uint32_t)first.st_rdev ? "true" : "false",
            current.e_tdev == (uint32_t)second.st_rdev ? "true" : "false",
            terminal_session == child ? "true" : "false", terminal_session, terminal_error);
        fflush(stdout);
        int recheck_error = remozio_command_terminal_context_recheck(&original_token, &context);
        printf("{\"contextStage\":%d,\"recheckError\":%d}\n", stage, recheck_error);
        fflush(stdout);
        if (recheck_error != (stage == 0 ? 0 : ESTALE)) return 23;
        if (write(channel[0], &value, 1) != 1) return 18;
    }
    int status = 0;
    pid_t result;
    do { result = waitpid(child, &status, 0); } while (result < 0 && errno == EINTR);
    if (result != child || !WIFEXITED(status) || WEXITSTATUS(status)) return 19;
    owned = -1;
    int exit_error = remozio_command_terminal_context_recheck(&original_token, &context);
    printf("{\"originalCallerReaped\":true,\"exitRecheckError\":%d}\n", exit_error);
    if (exit_error != ESRCH) return 24;
    close(original); close(slave[0]); close(slave[1]); close(master[0]); close(master[1]); close(channel[0]);
    mach_port_deallocate(mach_task_self(), inbox); mach_port_mod_refs(mach_task_self(), inbox, MACH_PORT_RIGHT_RECEIVE, -1);
    fprintf(stderr, "owned caller actually reaped: status=%d\n", status);
    return 0;
}
