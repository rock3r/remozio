#include "message.h"
#include <poll.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2 || (strcmp(argv[1], "first") && strcmp(argv[1], "second"))) return 1;
    mach_port_t endpoint = MACH_PORT_NULL;
    if (task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &endpoint) != KERN_SUCCESS ||
        endpoint == MACH_PORT_NULL) return 2;
    struct probe_message message = {0};
    message.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    message.header.msgh_size = sizeof(message);
    message.header.msgh_remote_port = endpoint;
    message.header.msgh_id = PROBE_MESSAGE_ID;
    message.version = PROBE_VERSION;
    message.phase = strcmp(argv[1], "first") == 0 ? 1 : 2;
#ifdef PROBE_WRONG_PHASE
    message.phase = 99;
#endif
    message.claimed_pid = UINT32_MAX;
    kern_return_t sent = KERN_SUCCESS;
#ifndef PROBE_SKIP_SEND
    sent = mach_msg(&message.header, MACH_SEND_MSG | MACH_SEND_TIMEOUT,
        sizeof(message), 0, MACH_PORT_NULL, PROBE_TIMEOUT_MS, MACH_PORT_NULL);
#endif
    mach_port_deallocate(mach_task_self(), endpoint);
    if (sent != KERN_SUCCESS) return 3;
    struct pollfd control = { .fd = STDIN_FILENO, .events = POLLIN };
    if (poll(&control, 1, 30000) <= 0) return 4;
    char byte;
    ssize_t count = read(STDIN_FILENO, &byte, 1);
    if (message.phase == 1) {
        if (count != 1 || byte != 'x') return 5;
#ifdef PROBE_SKIP_EXEC
        return 8;
#endif
        execl(argv[0], argv[0], "second", (char *)NULL);
        return 6;
    }
    return count == 0 ? 0 : 7;
}
