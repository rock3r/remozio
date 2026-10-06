#include <mach/mach.h>
#include <mach/message.h>
#include <arpa/inet.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 2) return 1;
    int first = strcmp(argv[1], "first") == 0;
    if (!first && strcmp(argv[1], "second")) return 2;
    mach_port_t endpoint = MACH_PORT_NULL;
    if (task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &endpoint) != KERN_SUCCESS) return 3;
    struct { mach_msg_header_t header; uint32_t version, length; char payload[8]; } message = {0};
    size_t count = first ? 7 : 4;
    message.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    message.header.msgh_size = (sizeof(mach_msg_header_t) + 8 + count + 3) & ~3u;
    message.header.msgh_remote_port = endpoint;
    message.header.msgh_id = 0x524d0401;
    message.version = htonl(1);
    message.length = htonl(count);
    memcpy(message.payload, first ? "pid=123" : "next", count);
    kern_return_t result = mach_msg(&message.header, MACH_SEND_MSG | MACH_SEND_TIMEOUT,
        message.header.msgh_size, 0, MACH_PORT_NULL, 5000, MACH_PORT_NULL);
    mach_port_deallocate(mach_task_self(), endpoint);
    if (result != KERN_SUCCESS) return 4;
    struct pollfd control = { .fd = STDIN_FILENO, .events = POLLIN };
    if (poll(&control, 1, 30000) <= 0) return 5;
    char byte;
    ssize_t received = read(STDIN_FILENO, &byte, 1);
    if (first) {
        if (received != 1 || byte != 'x') return 6;
        execl(argv[0], argv[0], "second", (char *)NULL);
        return 7;
    }
    return received == 0 ? 0 : 8;
}
