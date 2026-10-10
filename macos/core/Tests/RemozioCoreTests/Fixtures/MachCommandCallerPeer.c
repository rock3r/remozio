#include "RemozioCommandStreamSource.h"
#include <sys/ioctl.h>
#include <util.h>
#include <mach/mach.h>
#include <mach/message.h>
#include <arpa/inet.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/fileport.h>
#include <limits.h>
#include <signal.h>
static char private_terminal[PATH_MAX];
static int send_io(mach_port_t endpoint, const char *path, int terminal_role, int bind_terminal, int mapped_mask, int foreign_role) {
    FILE *file = fopen(path, "rb");
    if (!file || fseek(file, 0, SEEK_END)) return 20;
    long count = ftell(file);
    if (count <= 0 || count > 8192 || fseek(file, 0, SEEK_SET)) return 21;
    mach_port_t ports[6] = {0};
    int mapped = mapped_mask >= 0, port_count = mapped ? 6 : 5;
    int output = open("/dev/null", O_WRONLY | O_CLOEXEC);
    int master = -1, slave = -1, alias = -1, stable = -1;
    if (terminal_role >= 0 || (mapped && bind_terminal >= 0)) {
        if (mapped && signal(SIGHUP, SIG_IGN) == SIG_ERR) return 38;
        if (openpty(&master, &slave, private_terminal, NULL, NULL) || setsid() < 0 || ioctl(slave, TIOCSCTTY, 0)) return 35;
        alias = open("/dev/tty", O_RDWR | O_CLOEXEC | O_NOCTTY);
        if (alias < 0) return 36;
        if ((bind_terminal || mapped) && remozio_command_stream_source_retain(alias, &stable)) return 37;
    }
    if (mapped && bind_terminal < 0 && setsid() < 0) return 35;
    int sources[3] = { STDIN_FILENO, output, output };
    if (terminal_role >= 0) sources[terminal_role] = bind_terminal ? stable : alias;
    if (mapped) for (int index = 0; index < 3; index++) if (mapped_mask & (1 << index)) sources[index] = stable;
    int foreign_master = -1, foreign_slave = -1;
    if (foreign_role >= 0) {
        if (openpty(&foreign_master, &foreign_slave, NULL, NULL, NULL)) return 42;
        sources[foreign_role] = foreign_slave;
    }
    if (output < 0) return 22;
    for (int index = 0; index < 3; index++) if (fileport_makeport(sources[index], &ports[index])) return 22;
    if (mapped && bind_terminal >= 0 && fileport_makeport(bind_terminal ? stable : alias, &ports[3])) return 22;
    if (foreign_slave >= 0) close(foreign_slave);
    if (stable >= 0) close(stable);
    if (alias >= 0) close(alias);
    if (slave >= 0) close(slave);
    /* Keep the private master open until the caller exits after its control pipe closes. */
    close(output);
    for (int index = mapped ? 4 : 3; index < port_count; index++) {
        if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &ports[index]) != KERN_SUCCESS ||
            mach_port_insert_right(mach_task_self(), ports[index], ports[index], MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS) return 23;
    }
    size_t metadata = sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t) + (size_t)port_count * sizeof(mach_msg_port_descriptor_t);
    size_t size = (metadata + 8 + (size_t)count + 3) & ~3u;
    unsigned char *storage = calloc(1, size);
    if (!storage) return 24;
    mach_msg_header_t *header = (mach_msg_header_t *)storage;
    header->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
    header->msgh_size = (mach_msg_size_t)size; header->msgh_remote_port = endpoint; header->msgh_id = mapped ? 0x524d040c : 0x524d0407;
    mach_msg_body_t body = { .msgh_descriptor_count = (mach_msg_size_t)port_count };
    memcpy(storage + sizeof(*header), &body, sizeof(body));
    for (int index = 0; index < port_count; index++) {
        mach_msg_port_descriptor_t descriptor = {0};
        descriptor.name = ports[index]; descriptor.disposition = MACH_MSG_TYPE_COPY_SEND; descriptor.type = MACH_MSG_PORT_DESCRIPTOR;
        memcpy(storage + sizeof(*header) + sizeof(body) + index * sizeof(descriptor), &descriptor, sizeof(descriptor));
    }
    uint32_t version = htonl(mapped ? 5 : 4), length = htonl((uint32_t)count);
    memcpy(storage + metadata, &version, 4); memcpy(storage + metadata + 4, &length, 4);
    if (fread(storage + metadata + 8, 1, (size_t)count, file) != (size_t)count) return 25;
    fclose(file);
    kern_return_t result = mach_msg(header, MACH_SEND_MSG | MACH_SEND_TIMEOUT, header->msgh_size, 0, MACH_PORT_NULL, 5000, MACH_PORT_NULL);
    free(storage);
    for (int index = 0; index < port_count; index++) if (ports[index] != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), ports[index]);
    return result == KERN_SUCCESS ? 0 : 26;
}
static int send_revoked_notice(void) {
    mach_port_t endpoint = MACH_PORT_NULL;
    if (task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &endpoint) != KERN_SUCCESS) return 39;
    struct { mach_msg_header_t header; uint32_t version, length; char payload[8]; } message = {0};
    message.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    message.header.msgh_size = (sizeof(mach_msg_header_t) + 8 + 7 + 3) & ~3u;
    message.header.msgh_remote_port = endpoint; message.header.msgh_id = 0x524d0401;
    message.version = htonl(1); message.length = htonl(7); memcpy(message.payload, "revoked", 7);
    kern_return_t result = mach_msg(&message.header, MACH_SEND_MSG | MACH_SEND_TIMEOUT,
        message.header.msgh_size, 0, MACH_PORT_NULL, 5000, MACH_PORT_NULL);
    mach_port_deallocate(mach_task_self(), endpoint);
    return result == KERN_SUCCESS ? 0 : 40;
}
static int send_control(mach_port_t endpoint, const char *path) {
    FILE *file = fopen(path, "rb");
    if (!file) return 30;
    unsigned char bytes[8193]; size_t count = fread(bytes, 1, sizeof(bytes), file); fclose(file);
    if (!count || count > 8192) return 31;
    size_t prefix = sizeof(mach_msg_header_t), size = (prefix + 8 + count + 3) & ~3u;
    unsigned char *storage = calloc(1, size);
    if (!storage) return 32;
    mach_msg_header_t *header = (mach_msg_header_t *)storage;
    header->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    header->msgh_size = (mach_msg_size_t)size; header->msgh_remote_port = endpoint; header->msgh_id = 0x524d040b;
    uint32_t version = htonl(1), length = htonl((uint32_t)count);
    memcpy(storage + prefix, &version, 4); memcpy(storage + prefix + 4, &length, 4); memcpy(storage + prefix + 8, bytes, count);
    kern_return_t result = mach_msg(header, MACH_SEND_MSG | MACH_SEND_TIMEOUT, header->msgh_size, 0, MACH_PORT_NULL, 5000, MACH_PORT_NULL);
    free(storage); return result == KERN_SUCCESS ? 0 : 33;
}
int main(int argc, char **argv) {
    if (argc != 2 && argc != 3 && argc != 4) return 1;
    int first = strcmp(argv[1], "first") == 0;
    if (!first && strcmp(argv[1], "second")) return 2;
    mach_port_t endpoint = MACH_PORT_NULL;
    if (task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &endpoint) != KERN_SUCCESS) return 3;
    if (argc == 4) {
        int error;
        if (!strcmp(argv[3], "control")) error = send_control(endpoint, argv[2]);
        else if (!strncmp(argv[3], "raw-terminal-", 13) || !strncmp(argv[3], "bound-terminal-", 15)) {
            int bound = argv[3][0] == 'b';
            const char *role = argv[3] + (bound ? 15 : 13);
            if (strlen(role) != 1 || *role < '0' || *role > '2') return 34;
            error = send_io(endpoint, argv[2], *role - '0', bound, -1, -1);
        } else if (!strncmp(argv[3], "mapped-foreign-terminal-", 24)) {
            const char *role = argv[3] + 24;
            if (strlen(role) != 1 || *role < '0' || *role > '2') return 34;
            int index = *role - '0';
            error = send_io(endpoint, argv[2], -1, 1, 7 & ~(1 << index), index);
        } else if (!strcmp(argv[3], "mapped-no-terminal-0")) {
            error = send_io(endpoint, argv[2], -1, -1, 0, -1);
        } else if (!strncmp(argv[3], "mapped-raw-terminal-", 20)) {
            const char *mask = argv[3] + 20;
            if (strlen(mask) != 1 || *mask < '0' || *mask > '7') return 34;
            error = send_io(endpoint, argv[2], -1, 0, *mask - '0', -1);
        } else if (!strncmp(argv[3], "mapped-terminal-", 16)) {
            const char *mask = argv[3] + 16;
            if (strlen(mask) != 1 || *mask < '0' || *mask > '7') return 34;
            error = send_io(endpoint, argv[2], -1, 1, *mask - '0', -1);
        } else return 34;
        if (error) return error;
    } else if (argc == 3) {
        int error = send_io(endpoint, argv[2], -1, 0, -1, -1);
        if (error) return error;
    } else {
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
        if (result != KERN_SUCCESS) return 4;
    }
    mach_port_deallocate(mach_task_self(), endpoint);
    for (;;) {
        struct pollfd control = { .fd = STDIN_FILENO, .events = POLLIN };
        if (poll(&control, 1, 30000) <= 0) return 5;
        char byte;
        ssize_t received = read(STDIN_FILENO, &byte, 1);
        if (first && argc == 4 && !strncmp(argv[3], "mapped-terminal-", 16) && received == 1 && byte == 'r') {
            if (revoke(private_terminal)) return 41;
            int error = send_revoked_notice();
            if (error) return error;
            continue;
        }
        if (first) {
            if (received == 0) return 0;
            if (received != 1 || byte != 'x') return 6;
            execl(argv[0], argv[0], "second", (char *)NULL);
            return 7;
        }
        return received == 0 ? 0 : 8;
    }
}
