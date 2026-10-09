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
static int send_io(mach_port_t endpoint, const char *path) {
    FILE *file = fopen(path, "rb");
    if (!file || fseek(file, 0, SEEK_END)) return 20;
    long count = ftell(file);
    if (count <= 0 || count > 8192 || fseek(file, 0, SEEK_SET)) return 21;
    mach_port_t ports[5] = {0};
    int output = open("/dev/null", O_WRONLY | O_CLOEXEC);
    if (output < 0 || fileport_makeport(STDIN_FILENO, &ports[0]) ||
        fileport_makeport(output, &ports[1]) || fileport_makeport(output, &ports[2])) return 22;
    close(output);
    for (int index = 3; index < 5; index++) {
        if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &ports[index]) != KERN_SUCCESS ||
            mach_port_insert_right(mach_task_self(), ports[index], ports[index], MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS) return 23;
    }
    size_t metadata = sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t) + 5 * sizeof(mach_msg_port_descriptor_t);
    size_t size = (metadata + 8 + (size_t)count + 3) & ~3u;
    unsigned char *storage = calloc(1, size);
    if (!storage) return 24;
    mach_msg_header_t *header = (mach_msg_header_t *)storage;
    header->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
    header->msgh_size = (mach_msg_size_t)size; header->msgh_remote_port = endpoint; header->msgh_id = 0x524d0407;
    mach_msg_body_t body = { .msgh_descriptor_count = 5 };
    memcpy(storage + sizeof(*header), &body, sizeof(body));
    for (int index = 0; index < 5; index++) {
        mach_msg_port_descriptor_t descriptor = {0};
        descriptor.name = ports[index]; descriptor.disposition = MACH_MSG_TYPE_COPY_SEND; descriptor.type = MACH_MSG_PORT_DESCRIPTOR;
        memcpy(storage + sizeof(*header) + sizeof(body) + index * sizeof(descriptor), &descriptor, sizeof(descriptor));
    }
    uint32_t version = htonl(4), length = htonl((uint32_t)count);
    memcpy(storage + metadata, &version, 4); memcpy(storage + metadata + 4, &length, 4);
    if (fread(storage + metadata + 8, 1, (size_t)count, file) != (size_t)count) return 25;
    fclose(file);
    kern_return_t result = mach_msg(header, MACH_SEND_MSG | MACH_SEND_TIMEOUT, header->msgh_size, 0, MACH_PORT_NULL, 5000, MACH_PORT_NULL);
    free(storage);
    for (int index = 0; index < 5; index++) mach_port_deallocate(mach_task_self(), ports[index]);
    return result == KERN_SUCCESS ? 0 : 26;
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
        if (strcmp(argv[3], "control")) return 34;
        int error = send_control(endpoint, argv[2]); if (error) return error;
    } else if (argc == 3) {
        int error = send_io(endpoint, argv[2]);
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
    struct pollfd control = { .fd = STDIN_FILENO, .events = POLLIN };
    if (poll(&control, 1, 30000) <= 0) return 5;
    char byte;
    ssize_t received = read(STDIN_FILENO, &byte, 1);
    if (first) {
        if (received == 0) return 0;
        if (received != 1 || byte != 'x') return 6;
        execl(argv[0], argv[0], "second", (char *)NULL);
        return 7;
    }
    return received == 0 ? 0 : 8;
}
