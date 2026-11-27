#define _GNU_SOURCE
#include "single_owner_authority.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef SO_PEERPIDFD
#define SO_PEERPIDFD 77
#endif

/* The whole file, terminated with a zero. -1 on a read error and on a file that does not fit. */
static long read_small(const char *path, char *buffer, size_t size) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    size_t used = 0;
    for (;;) {
        if (used + 1 >= size) {
            close(fd);
            return -1;
        }
        ssize_t n = read(fd, buffer + used, size - 1 - used);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) {
            close(fd);
            return -1;
        }
        if (n == 0) break;
        used += (size_t)n;
    }
    close(fd);
    buffer[used] = 0;
    return (long)used;
}

int csa_poll(const int *descriptors, int count, int timeout_ms) {
    struct pollfd ready[64];
    if (count <= 0 || count > 64) return -2;
    for (int i = 0; i < count; i++) ready[i] = (struct pollfd){.fd = descriptors[i], .events = POLLIN};
    int polled;
    do polled = poll(ready, (nfds_t)count, timeout_ms); while (polled < 0 && errno == EINTR);
    if (polled < 0) return -2;
    for (int i = 0; i < count; i++)
        if (ready[i].revents) return i;
    return -1;
}

int csa_accept(int listener) {
    int fd;
    do fd = accept4(listener, NULL, NULL, SOCK_CLOEXEC); while (fd < 0 && errno == EINTR);
    return fd;
}

int csa_peer(int socket, unsigned *uid, int *pid, int *pidfd) {
    struct ucred cred;
    socklen_t length = sizeof cred;
    int descriptor = -1;
    socklen_t pidfd_length = sizeof descriptor;
    if (getsockopt(socket, SOL_SOCKET, SO_PEERCRED, &cred, &length) != 0 || length != sizeof cred) return -1;
    if (getsockopt(socket, SOL_SOCKET, SO_PEERPIDFD, &descriptor, &pidfd_length) != 0 || descriptor < 0) return -1;
    *uid = cred.uid;
    *pid = cred.pid;
    *pidfd = descriptor;
    return 0;
}

int csa_pidfd_pid(int pidfd) {
    char path[64], text[2048];
    snprintf(path, sizeof path, "/proc/self/fdinfo/%d", pidfd);
    if (read_small(path, text, sizeof text) <= 0) return -1;
    const char *line = strstr(text, "\nPid:");
    if (!line) return -1;
    char *end = NULL;
    long value = strtol(line + 5, &end, 10);
    return end && end != line + 5 && value > 0 && value < 0x7fffffff ? (int)value : -1;
}

int csa_pidfd_alive(int pidfd) {
    struct pollfd ready = {.fd = pidfd, .events = POLLIN};
    int polled;
    do polled = poll(&ready, 1, 0); while (polled < 0 && errno == EINTR);
    if (polled < 0 || (ready.revents & (POLLERR | POLLNVAL))) return -1;
    return polled == 0 ? 1 : 0;
}

int csa_start_time(int pid, unsigned long long *start) {
    char path[64], text[4096];
    snprintf(path, sizeof path, "/proc/%d/stat", pid);
    if (read_small(path, text, sizeof text) <= 0) return -1;
    char *field = strrchr(text, ')');
    if (!field || field[1] != ' ' || !field[2]) return -1;
    field += 2; /* field 3, the state */
    if (*field == 'Z' || *field == 'X') return -1; /* exited, not yet reaped */
    for (int index = 3; index < 22; index++) {
        field = strchr(field, ' ');
        if (!field) return -1;
        field++;
    }
    char *end = NULL;
    errno = 0;
    unsigned long long value = strtoull(field, &end, 10);
    if (errno || end == field || (*end != ' ' && *end != '\n')) return -1;
    *start = value;
    return 0;
}

int csa_boot_id(char *out, size_t size) {
    char text[64];
    if (size < 37 || read_small("/proc/sys/kernel/random/boot_id", text, sizeof text) < 36) return -1;
    if (text[36] != '\n' && text[36] != 0) return -1;
    memcpy(out, text, 36);
    out[36] = 0;
    return 0;
}

long csa_recv(int socket, char *buffer, size_t size) {
    if (size < 2) return -1;
    struct iovec io = {.iov_base = buffer, .iov_len = size - 1};
    struct msghdr message = {.msg_iov = &io, .msg_iovlen = 1};
    ssize_t n;
    do n = recvmsg(socket, &message, MSG_CMSG_CLOEXEC); while (n < 0 && errno == EINTR);
    if (n < 0 || (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC))) return -1;
    buffer[n] = 0;
    return (long)n;
}

int csa_send(int socket, const char *buffer, size_t length) {
    ssize_t n;
    do n = send(socket, buffer, length, MSG_NOSIGNAL); while (n < 0 && errno == EINTR);
    return n == (ssize_t)length ? 0 : -1;
}

int csa_line(const char *text) {
    return fputs(text, stdout) >= 0 && fputc('\n', stdout) != EOF && fflush(stdout) == 0 ? 0 : -1;
}
