/*
 * Descriptor shim for the single-owner experiment (issue #988, PR2). A transient systemd
 * unit cannot inherit the runner's descriptors, so the unit's ExecStart is this shim. It
 * connects to the runner's rendezvous socket, receives four descriptors, places them at
 * fixed numbers and replaces itself with the owner image. The PID, the cgroup, the unit
 * options and the ambient capabilities stay those of the unit's main process: execve of an
 * image without file capabilities keeps the ambient set, and the shim never changes it.
 *
 * usage: fdshim <rendezvous-socket> <owner-image> <owner arguments...>
 *
 * The runner sends one SEQPACKET message "FDS\n" with SCM_RIGHTS, in this order: the
 * owner's stdout, the frontend listener, the control socket and the restart log. They
 * become 1, 3, 4 and 5; the runner passes "3", "4" and "5" in the owner arguments. Every
 * other descriptor above 2 is closed. The environment of the owner is empty.
 *
 * Exit codes (before execve only): 4 usage, 11 rendezvous failure, 12 protocol failure,
 * 13 descriptor failure, 14 execve failure.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

#define RECEIVED 4

int main(int argc, char **argv) {
    if (argc < 3 || strlen(argv[1]) >= sizeof(((struct sockaddr_un *)0)->sun_path)) return 4;
    int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    strcpy(address.sun_path, argv[1]);
    if (fd < 0 || connect(fd, (struct sockaddr *)&address, sizeof address) != 0) return 11;
    static const char hello[] = "SHIM\n";
    if (send(fd, hello, sizeof hello - 1, MSG_NOSIGNAL) != (ssize_t)(sizeof hello - 1)) return 11;

    char text[8] = {0};
    /* The union aligns the buffer for struct cmsghdr, as cmsg(3) asks. */
    union {
        char buffer[CMSG_SPACE(RECEIVED * sizeof(int))];
        struct cmsghdr align;
    } control;
    memset(&control, 0, sizeof control);
    struct iovec iov = {text, sizeof text - 1};
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = control.buffer,
                             .msg_controllen = sizeof control.buffer};
    ssize_t got = recvmsg(fd, &message, MSG_CMSG_CLOEXEC);
    struct cmsghdr *header = got > 0 ? CMSG_FIRSTHDR(&message) : NULL;
    if (got != 4 || memcmp(text, "FDS\n", 4) || (message.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) || !header ||
        header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS ||
        header->cmsg_len != CMSG_LEN(RECEIVED * sizeof(int)) || CMSG_NXTHDR(&message, header))
        return 12;
    int received[RECEIVED], high[RECEIVED];
    memcpy(received, CMSG_DATA(header), sizeof received);
    close(fd);

    /* Above every target first, then into place; close everything else above 2. */
    for (int i = 0; i < RECEIVED; i++)
        if ((high[i] = fcntl(received[i], F_DUPFD_CLOEXEC, 64)) < 0) return 13;
    static const int target[RECEIVED] = {1, 3, 4, 5};
    for (int i = 0; i < RECEIVED; i++)
        if (dup2(high[i], target[i]) != target[i]) return 13;
    if (syscall(SYS_close_range, 6, ~0U, 0) != 0) return 13;

    char *const envp[] = {NULL};
    execve(argv[2], argv + 2, envp);
    return 14;
}
