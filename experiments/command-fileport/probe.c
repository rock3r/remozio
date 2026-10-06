#include <mach/mach.h>
#include <bsm/libbsm.h>
#include <sys/fileport.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <spawn.h>
#include <poll.h>
#include <util.h>
#include <termios.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#define MESSAGE_ID 0x524d0501
struct message {
    mach_msg_header_t header;
    mach_msg_body_t body;
    mach_msg_port_descriptor_t source;
    uint32_t claimed_kind;
};

static int wait_control(void) {
    struct pollfd control = {.fd = STDIN_FILENO, .events = POLLIN};
    if (poll(&control, 1, 10000) <= 0) return 1;
    char byte;
    return read(STDIN_FILENO, &byte, 1) == 0 ? 0 : 1;
}

static int peer(const char *mode) {
    mach_port_t endpoint = MACH_PORT_NULL, source = MACH_PORT_NULL;
    if (task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &endpoint) != KERN_SUCCESS) return 1;
    if (!strcmp(mode, "silent")) { mach_port_deallocate(mach_task_self(), endpoint); return wait_control(); }
    if (!strcmp(mode, "ordinary_port")) {
        if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &source) != KERN_SUCCESS ||
            mach_port_insert_right(mach_task_self(), source, source, MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS) return 2;
    } else if (fileport_makeport(3, &source)) return 3;
    close(3);
    struct message message = {0};
    message.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
    message.header.msgh_size = sizeof(message);
    message.header.msgh_remote_port = endpoint;
    message.header.msgh_id = MESSAGE_ID;
    message.body.msgh_descriptor_count = 1;
    message.source.name = source;
    message.source.disposition = MACH_MSG_TYPE_COPY_SEND;
    message.source.type = MACH_MSG_PORT_DESCRIPTOR;
    message.claimed_kind = S_IFREG;
    kern_return_t result = mach_msg(&message.header, MACH_SEND_MSG | MACH_SEND_TIMEOUT,
        sizeof(message), 0, MACH_PORT_NULL, 1000, MACH_PORT_NULL);
    mach_port_deallocate(mach_task_self(), source);
    mach_port_deallocate(mach_task_self(), endpoint);
    if (result != KERN_SUCCESS) return 4;
    int status = wait_control();
    if (!strcmp(mode, "ordinary_port")) mach_port_mod_refs(mach_task_self(), source, MACH_PORT_RIGHT_RECEIVE, -1);
    return status;
}

static int reap(pid_t child, int *status) {
    struct timespec start, now, pause = {.tv_nsec = 10000000};
    if (clock_gettime(CLOCK_MONOTONIC, &start)) return 0;
    do {
        pid_t result = waitpid(child, status, WNOHANG);
        if (result == child) return 1;
        if (result < 0 && errno != EINTR) return 0;
        if (clock_gettime(CLOCK_MONOTONIC, &now) || now.tv_sec - start.tv_sec >= 5) return 0;
        nanosleep(&pause, NULL);
    } while (1);
}

static int start_peer(const char *program, const char *mode, int source, mach_port_t endpoint, pid_t *child, int *control) {
    int pipe_fds[2];
    if (pipe(pipe_fds)) return 0;
    // Use a private high descriptor so the control pipe cannot alias the source destination.
    int held = fcntl(source, F_DUPFD_CLOEXEC, 10);
    if (held < 0) { close(pipe_fds[0]); close(pipe_fds[1]); return 0; }
    posix_spawnattr_t attributes;
    posix_spawn_file_actions_t actions;
    int attributes_ready = 0, actions_ready = 0, success = 0;
    if (posix_spawnattr_init(&attributes)) goto done;
    attributes_ready = 1;
    if (posix_spawn_file_actions_init(&actions)) goto done;
    actions_ready = 1;
    if (posix_spawnattr_setspecialport_np(&attributes, endpoint, TASK_BOOTSTRAP_PORT) ||
        posix_spawnattr_setflags(&attributes, POSIX_SPAWN_CLOEXEC_DEFAULT) ||
        posix_spawn_file_actions_adddup2(&actions, pipe_fds[0], STDIN_FILENO) ||
        posix_spawn_file_actions_addclose(&actions, pipe_fds[0]) ||
        posix_spawn_file_actions_addclose(&actions, pipe_fds[1]) ||
        posix_spawn_file_actions_adddup2(&actions, held, 3) ||
        posix_spawn_file_actions_addclose(&actions, held)) goto done;
    char *arguments[] = {(char *)program, "--peer", (char *)mode, NULL}, *environment[] = {NULL};
    if (posix_spawn(child, program, &actions, &attributes, arguments, environment)) goto done;
    *control = pipe_fds[1]; success = 1;
done:
    if (actions_ready) posix_spawn_file_actions_destroy(&actions);
    if (attributes_ready) posix_spawnattr_destroy(&attributes);
    close(held); close(pipe_fds[0]);
    if (!success) close(pipe_fds[1]);
    return success;
}

static int read_exact(int fd, const char *expected, size_t size) {
    char buffer[32]; size_t used = 0;
    if (size > sizeof(buffer)) return 0;
    while (used < size) {
        struct pollfd input = {.fd = fd, .events = POLLIN};
        if (poll(&input, 1, 1000) <= 0) return 0;
        ssize_t count = read(fd, buffer + used, size - used);
        if (count <= 0) return 0;
        used += (size_t)count;
    }
    return !memcmp(buffer, expected, size);
}

#define REQUIRE(expression) do { if (!(expression)) goto done; } while (0)
static int run_case(const char *program, const char *kind, const char *path) {
    int source = -1, companion = -1, control = -1, imported = -1, passed = 0;
    pid_t child = -1; mach_port_t endpoint = MACH_PORT_NULL;
    _Alignas(mach_msg_audit_trailer_t) unsigned char buffer[512] = {0};
    mach_msg_header_t *header = (mach_msg_header_t *)buffer;
    int received = 0;
    if (!strcmp(kind, "file")) {
        source = open(path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        REQUIRE(source >= 0 && write(source, "012345", 6) == 6 && lseek(source, 2, SEEK_SET) == 2);
    } else if (!strcmp(kind, "directory")) source = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    else if (!strcmp(kind, "tty")) {
        REQUIRE(openpty(&companion, &source, NULL, NULL, NULL) == 0);
        struct termios settings;
        REQUIRE(tcgetattr(source, &settings) == 0);
        cfmakeraw(&settings);
        REQUIRE(tcsetattr(source, TCSANOW, &settings) == 0);
    } else if (!strcmp(kind, "socket")) {
        int pair[2]; REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
        source = pair[0]; companion = pair[1];
        REQUIRE(write(companion, "before", 6) == 6);
    } else if (!strcmp(kind, "pipe") || !strcmp(kind, "writeonly")) {
        int pair[2]; REQUIRE(pipe(pair) == 0);
        source = pair[0]; companion = pair[1];
        if (!strcmp(kind, "writeonly")) { source = pair[1]; companion = pair[0]; }
        else REQUIRE(write(companion, "before", 6) == 6);
    } else source = open("/dev/null", O_RDONLY | O_CLOEXEC);
    REQUIRE(source >= 0);
    struct stat original; REQUIRE(fstat(source, &original) == 0);
    REQUIRE(mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &endpoint) == KERN_SUCCESS &&
        mach_port_insert_right(mach_task_self(), endpoint, endpoint, MACH_MSG_TYPE_MAKE_SEND) == KERN_SUCCESS);
    REQUIRE(start_peer(program, kind, source, endpoint, &child, &control));
    close(source); source = -1;
    mach_msg_return_t result = mach_msg(header, MACH_RCV_MSG | MACH_RCV_TIMEOUT | MACH_RCV_INTERRUPT |
        MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0) | MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT),
        0, sizeof(buffer), endpoint, 1000, MACH_PORT_NULL);
    if ((result & ~MACH_MSG_MASK) == MACH_RCV_BODY_ERROR) mach_msg_destroy(header);
    if (!strcmp(kind, "silent")) { REQUIRE(result == MACH_RCV_TIMED_OUT); goto finish_peer; }
    REQUIRE(result == KERN_SUCCESS); received = 1;
    REQUIRE(header->msgh_size == sizeof(struct message) && header->msgh_id == MESSAGE_ID &&
        header->msgh_bits & MACH_MSGH_BITS_COMPLEX && header->msgh_local_port == endpoint &&
        header->msgh_remote_port == MACH_PORT_NULL && header->msgh_voucher_port == MACH_PORT_NULL);
    struct message *message = (struct message *)buffer;
    REQUIRE(message->body.msgh_descriptor_count == 1 && message->source.type == MACH_MSG_PORT_DESCRIPTOR &&
        message->source.disposition == MACH_MSG_TYPE_PORT_SEND);
    mach_msg_audit_trailer_t trailer;
    memcpy(&trailer, buffer + ((header->msgh_size + 3u) & ~3u), sizeof(trailer));
    REQUIRE(trailer.msgh_trailer_type == MACH_MSG_TRAILER_FORMAT_0 && trailer.msgh_trailer_size == sizeof(trailer) &&
        audit_token_to_pid(trailer.msgh_audit) == child && audit_token_to_euid(trailer.msgh_audit) == geteuid());
    imported = fileport_makefd(message->source.name);
    if (!strcmp(kind, "ordinary_port")) {
        REQUIRE(imported < 0 && errno == EINVAL);
        mach_msg_destroy(header); received = 0; goto finish_peer;
    }
    REQUIRE(imported >= 0);
    mach_msg_destroy(header); received = 0;
    struct stat actual; REQUIRE(fstat(imported, &actual) == 0 && actual.st_dev == original.st_dev &&
        actual.st_ino == original.st_ino && actual.st_mode == original.st_mode && fcntl(imported, F_GETFD) & FD_CLOEXEC);
    if (!strcmp(kind, "file")) {
        REQUIRE(S_ISREG(actual.st_mode) && lseek(imported, 0, SEEK_CUR) == 2);
        REQUIRE(read_exact(imported, "2345", 4));
    } else if (!strcmp(kind, "directory")) REQUIRE(S_ISDIR(actual.st_mode));
    else if (!strcmp(kind, "pipe") || !strcmp(kind, "socket")) {
        int available = 0;
        REQUIRE(ioctl(imported, FIONREAD, &available) == 0 && available == 6);
        REQUIRE(write(companion, "after", 5) == 5);
        REQUIRE(read_exact(imported, "beforeafter", 11));
    } else if (!strcmp(kind, "tty")) {
        REQUIRE(S_ISCHR(actual.st_mode) && isatty(imported));
        REQUIRE(write(companion, "later", 5) == 5 && read_exact(imported, "later", 5));
        struct winsize requested = {.ws_row = 40, .ws_col = 120}, observed = {0};
        REQUIRE(ioctl(companion, TIOCSWINSZ, &requested) == 0 && ioctl(imported, TIOCGWINSZ, &observed) == 0 &&
            observed.ws_row == requested.ws_row && observed.ws_col == requested.ws_col);
    } else if (!strcmp(kind, "writeonly")) {
        REQUIRE((fcntl(imported, F_GETFL) & O_ACCMODE) == O_WRONLY);
        char byte; REQUIRE(read(imported, &byte, 1) < 0 && errno == EBADF);
    } else {
        REQUIRE(S_ISCHR(actual.st_mode) && !isatty(imported));
        char byte; REQUIRE(read(imported, &byte, 1) == 0);
    }
    if (strcmp(kind, "file")) REQUIRE((actual.st_mode & S_IFMT) != message->claimed_kind);
finish_peer:
    close(control); control = -1;
    int status; REQUIRE(reap(child, &status)); child = -1;
    REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    if (imported >= 0) {
        REQUIRE(fcntl(imported, F_GETFD) >= 0);
        close(imported);
        REQUIRE(fcntl(imported, F_GETFD) < 0 && errno == EBADF);
        imported = -1;
    }
    passed = 1;
done:
    if (received) mach_msg_destroy(header);
    if (source >= 0) close(source);
    if (companion >= 0) close(companion);
    if (control >= 0) close(control);
    if (imported >= 0) close(imported);
    if (child > 0) {
        int status;
        if (!reap(child, &status)) {
            pid_t owned;
            do { owned = waitpid(child, &status, WNOHANG); } while (owned < 0 && errno == EINTR);
            if (owned == 0) { kill(child, SIGKILL); while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {} }
        }
    }
    if (endpoint != MACH_PORT_NULL) {
        mach_port_mod_refs(mach_task_self(), endpoint, MACH_PORT_RIGHT_RECEIVE, -1);
        mach_port_deallocate(mach_task_self(), endpoint);
    }
    return passed;
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    if (argc == 3 && !strcmp(argv[1], "--peer")) return peer(argv[2]);
    if (argc != 3) return 1;
    const char *kinds[] = {"file", "directory", "pipe", "socket", "tty", "null", "writeonly", "ordinary_port", "silent"};
    const char *observations[] = {"file_identity_offset_and_lifetime", "directory_identity_and_lifetime",
        "pipe_queued_and_later_input", "socket_queued_and_later_input", "pty_input_and_resize",
        "null_input", "write_only_input_rejected", "ordinary_port_rejected", "silent_peer_reaped"};
    printf("{");
    for (size_t index = 0; index < sizeof(kinds) / sizeof(kinds[0]); ++index) {
        int passed = run_case(argv[0], kinds[index], !strcmp(kinds[index], "file") ? argv[1] : argv[2]);
        printf("\"%s\":%s,", observations[index], passed ? "true" : "false"); fflush(stdout);
        if (!passed) { printf("\"passed\":false}\n"); return 2; }
    }
    printf("\"passed\":true}\n"); return 0;
}
