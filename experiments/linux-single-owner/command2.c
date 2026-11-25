/*
 * Single-owner command fixture for PR2 (issue #988). The owner starts it as the authorized
 * command. It appends one line to the marker file, reports what it inherited as one JSON
 * object of strings, and then does what its file name asks:
 *
 *   cmd-report  nothing more
 *   cmd-sudo    runs "passwd -S <caller>" and "sudo -n true", and reports how each ended
 *   cmd-prompt  runs "sudo true" (a password prompt, but no terminal) and reports how it ended
 *   cmd-hog     allocates memory in 1 MiB steps until the kernel kills it (exit 7 if it
 *               reaches 1 GiB alive)
 *
 * Every helper gets 5 s. sudo can wait for a FIDO touch through PAM even with -n, so a sudo
 * that does not end in time is "inconclusive", not a failure. passwd -S of the caller's own
 * account is the decisive set-user-ID check: shadow-utils exits 0 for the caller's own account
 * with or without euid 0, but it prints the seven /etc/shadow fields only when it could read
 * /etc/shadow, which needs the set-user-ID start with euid 0 (no no_new_privs). Without it, it
 * prints the name and one status field from /etc/passwd ("no-shadow"). passwd -S root is no
 * check: shadow-utils refuses another account by the real UID, with or without euid 0. The
 * command reads its own NoNewPrivs from /proc/self/status.
 *
 * usage: <name> <normal|short|sleep> <marker>; sleep keeps the process alive after the report, for
 * at most SLEEP_SECONDS
 * (for cmd-hog, sleep replaces the allocation, so one image gives the sleeper and the hog).
 * The values are raw for the runner, which publishes closed categories.
 * The exit codes avoid the owner's reserved range 120-123.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define SLEEP_SECONDS 300

static void copy_field(const char *status, const char *key, char *out, size_t size) {
    const char *line = strstr(status, key);
    snprintf(out, size, "missing");
    if (!line) return;
    line += strlen(key);
    while (*line == ' ' || *line == '\t') line++;
    size_t length = strcspn(line, "\n");
    if (length == 0 || length >= size) return;
    for (size_t i = 0; i < length; i++)
        if (!strchr("0123456789abcdef", line[i])) return;
    memcpy(out, line, length);
    out[length] = 0;
}

/* Printable ASCII without quotes or backslashes, else "other". */
static void clean_text(char *text) {
    for (char *c = text; *c; c++)
        if (*c < 0x20 || *c > 0x7e || *c == '"' || *c == '\\') {
            strcpy(text, "other");
            return;
        }
}

static void read_link(const char *path, char *out, size_t size) {
    ssize_t n = readlink(path, out, size - 1);
    if (n <= 0) {
        snprintf(out, size, "missing");
        return;
    }
    out[n] = 0;
    clean_text(out);
}

static void read_label(char *out, size_t size) {
    int fd = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);
    ssize_t n = fd < 0 ? -1 : read(fd, out, size - 1);
    if (fd >= 0) close(fd);
    if (n <= 0) {
        snprintf(out, size, "missing");
        return;
    }
    out[n] = 0;
    out[strcspn(out, "\n")] = 0;
    clean_text(out);
}

static int compare_ints(const void *a, const void *b) {
    int x = *(const int *)a, y = *(const int *)b;
    return (x > y) - (x < y);
}

/* The open descriptors in ascending order, as "0 1 2", without the one that lists them.
 * readdir gives no order, so the numbers are sorted before they are printed. */
static void list_fds(char *out, size_t size) {
    DIR *dir = opendir("/proc/self/fd");
    snprintf(out, size, "missing");
    if (!dir) return;
    int own = dirfd(dir), fds[32], count = 0, many = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.' || atoi(entry->d_name) == own) continue;
        if (count >= 32) {
            many = 1;
            break;
        }
        fds[count++] = atoi(entry->d_name);
    }
    closedir(dir);
    if (many) {
        snprintf(out, size, "many");
        return;
    }
    qsort(fds, (size_t)count, sizeof fds[0], compare_ints);
    size_t used = 0;
    out[0] = 0;
    for (int i = 0; i < count; i++) {
        if (used + 12 >= size) {
            snprintf(out, size, "many");
            return;
        }
        used += (size_t)snprintf(out + used, size - used, "%s%d", used ? " " : "", fds[i]);
    }
}

static long elapsed_ms(const struct timespec *start) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (long)(now.tv_sec - start->tv_sec) * 1000 + (now.tv_nsec - start->tv_nsec) / 1000000;
}

static void pause_ms(long ms) {
    struct timespec pause_time = {0, ms * 1000 * 1000};
    nanosleep(&pause_time, NULL);
}

/* Runs argv with stderr to a pipe (stdout too when both is set, else /dev/null), for at most 5 s.
 * Returns 1 on a timeout (the helper is killed), else 0 with its wait status and the text.
 * After the helper is reaped, the pipe is drained to end of file, so its last line is kept. */
static int run_tool(char *const argv[], int both, int *status, char *text, size_t size) {
    int err[2];
    *status = -1;
    text[0] = 0;
    if (pipe2(err, O_CLOEXEC) != 0) return 0;
    pid_t child = fork();
    if (child < 0) {
        close(err[0]);
        close(err[1]);
        return 0;
    }
    if (child == 0) {
        /* dup2 clears close-on-exec on 1 and 2 only: /dev/null and the pipe's own ends close. */
        int devnull = open("/dev/null", O_WRONLY | O_CLOEXEC);
        if (devnull < 0 || dup2(both ? err[1] : devnull, 1) != 1 || dup2(err[1], 2) != 2) _exit(126);
        execvp(argv[0], argv);
        _exit(127);
    }
    close(err[1]);
    size_t used = 0;
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    int flags = fcntl(err[0], F_GETFL);
    fcntl(err[0], F_SETFL, flags | O_NONBLOCK);
    int done = 0;
    for (;;) {
        int eof = used + 1 >= size; /* a full buffer reads nothing more */
        if (!eof) {
            ssize_t n = read(err[0], text + used, size - 1 - used);
            if (n > 0) {
                used += (size_t)n;
                continue;
            }
            if (n == 0 || (errno != EAGAIN && errno != EINTR)) eof = 1;
        }
        if (!done && waitpid(child, status, WNOHANG) == child) done = 1;
        if (done && eof) break;
        if (elapsed_ms(&start) > 5000) {
            /* Reaped already: a descendant holds the pipe; the helper's status is known. */
            if (done) break;
            /* kill can fail (EPERM) once a set-user-ID helper changed its real UID: wait 1 s at
             * most, then report the timeout without the status. */
            kill(child, SIGKILL);
            for (int i = 0; i < 100 && waitpid(child, status, WNOHANG) != child; i++) pause_ms(10);
            close(err[0]);
            text[used] = 0;
            return 1;
        }
        pause_ms(10);
    }
    close(err[0]);
    text[used] = 0;
    return 0;
}

static const char *run_sudo(int noninteractive) {
    char *const with_n[] = {"sudo", "-n", "true", NULL};
    char *const without_n[] = {"sudo", "true", NULL};
    char text[4096];
    int status;
    if (run_tool(noninteractive ? with_n : without_n, 0, &status, text, sizeof text)) return "inconclusive";
    if (status == -1) return "other";
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) return "allowed";
    if (WIFEXITED(status) && WEXITSTATUS(status) == 127) return "not-found";
    /* sudo.ws and sudo-rs word these differently; both are matched. */
    if (strstr(text, "a password is required") || strstr(text, "interactive authentication is required"))
        return "password-required";
    if (strstr(text, "a terminal is required") || strstr(text, "no tty present")) return "terminal-required";
    if (strstr(text, "no new privileges")) return "no-new-privs";
    if (strstr(text, "effective uid is not 0") || strstr(text, "setuid bit set")) return "not-setuid";
    if (strstr(text, "not in the sudoers") || strstr(text, "not allowed to execute")) return "not-permitted";
    return "other";
}

/* The caller's account name from /etc/passwd (no NSS in a static image), or 0. A file that does
 * not fit the buffer is refused, not cut. */
static int caller_name(char *out, size_t size) {
    static char text[1 << 20];
    int fd = open("/etc/passwd", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    size_t total = 0;
    for (;;) {
        ssize_t n = read(fd, text + total, sizeof text - 1 - total);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            if (n < 0) total = 0;
            break;
        }
        total += (size_t)n;
        if (total == sizeof text - 1) {
            total = 0;
            break;
        }
    }
    close(fd);
    if (total == 0) return 0;
    text[total] = 0;
    char uid[16];
    snprintf(uid, sizeof uid, "%u", (unsigned)getuid());
    for (char *line = strtok(text, "\n"); line; line = strtok(NULL, "\n")) {
        char *first = strchr(line, ':');
        char *second = first ? strchr(first + 1, ':') : NULL;
        char *third = second ? strchr(second + 1, ':') : NULL;
        if (!third || (size_t)(third - second - 1) != strlen(uid) || strncmp(second + 1, uid, strlen(uid))) continue;
        size_t length = (size_t)(first - line);
        if (length == 0 || length >= size) return 0;
        for (size_t i = 0; i < length; i++)
            if (!strchr("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-", line[i])) return 0;
        memcpy(out, line, length);
        out[length] = 0;
        return 1;
    }
    return 0;
}

/* The number of space-separated fields on the line that starts with "<name> ", or 0. */
static int status_fields(char *text, const char *name) {
    size_t length = strlen(name);
    for (char *line = strtok(text, "\n"); line; line = strtok(NULL, "\n")) {
        if (strncmp(line, name, length) != 0 || line[length] != ' ') continue;
        int fields = 1;
        for (char *c = line; *c; c++)
            if (*c == ' ' && c[1] && c[1] != ' ') fields++;
        return fields;
    }
    return 0;
}

/* passwd -S <caller>: "ok" only with the seven /etc/shadow fields, which shadow-utils prints only
 * when the set-user-ID image started with euid 0; "no-shadow" when it exited 0 with the name and
 * one status field from /etc/passwd (no euid 0, for example under no_new_privs). */
static const char *run_passwd(void) {
    char name[64], text[4096];
    if (!caller_name(name, sizeof name)) return "no-user";
    char *const argv[] = {"passwd", "-S", name, NULL};
    int status;
    if (run_tool(argv, 1, &status, text, sizeof text)) return "timeout";
    if (status == -1) return "other";
    if (WIFEXITED(status) && WEXITSTATUS(status) == 127) return "not-found";
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) return "failed";
    int fields = status_fields(text, name);
    return fields == 7 ? "ok" : fields == 2 ? "no-shadow" : "other";
}

/* Every page is written through a volatile pointer and every block stays reachable, so an
 * optimizing compiler cannot drop the allocation (Clang -O2 removed a plain malloc and memset). */
static char *volatile hog_blocks[1024];

static void hog(void) {
    for (int step = 0; step < 1024; step++) {
        char *block = malloc(1 << 20);
        if (!block) break;
        volatile char *page = block;
        for (size_t offset = 0; offset < (1u << 20); offset += 4096) page[offset] = (char)(step | 1);
        hog_blocks[step] = block;
        pause_ms(2);
    }
    _exit(7);
}

int main(int argc, char **argv) {
    if (argc != 3) return 4;
    const char *name = strrchr(argv[0], '/') ? strrchr(argv[0], '/') + 1 : argv[0];
    int marker = open(argv[2], O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (marker < 0 || write(marker, "ran\n", 4) != 4) return 5;
    close(marker);
    if (strcmp(argv[1], "short") == 0) return 0;

    char status[8192] = {0};
    int fd = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
    ssize_t n = fd < 0 ? -1 : read(fd, status, sizeof status - 1);
    if (fd >= 0) close(fd);
    if (n <= 0) return 6;
    status[n] = 0;
    char prm[32], eff[32], inh[32], amb[32], bnd[32], nnp[32], mnt[64], label[256], fds[256];
    copy_field(status, "\nCapPrm:", prm, sizeof prm);
    copy_field(status, "\nCapEff:", eff, sizeof eff);
    copy_field(status, "\nCapInh:", inh, sizeof inh);
    copy_field(status, "\nCapAmb:", amb, sizeof amb);
    copy_field(status, "\nCapBnd:", bnd, sizeof bnd);
    copy_field(status, "\nNoNewPrivs:", nnp, sizeof nnp);
    read_link("/proc/self/ns/mnt", mnt, sizeof mnt);
    read_label(label, sizeof label);
    list_fds(fds, sizeof fds);
    const char *sudo = "not-run", *passwd = "not-run";
    if (strcmp(name, "cmd-sudo") == 0) {
        passwd = run_passwd();
        sudo = run_sudo(1);
    }
    else if (strcmp(name, "cmd-prompt") == 0) sudo = run_sudo(0);
    else if (strcmp(name, "cmd-report") != 0 && strcmp(name, "cmd-hog") != 0) return 8;
    printf("{\"capPrm\":\"%s\",\"capEff\":\"%s\",\"capInh\":\"%s\",\"capAmb\":\"%s\",\"capBnd\":\"%s\","
           "\"noNewPrivs\":\"%s\",\"mntNs\":\"%s\",\"label\":\"%s\",\"fds\":\"%s\",\"sudo\":\"%s\","
           "\"passwd\":\"%s\"}\n",
           prm, eff, inh, amb, bnd, nnp, mnt, label, fds, sudo, passwd);
    fflush(stdout);
    if (strcmp(name, "cmd-hog") == 0 && strcmp(argv[1], "sleep") != 0) hog();
    /* At most SLEEP_SECONDS: a run that is killed before its cleanup leaves no sleeper until reboot.
     * The limit is above the longest case (the runner's timeout is at most 120 s). */
    if (strcmp(argv[1], "sleep") == 0)
        for (int second = 0; second < SLEEP_SECONDS; second++) {
            struct timespec pause_second = {1, 0};
            nanosleep(&pause_second, NULL);
        }
    return 0;
}
