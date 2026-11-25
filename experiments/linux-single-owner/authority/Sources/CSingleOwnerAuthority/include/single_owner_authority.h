#ifndef SINGLE_OWNER_AUTHORITY_H
#define SINGLE_OWNER_AUTHORITY_H

#include <stddef.h>
#include <sys/types.h>

/* Waits up to timeout_ms for input on any of the descriptors. Returns the index of the first
 * ready one, -1 on a timeout and -2 on an error. */
int csa_poll(const int *descriptors, int count, int timeout_ms);

/* accept4 with SOCK_CLOEXEC; -1 on an error. */
int csa_accept(int listener);

/* The peer's UID and PID (SO_PEERCRED) and its pidfd (SO_PEERPIDFD, close-on-exec, owned by the
 * caller). Returns 0, or -1 when any of them is not available. */
int csa_peer(int socket, unsigned *uid, int *pid, int *pidfd);

/* The PID that a pidfd names now (the Pid: line of its fdinfo); -1 when the process is gone. */
int csa_pidfd_pid(int pidfd);

/* 1 while the process of the pidfd runs, 0 once it has exited (a zombie too: the pidfd is
 * readable from the exit on), -1 on an error. */
int csa_pidfd_alive(int pidfd);

/* Field 22 of /proc/<pid>/stat. Returns 0, or -1 on an error and for a zombie or dead process. */
int csa_start_time(int pid, unsigned long long *start);

/* The 36 characters of /proc/sys/kernel/random/boot_id and a terminating zero. Returns 0 or -1. */
int csa_boot_id(char *out, size_t size);

/* Receives one SEQPACKET frame into buffer and terminates it with a zero. Returns the length,
 * 0 at end of file, or -1 on an error or a truncated frame. */
long csa_recv(int socket, char *buffer, size_t size);

/* Sends one frame. Returns 0 or -1. */
int csa_send(int socket, const char *buffer, size_t length);

/* Writes one line to stdout and flushes it. Returns 0 or -1. */
int csa_line(const char *text);

#endif
