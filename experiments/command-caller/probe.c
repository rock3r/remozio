#include "message.h"
#include <Security/Security.h>
#include <bsm/libbsm.h>
#include <libproc.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

static int receive_token(mach_port_t endpoint, uint32_t phase, audit_token_t *token) {
    _Alignas(mach_msg_audit_trailer_t) unsigned char buffer[4096] = {0};
    mach_msg_header_t *header = (mach_msg_header_t *)buffer;
    kern_return_t result = mach_msg(header, MACH_RCV_MSG | MACH_RCV_TIMEOUT |
        MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0) | MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT),
        0, sizeof(buffer), endpoint, PROBE_TIMEOUT_MS, MACH_PORT_NULL);
    if (result != KERN_SUCCESS) { fprintf(stderr, "receive failed: %d\n", result); return 0; }
    if ((header->msgh_bits & MACH_MSGH_BITS_COMPLEX) ||
        header->msgh_size != sizeof(struct probe_message) || header->msgh_id != PROBE_MESSAGE_ID ||
        header->msgh_local_port != endpoint || header->msgh_remote_port != MACH_PORT_NULL ||
        header->msgh_voucher_port != MACH_PORT_NULL) {
        mach_msg_destroy(header);
        return 0;
    }
    size_t offset = (header->msgh_size + 3u) & ~3u;
    if (offset > sizeof(buffer) - sizeof(mach_msg_audit_trailer_t)) return 0;
    mach_msg_audit_trailer_t trailer;
    memcpy(&trailer, buffer + offset, sizeof(trailer));
    if (trailer.msgh_trailer_type != MACH_MSG_TRAILER_FORMAT_0 ||
        trailer.msgh_trailer_size != sizeof(trailer)) return 0;
    struct probe_message message;
    memcpy(&message, buffer, sizeof(message));
    audit_token_t forged = {0};
    if (message.version != PROBE_VERSION || message.phase != phase || message.claimed_pid != UINT32_MAX ||
        memcmp(&message.claimed_token, &forged, sizeof(forged))) return 0;
    *token = trailer.msgh_audit;
    return 1;
}

static OSStatus code_for(audit_token_t token, SecCodeRef *code) {
    CFDataRef data = CFDataCreate(kCFAllocatorDefault, (const UInt8 *)&token, sizeof(token));
    if (!data) return errSecAllocate;
    const void *keys[] = {kSecGuestAttributeAudit}, *values[] = {data};
    CFDictionaryRef attributes = CFDictionaryCreate(kCFAllocatorDefault, keys, values, 1,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    OSStatus status = attributes ? SecCodeCopyGuestWithAttributes(NULL, attributes, kSecCSDefaultFlags, code) : errSecAllocate;
    if (attributes) CFRelease(attributes);
    CFRelease(data);
    return status;
}

static int path_matches(audit_token_t token, const char *expected) {
    char path[PROC_PIDPATHINFO_MAXSIZE];
    return proc_pidpath_audittoken(&token, path, sizeof(path)) > 0 && strcmp(path, expected) == 0;
}

static int path_rejected(audit_token_t token) {
    char path[PROC_PIDPATHINFO_MAXSIZE];
    return proc_pidpath_audittoken(&token, path, sizeof(path)) <= 0;
}

static int wait_child(pid_t child, int *status) {
    struct timespec start, now, pause = {.tv_sec = 0, .tv_nsec = 10000000};
    if (clock_gettime(CLOCK_MONOTONIC, &start)) return 0;
    for (;;) {
        pid_t result = waitpid(child, status, WNOHANG);
        if (result == child) return 1;
        if (result < 0 && errno != EINTR) return 0;
        if (clock_gettime(CLOCK_MONOTONIC, &now) || now.tv_sec - start.tv_sec >= 5) return 0;
        nanosleep(&pause, NULL);
    }
}

static int retire_child(pid_t child) {
    int status;
    pid_t result = waitpid(child, &status, WNOHANG);
    if (result == child || (result < 0 && errno == ECHILD)) return 1;
    kill(child, SIGKILL);
    do { result = waitpid(child, &status, 0); } while (result < 0 && errno == EINTR);
    return result == child || (result < 0 && errno == ECHILD);
}

#define OBSERVE(name, expression) do { \
    int observed = !!(expression); \
    printf("\"" name "\":%s,", observed ? "true" : "false"); \
    if (!observed) goto cleanup; \
} while (0)

int main(int argc, char **argv) {
    if (argc != 3 || strlen(argv[2]) != 40 || strspn(argv[2], "0123456789abcdef") != 40) return 1;
    signal(SIGPIPE, SIG_IGN);
    int passed = 0, control[2] = {-1, -1}, attributes_ready = 0, actions_ready = 0;
    pid_t child = -1;
    mach_port_t endpoint = MACH_PORT_NULL;
    posix_spawnattr_t attributes;
    posix_spawn_file_actions_t actions;
    SecCodeRef original = NULL, current = NULL, stale = NULL;
    SecRequirementRef expected = NULL, wrong = NULL;
    CFDictionaryRef signing = NULL;
    char expression[256];
    snprintf(expression, sizeof(expression),
        "identifier \"dev.remozio.experiments.command-caller.peer\" and cdhash H\"%s\"", argv[2]);
    CFStringRef requirement_text = CFStringCreateWithCString(kCFAllocatorDefault, expression, kCFStringEncodingUTF8);
    if (!requirement_text) return 2;
    OSStatus parsed = SecRequirementCreateWithString(requirement_text, kSecCSDefaultFlags, &expected);
    CFRelease(requirement_text);
    if (parsed != errSecSuccess || SecRequirementCreateWithString(
        CFSTR("identifier \"dev.remozio.experiments.command-caller.peer\" and cdhash H\"0000000000000000000000000000000000000000\""),
        kSecCSDefaultFlags, &wrong) != errSecSuccess) goto cleanup;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &endpoint) != KERN_SUCCESS ||
        mach_port_insert_right(mach_task_self(), endpoint, endpoint, MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS ||
        pipe(control)) goto cleanup;
    if (posix_spawnattr_init(&attributes)) goto cleanup;
    attributes_ready = 1;
    if (posix_spawn_file_actions_init(&actions)) goto cleanup;
    actions_ready = 1;
    if (posix_spawnattr_setspecialport_np(&attributes, endpoint, TASK_BOOTSTRAP_PORT) ||
        posix_spawnattr_setflags(&attributes, POSIX_SPAWN_CLOEXEC_DEFAULT) ||
        posix_spawn_file_actions_adddup2(&actions, control[0], STDIN_FILENO) ||
        posix_spawn_file_actions_addclose(&actions, control[1]) ||
        posix_spawn_file_actions_addclose(&actions, control[0])) goto cleanup;
    char *arguments[] = {argv[1], "first", NULL}, *environment[] = {NULL};
    pid_t spawned;
    if (posix_spawn(&spawned, argv[1], &actions, &attributes, arguments, environment)) goto cleanup;
    child = spawned;
    close(control[0]); control[0] = -1;
    printf("{");
    audit_token_t first, second;
    OBSERVE("first_message_has_audit_trailer", receive_token(endpoint, 1, &first));
    OBSERVE("kernel_pid_matches_spawned_peer", audit_token_to_pid(first) == child);
    OBSERVE("kernel_uid_matches", audit_token_to_euid(first) == geteuid());
    OBSERVE("forged_payload_pid_ignored", (uint32_t)audit_token_to_pid(first) != UINT32_MAX);
    audit_token_t forged = {0};
    OBSERVE("forged_payload_token_ignored", memcmp(&first, &forged, sizeof(first)) != 0);
    OBSERVE("audit_bound_path_matches", path_matches(first, argv[1]));
    OBSERVE("audit_bound_code_available", code_for(first, &original) == errSecSuccess);
    OBSERVE("signing_information_available", SecCodeCopySigningInformation(original, kSecCSSigningInformation, &signing) == errSecSuccess);
    OBSERVE("pinned_fixture_code_accepted", SecCodeCheckValidity(original, kSecCSDefaultFlags, expected) == errSecSuccess);
    OBSERVE("wrong_code_hash_rejected", SecCodeCheckValidity(original, kSecCSDefaultFlags, wrong) != errSecSuccess);
    if (write(control[1], "x", 1) != 1) goto cleanup;
    OBSERVE("second_message_has_audit_trailer", receive_token(endpoint, 2, &second));
    OBSERVE("exec_preserves_pid", audit_token_to_pid(second) == child);
    OBSERVE("exec_changes_incarnation", audit_token_to_pidversion(first) != audit_token_to_pidversion(second));
    OBSERVE("old_token_path_rejected_while_peer_lives", kill(child, 0) == 0 && path_rejected(first));
    OBSERVE("new_token_path_matches", path_matches(second, argv[1]));
    OBSERVE("old_token_code_lookup_rejected", code_for(first, &stale) != errSecSuccess);
    OBSERVE("retained_old_code_rejected", SecCodeCheckValidity(original, kSecCSDefaultFlags, expected) != errSecSuccess);
    OBSERVE("new_token_code_available", code_for(second, &current) == errSecSuccess);
    OBSERVE("new_code_matches_pin", SecCodeCheckValidity(current, kSecCSDefaultFlags, expected) == errSecSuccess);
    close(control[1]); control[1] = -1;
    int status;
    OBSERVE("peer_exit_observed", wait_child(child, &status));
    child = -1;
    OBSERVE("peer_exited_cleanly", WIFEXITED(status) && WEXITSTATUS(status) == 0);
    OBSERVE("exited_token_path_rejected", path_rejected(second));
    OBSERVE("retained_exited_code_rejected", SecCodeCheckValidity(current, kSecCSDefaultFlags, expected) != errSecSuccess);
    printf("\"passed\":true}\n");
    passed = 1;
cleanup:
    if (control[0] >= 0) close(control[0]);
    if (control[1] >= 0) close(control[1]);
    if (child > 0) fprintf(stderr, "peer_retired=%s\n", retire_child(child) ? "true" : "false");
    if (actions_ready) posix_spawn_file_actions_destroy(&actions);
    if (attributes_ready) posix_spawnattr_destroy(&attributes);
    if (endpoint != MACH_PORT_NULL) {
        mach_port_mod_refs(mach_task_self(), endpoint, MACH_PORT_RIGHT_RECEIVE, -1);
        mach_port_deallocate(mach_task_self(), endpoint);
    }
    if (signing) CFRelease(signing);
    if (stale) CFRelease(stale);
    if (original) CFRelease(original);
    if (current) CFRelease(current);
    if (expected) CFRelease(expected);
    if (wrong) CFRelease(wrong);
    return passed ? 0 : 3;
}
