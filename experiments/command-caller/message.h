#ifndef REMOZIO_CALLER_MESSAGE_H
#define REMOZIO_CALLER_MESSAGE_H
#include <mach/mach.h>
#include <mach/message.h>
#include <stdint.h>

#define PROBE_MESSAGE_ID 0x524d01
#define PROBE_VERSION 1
#define PROBE_TIMEOUT_MS 5000
struct probe_message {
    mach_msg_header_t header;
    uint32_t version;
    uint32_t phase;
    uint32_t claimed_pid;
    audit_token_t claimed_token;
};
#endif
