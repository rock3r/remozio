#ifndef REMOZIO_MACH_H
#define REMOZIO_MACH_H
#include <mach/mach.h>
#include <Security/Security.h>
#include <stdbool.h>
kern_return_t remozio_receive_audit(mach_msg_header_t * _Nonnull buffer, mach_msg_size_t capacity,
    mach_port_t endpoint, mach_msg_timeout_t timeout);
OSStatus remozio_copy_dynamic_signing_information(SecCodeRef _Nonnull code,
    CFDictionaryRef _Nullable * _Nonnull CF_RETURNS_RETAINED information);
bool remozio_code_is_adhoc(uint32_t flags);
#endif
