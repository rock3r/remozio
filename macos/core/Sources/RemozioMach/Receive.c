#include "RemozioMach.h"
#include <bsm/libbsm.h>
#include <mach/task_info.h>

kern_return_t remozio_preview_audit(mach_port_t endpoint, mach_msg_timeout_t timeout,
    remozio_mach_preview_t *preview) {
    _Alignas(mach_msg_header_t) unsigned char buffer[sizeof(mach_msg_header_t) + sizeof(mach_msg_trailer_t)] = {0};
    mach_msg_header_t *header = (mach_msg_header_t *)buffer;
    mach_msg_return_t result = mach_msg(header,
        MACH_RCV_MSG | MACH_RCV_LARGE | MACH_RCV_TIMEOUT | MACH_RCV_INTERRUPT |
        MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0) |
        MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT),
        0, sizeof(buffer), endpoint, timeout, MACH_PORT_NULL);
    if (result != MACH_RCV_TOO_LARGE) {
        if (result == MACH_MSG_SUCCESS || (result & ~MACH_MSG_MASK) == MACH_RCV_BODY_ERROR) mach_msg_destroy(header);
        return result == MACH_MSG_SUCCESS ? MACH_RCV_INVALID_DATA : result;
    }
    mach_msg_size_t queuedSize = 0;
    preview->size = header->msgh_size;
    mach_msg_audit_trailer_t trailer = {0};
    mach_msg_type_number_t count = sizeof(trailer);
    preview->sequence = 0;
    result = mach_port_peek(mach_task_self(), endpoint,
        MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0) |
        MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT),
        &preview->sequence, &queuedSize, &preview->identifier, (char *)&trailer, &count);
    if (result != KERN_SUCCESS) return result;
    if (count != sizeof(trailer) || trailer.msgh_trailer_type != MACH_MSG_TRAILER_FORMAT_0)
        return MACH_RCV_INVALID_DATA;
    preview->token = trailer.msgh_audit;
    return KERN_SUCCESS;
}

kern_return_t remozio_discard_message(mach_port_t endpoint) {
    _Alignas(mach_msg_header_t) unsigned char buffer[sizeof(mach_msg_header_t) + sizeof(mach_msg_trailer_t)] = {0};
    mach_msg_header_t *header = (mach_msg_header_t *)buffer;
    mach_msg_return_t result = mach_msg(header, MACH_RCV_MSG | MACH_RCV_TIMEOUT | MACH_RCV_INTERRUPT |
        MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0) |
        MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT),
        0, sizeof(buffer), endpoint, 0, MACH_PORT_NULL);
    if (result == MACH_MSG_SUCCESS || (result & ~MACH_MSG_MASK) == MACH_RCV_BODY_ERROR) mach_msg_destroy(header);
    return result;
}

kern_return_t remozio_receive_audit(mach_msg_header_t *buffer, mach_msg_size_t capacity,
    mach_port_t endpoint, mach_msg_timeout_t timeout) {
    mach_msg_return_t result = mach_msg(buffer, MACH_RCV_MSG | MACH_RCV_TIMEOUT | MACH_RCV_INTERRUPT |
        MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0) |
        MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT),
        0, capacity, endpoint, timeout, MACH_PORT_NULL);
    if ((result & ~MACH_MSG_MASK) == MACH_RCV_BODY_ERROR) {
        mach_msg_destroy(buffer);
    }
    return result;
}
OSStatus remozio_copy_dynamic_signing_information(SecCodeRef code, CFDictionaryRef *information) {
    // Security accepts dynamic code here; Swift imports only the static-code parameter type.
    return SecCodeCopySigningInformation((SecStaticCodeRef)code, kSecCSSigningInformation, information);
}
bool remozio_code_is_adhoc(uint32_t flags) {
    return (flags & kSecCodeSignatureAdhoc) != 0;
}

kern_return_t remozio_pid_audit_token(pid_t pid, audit_token_t *token) {
    if (pid <= 0) return KERN_INVALID_ARGUMENT;
    mach_port_t name = MACH_PORT_NULL;
    kern_return_t result = task_name_for_pid(mach_task_self(), pid, &name);
    if (result != KERN_SUCCESS) return result;
    audit_token_t observed = {0};
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    result = task_info(name, TASK_AUDIT_TOKEN, (task_info_t)&observed, &count);
    mach_port_deallocate(mach_task_self(), name);
    if (result != KERN_SUCCESS) return result;
    if (count != TASK_AUDIT_TOKEN_COUNT || audit_token_to_pid(observed) != pid) return KERN_INVALID_ARGUMENT;
    *token = observed;
    return KERN_SUCCESS;
}
