#include "RemozioMach.h"
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
