#include "include/RemozioCommandMonitorProtocol.h"
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <string.h>
#include <sys/wait.h>
static uint32_t word(const unsigned char *bytes) {
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) | ((uint32_t)bytes[2] << 8) | bytes[3];
}
static void put_word(unsigned char *bytes, uint32_t value) {
    for (unsigned index = 0; index < 4; ++index) bytes[index] = (unsigned char)(value >> ((3U - index) * 8));
}
static uint64_t wide(const unsigned char *bytes) { return ((uint64_t)word(bytes) << 32) | word(bytes + 4); }
static void put_wide(unsigned char *bytes, uint64_t value) { put_word(bytes, (uint32_t)(value >> 32)); put_word(bytes + 4, (uint32_t)value); }
static bool final_wait_status(uint32_t detail) {
    if (detail > 0xffff) return false;
    int status = (int)detail;
    if (WIFEXITED(status)) return (status & 0xff) == 0;
    if (WIFSIGNALED(status)) return (status & ~0xff) == 0 && WTERMSIG(status) > 0 && WTERMSIG(status) < NSIG;
    return false;
}
static int valid(const remozio_monitor_record_t *record) {
    if (!record || !record->sequence || record->target_pid > INT_MAX || record->detail > INT_MAX ||
        (record->flags & ~(REMOZIO_MONITOR_STOPPED | REMOZIO_MONITOR_TRACING_KNOWN | REMOZIO_MONITOR_TRACED | REMOZIO_MONITOR_BIRTH_KNOWN | REMOZIO_MONITOR_TARGET_RELEASE_ATTEMPTED))) return EPROTO;
    if ((record->flags & REMOZIO_MONITOR_TARGET_RELEASE_ATTEMPTED) && !record->target_pid) return EPROTO;
    if (record->flags & REMOZIO_MONITOR_BIRTH_KNOWN) {
        if (!record->target_pid || !record->birth_seconds || record->birth_microseconds >= 1000000) return EPROTO;
    } else if (record->birth_seconds || record->birth_microseconds) return EPROTO;
    switch (record->tag) {
    case REMOZIO_MONITOR_PREPARED:
        if (!record->target_pid || record->detail || record->stop_code || record->job_revision ||
            (record->flags & ~REMOZIO_MONITOR_BIRTH_KNOWN)) return EPROTO;
        break;
    case REMOZIO_MONITOR_JOB_STATE:
        if (!record->target_pid || !record->job_revision || !(record->flags & REMOZIO_MONITOR_TARGET_RELEASE_ATTEMPTED)) return EPROTO;
        if (record->flags & REMOZIO_MONITOR_STOPPED) {
            if (!record->detail || record->detail >= NSIG || (record->stop_code != CLD_STOPPED && record->stop_code != CLD_TRAPPED)) return EPROTO;
            if ((record->flags & REMOZIO_MONITOR_TRACED) && !(record->flags & REMOZIO_MONITOR_TRACING_KNOWN)) return EPROTO;
        } else if (record->detail || record->stop_code || (record->flags & (REMOZIO_MONITOR_TRACING_KNOWN | REMOZIO_MONITOR_TRACED))) return EPROTO;
        break;
    case REMOZIO_MONITOR_TARGET_REAPED:
        if (!record->target_pid || record->stop_code || (record->flags & ~(REMOZIO_MONITOR_BIRTH_KNOWN | REMOZIO_MONITOR_TARGET_RELEASE_ATTEMPTED)) ||
            !final_wait_status(record->detail)) return EPROTO;
        break;
    case REMOZIO_MONITOR_FAILURE:
        if (!record->detail || record->stop_code || record->job_revision || (record->flags & ~(REMOZIO_MONITOR_BIRTH_KNOWN | REMOZIO_MONITOR_TARGET_RELEASE_ATTEMPTED))) return EPROTO;
        break;
    default: return EPROTO;
    }
    return 0;
}
int remozio_monitor_record_encode(const remozio_monitor_record_t *record, unsigned char bytes[REMOZIO_MONITOR_RECORD_BYTES]) {
    if (!bytes) return EINVAL;
    int error = valid(record); if (error) return error;
    memset(bytes, 0, REMOZIO_MONITOR_RECORD_BYTES);
    put_word(bytes, 0x524d4d31); put_word(bytes + 4, REMOZIO_MONITOR_WIRE_VERSION); put_word(bytes + 8, record->tag);
    put_word(bytes + 12, record->flags); put_word(bytes + 16, record->target_pid); put_word(bytes + 20, record->detail); put_word(bytes + 24, record->stop_code);
    put_wide(bytes + 32, record->sequence); put_wide(bytes + 40, record->job_revision); put_wide(bytes + 48, record->birth_seconds); put_wide(bytes + 56, record->birth_microseconds);
    return 0;
}
int remozio_monitor_record_decode(const void *input, size_t count, remozio_monitor_record_t *record) {
    if (!record) return EINVAL;
    memset(record, 0, sizeof(*record));
    if (!input || count != REMOZIO_MONITOR_RECORD_BYTES) return EPROTO;
    const unsigned char *bytes = input;
    if (word(bytes) != 0x524d4d31 || word(bytes + 4) != REMOZIO_MONITOR_WIRE_VERSION || word(bytes + 28)) return EPROTO;
    remozio_monitor_record_t candidate = {.tag = word(bytes + 8), .flags = word(bytes + 12), .target_pid = word(bytes + 16),
        .detail = word(bytes + 20), .stop_code = word(bytes + 24), .sequence = wide(bytes + 32), .job_revision = wide(bytes + 40),
        .birth_seconds = wide(bytes + 48), .birth_microseconds = wide(bytes + 56)};
    int error = valid(&candidate); if (error) return error;
    *record = candidate; return 0;
}

void remozio_monitor_stream_init(remozio_monitor_stream_t *stream) {
    if (stream) memset(stream, 0, sizeof(*stream));
}
int remozio_monitor_stream_note_release(remozio_monitor_stream_t *stream) {
    if (!stream) return EINVAL;
    if (stream->release_attempted) return EALREADY;
    if (!stream->prepared || stream->failed || stream->reaped) return EBUSY;
    stream->release_attempted = true;
    return 0;
}
int remozio_monitor_stream_accept(remozio_monitor_stream_t *stream, const remozio_monitor_record_t *record) {
    if (!stream || !record) return EINVAL;
    if (valid(record) || stream->reaped || stream->latest.sequence == UINT64_MAX ||
        record->sequence != stream->latest.sequence + 1) return EPROTO;
    bool target_release = (record->flags & REMOZIO_MONITOR_TARGET_RELEASE_ATTEMPTED) != 0;
    if ((target_release && !stream->release_attempted) || (!target_release && stream->target_release_attempted)) return EPROTO;
    if (stream->latest.target_pid && (record->target_pid != stream->latest.target_pid ||
        !!(record->flags & REMOZIO_MONITOR_BIRTH_KNOWN) != !!(stream->latest.flags & REMOZIO_MONITOR_BIRTH_KNOWN) ||
        record->birth_seconds != stream->latest.birth_seconds || record->birth_microseconds != stream->latest.birth_microseconds)) return EPROTO;
    remozio_monitor_stream_t next = *stream;
    next.target_release_attempted = target_release;
    switch (record->tag) {
    case REMOZIO_MONITOR_PREPARED:
        if (stream->latest.sequence || stream->prepared || stream->failed) return EPROTO;
        next.prepared = true;
        break;
    case REMOZIO_MONITOR_JOB_STATE:
        if (!stream->prepared || stream->failed || !stream->release_attempted || record->job_revision <= stream->last_job_revision) return EPROTO;
        next.last_job_revision = record->job_revision;
        break;
    case REMOZIO_MONITOR_TARGET_REAPED:
        if (!stream->latest.target_pid || (!stream->prepared && !stream->failed) || record->job_revision < stream->last_job_revision) return EPROTO;
        next.reaped = true;
        next.last_job_revision = record->job_revision;
        break;
    case REMOZIO_MONITOR_FAILURE:
        if (stream->failed) return EPROTO;
        next.failed = true;
        next.failure_error = record->detail;
        break;
    default: return EPROTO;
    }
    next.latest = *record;
    *stream = next;
    return 0;
}

static int valid_control(const remozio_monitor_control_t *control) {
    if (!control || !control->sequence) return EPROTO;
    if (control->tag == REMOZIO_MONITOR_SIGNAL) return control->signal > 0 && control->signal < NSIG ? 0 : EPROTO;
    if (control->tag == REMOZIO_MONITOR_CANCEL) return control->signal == 0 ? 0 : EPROTO;
    return EPROTO;
}
int remozio_monitor_control_encode(const remozio_monitor_control_t *control, unsigned char bytes[REMOZIO_MONITOR_CONTROL_BYTES]) {
    if (!bytes) return EINVAL;
    int error = valid_control(control); if (error) return error;
    memset(bytes, 0, REMOZIO_MONITOR_CONTROL_BYTES);
    put_word(bytes, 0x524d4b31); put_word(bytes + 4, REMOZIO_MONITOR_WIRE_VERSION);
    put_word(bytes + 8, control->tag); put_word(bytes + 12, control->signal); put_wide(bytes + 16, control->sequence);
    return 0;
}
int remozio_monitor_control_decode(const void *input, size_t count, remozio_monitor_control_t *control) {
    if (!control) return EINVAL;
    memset(control, 0, sizeof(*control));
    if (!input || count != REMOZIO_MONITOR_CONTROL_BYTES) return EPROTO;
    const unsigned char *bytes = input;
    if (word(bytes) != 0x524d4b31 || word(bytes + 4) != REMOZIO_MONITOR_WIRE_VERSION || wide(bytes + 24)) return EPROTO;
    remozio_monitor_control_t candidate = {.tag = word(bytes + 8), .signal = word(bytes + 12), .sequence = wide(bytes + 16)};
    int error = valid_control(&candidate); if (error) return error;
    *control = candidate; return 0;
}
