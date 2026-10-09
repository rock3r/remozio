#ifndef REMOZIO_COMMAND_MONITOR_PROTOCOL_H
#define REMOZIO_COMMAND_MONITOR_PROTOCOL_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#define REMOZIO_MONITOR_RECORD_BYTES 64
#define REMOZIO_MONITOR_WIRE_VERSION 1
/* Private inherited pipes only. These records do not grant authority or authenticate an executable. */
enum remozio_monitor_tag {
    REMOZIO_MONITOR_PREPARED = 1,
    REMOZIO_MONITOR_JOB_STATE = 2,
    REMOZIO_MONITOR_TARGET_REAPED = 3,
    REMOZIO_MONITOR_FAILURE = 4
};
enum remozio_monitor_flags {
    REMOZIO_MONITOR_STOPPED = 1,
    REMOZIO_MONITOR_TRACING_KNOWN = 2,
    REMOZIO_MONITOR_TRACED = 4,
    REMOZIO_MONITOR_BIRTH_KNOWN = 8,
    /* The monitor attempted its target release. A Root write alone does not establish this. */
    REMOZIO_MONITOR_TARGET_RELEASE_ATTEMPTED = 16
};
typedef struct {
    uint32_t tag, flags, target_pid, detail, stop_code;
    uint64_t sequence, job_revision, birth_seconds, birth_microseconds;
} remozio_monitor_record_t;
/* Exact version, canonical fields, and tag-specific shape. A decoder does not establish process ownership. */
int remozio_monitor_record_encode(const remozio_monitor_record_t *record, unsigned char bytes[REMOZIO_MONITOR_RECORD_BYTES]);
int remozio_monitor_record_decode(const void *bytes, size_t count, remozio_monitor_record_t *record);
typedef struct {
    remozio_monitor_record_t latest;
    uint64_t last_job_revision;
    uint32_t failure_error;
    bool prepared, release_attempted, target_release_attempted, failed, reaped;
} remozio_monitor_stream_t;
/* Initialize a fresh inherited status channel. Never reset this state to accept a replacement target. */
void remozio_monitor_stream_init(remozio_monitor_stream_t *stream);
/* Consume the local release attempt before writing its byte, including when that write fails.
 * This marker is not durable approval. The serialized Root owner must complete its separate checks first. */
int remozio_monitor_stream_note_release(remozio_monitor_stream_t *stream);
/* Requires consecutive emitted sequences, one target binding and monotonic job revisions.
 * Protocol errors leave the state unchanged. A reaped report requires separate kernel and owner evidence. */
int remozio_monitor_stream_accept(remozio_monitor_stream_t *stream, const remozio_monitor_record_t *record);
#define REMOZIO_MONITOR_CONTROL_BYTES 32
enum remozio_monitor_control_tag {
    REMOZIO_MONITOR_SIGNAL = 1,
    REMOZIO_MONITOR_CANCEL = 2
};
typedef struct {
    uint32_t tag, signal;
    uint64_t sequence;
} remozio_monitor_control_t;
/* Private inherited control pipe only. No PID, approval, or executable is accepted here. */
int remozio_monitor_control_encode(const remozio_monitor_control_t *control, unsigned char bytes[REMOZIO_MONITOR_CONTROL_BYTES]);
int remozio_monitor_control_decode(const void *bytes, size_t count, remozio_monitor_control_t *control);
#endif
