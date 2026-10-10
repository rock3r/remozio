/* Test-only private status-channel boundary. No target or monitor process is spawned. */
#include "CommandMonitor.c"
#include <stdio.h>
int main(void) {
    int status[2];
    if (pipe(status)) return 1;
    remozio_command_monitor_t monitor = {0};
    monitor.parent = getpid();
    monitor.configuration = monitor.release = monitor.control = monitor.events = -1;
    monitor.status = status[0]; monitor.control_sequence = 1;
    monitor.state.configured = monitor.state.prepared = monitor.state.release_attempted = true;
    remozio_monitor_record_t prepared = {.tag = REMOZIO_MONITOR_PREPARED, .target_pid = 42, .sequence = 1};
    if (remozio_monitor_stream_accept(&monitor.state.status, &prepared) ||
        remozio_monitor_stream_note_release(&monitor.state.status)) return 2;
    remozio_monitor_record_t stopped = {.tag = REMOZIO_MONITOR_JOB_STATE,
        .flags = REMOZIO_MONITOR_STOPPED | REMOZIO_MONITOR_TARGET_RELEASE_ATTEMPTED,
        .target_pid = 42, .detail = SIGSTOP, .stop_code = CLD_STOPPED, .sequence = 2, .job_revision = 1};
    if (remozio_monitor_stream_accept(&monitor.state.status, &stopped)) return 3;
    remozio_monitor_record_t ack = {.tag = REMOZIO_MONITOR_CONTROL_APPLIED,
        .flags = REMOZIO_MONITOR_TARGET_RELEASE_ATTEMPTED, .target_pid = 42,
        .sequence = 3, .applied_control_sequence = 2};
    unsigned char bytes[REMOZIO_MONITOR_RECORD_BYTES];
    remozio_monitor_stream_t codec_only = monitor.state.status;
    if (remozio_monitor_record_encode(&ack, bytes) || remozio_monitor_stream_accept(&codec_only, &ack) ||
        write(status[1], bytes, sizeof(bytes)) != sizeof(bytes)) return 4;
    int error = pump_status(&monitor);
    bool rejected = error == EPROTO && monitor.state.protocol_failed && monitor.state.status_closed &&
        monitor.status == -1 && monitor.state.status.last_applied_control_sequence == 0 && monitor.state.status.latest.sequence == 2;
    remozio_command_current_job_t job = {0};
    bool unknown = remozio_command_monitor_current_job(&monitor, &job) == 0 && !job.known;
    bool closed = pump_status(&monitor) == 0 && monitor.state.protocol_failed;
    close_resources(&monitor); close(status[1]);
    printf("{\"unqueuedWatermarkRejected\":%s,\"queryUnknown\":%s,\"channelRemainsClosed\":%s}\n",
        rejected ? "true" : "false", unknown ? "true" : "false", closed ? "true" : "false");
    return rejected && unknown && closed ? 0 : 5;
}
