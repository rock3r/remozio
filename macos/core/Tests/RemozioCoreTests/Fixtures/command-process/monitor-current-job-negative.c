/* Test-only negative control: substitute a cached record for the fresh kernel query. */
#define remozio_command_monitor_current_job fixture_unused_current_job
#include "CommandMonitor.c"
#undef remozio_command_monitor_current_job
int remozio_command_monitor_current_job(remozio_command_monitor_t *monitor, remozio_command_current_job_t *job) {
    if (!monitor || !job) return EINVAL;
    memset(job, 0, sizeof(*job));
    static remozio_monitor_record_t cached = {0};
    if (monitor->state.status.latest.tag == REMOZIO_MONITOR_JOB_STATE &&
        (monitor->state.status.latest.flags & REMOZIO_MONITOR_STOPPED) && !cached.sequence) cached = monitor->state.status.latest;
    const remozio_monitor_record_t *record = &cached;
    if (!monitor->state.target_exec_observed || monitor->state.status.reaped || !record->sequence ||
        monitor->state.status.last_applied_control_sequence != monitor->control_sequence) return 0;
    job->known = true;
    job->stopped = (record->flags & REMOZIO_MONITOR_STOPPED) != 0;
    job->traced = (record->flags & REMOZIO_MONITOR_TRACED) != 0;
    job->original_group = true;
    job->job_revision = record->job_revision;
    job->stop_signal = job->stopped ? record->detail : 0;
    return 0;
}
