/* Observe every accepted record without changing the native parent's behavior. */
#include "RemozioCommandMonitorProtocol.h"
int fixture_observe_record(remozio_monitor_stream_t *stream, const remozio_monitor_record_t *record);
#define remozio_monitor_stream_accept fixture_observe_record
#include "CommandMonitor.c"
