/* Disposable credential seam. All monitor framing, terminal control and child waits use product code. */
#ifndef REMOZIO_OWNED_LIVE_FIXTURE
#error "This credential seam requires an explicit disposable fixture build."
#endif
#include <unistd.h>
static uid_t fixture_root_uid(void) { return 0; }
#define getuid fixture_root_uid
#define geteuid fixture_root_uid
#include "../../macos/app/CommandMonitor/MonitorMain.c"
