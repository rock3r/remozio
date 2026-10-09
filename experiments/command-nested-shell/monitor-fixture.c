/* Substitute only the monitor UID guard. The fixture changes no credentials. */
#include <unistd.h>
static uid_t fixture_root_uid(void) { return 0; }
#define getuid fixture_root_uid
#define geteuid fixture_root_uid
#include "MonitorMain.c"
