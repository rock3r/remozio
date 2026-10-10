/* Disposable same-user credential seam. The product launcher still parses, validates and executes its frame. */
#ifndef REMOZIO_OWNED_LIVE_FIXTURE
#error "This credential seam requires an explicit disposable fixture build."
#endif
#include <unistd.h>
#include <errno.h>
#include <string.h>
static gid_t fixture_groups[16];
static int fixture_group_count;
static uid_t fixture_getuid(void) { static int calls; return calls++ ? getuid() : 0; }
static uid_t fixture_geteuid(void) { static int calls; return calls++ ? geteuid() : 0; }
static int fixture_setuid(uid_t uid) { if (uid == getuid()) return 0; errno = EPERM; return -1; }
static int fixture_setgid(gid_t gid) { if (gid == getgid()) return 0; errno = EPERM; return -1; }
static int fixture_setgroups(int count, const gid_t *groups) {
    if (count != 1 || !groups || groups[0] != getgid()) { errno = EPERM; return -1; }
    memcpy(fixture_groups, groups, (size_t)count * sizeof(gid_t)); fixture_group_count = count; return 0;
}
static int fixture_getgroups(int count, gid_t *groups) {
    if (count < fixture_group_count || !groups) { errno = EINVAL; return -1; }
    memcpy(groups, fixture_groups, (size_t)fixture_group_count * sizeof(gid_t)); return fixture_group_count;
}
#define getuid fixture_getuid
#define geteuid fixture_geteuid
#define setuid fixture_setuid
#define setgid fixture_setgid
#define setgroups fixture_setgroups
#define getgroups fixture_getgroups
#include "../../macos/app/CommandChild/ChildMain.c"
