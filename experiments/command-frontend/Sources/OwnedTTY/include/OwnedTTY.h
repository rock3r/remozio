#ifndef REMOZIO_FIXTURE_OWNED_TTY_H
#define REMOZIO_FIXTURE_OWNED_TTY_H
#include <mach/mach.h>
#include <mach/task_special_ports.h>
#include <sys/types.h>
int remozio_fixture_open_tty(int *master, int *slave);
int remozio_fixture_adopt_tty(int *master, int *slave);
int remozio_fixture_spawn_supervisor(const char *path, char *const arguments[],
    mach_port_t authority, const char *resume_marker, pid_t *child, int *output);
int remozio_fixture_install_cancellation(void);
int remozio_fixture_cancelled(void);
#endif
