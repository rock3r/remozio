#ifndef REMOZIO_FIXTURE_OWNED_TTY_H
#define REMOZIO_FIXTURE_OWNED_TTY_H
int remozio_fixture_open_tty(int *master, int *slave);
int remozio_fixture_adopt_tty(int *master, int *slave);
#endif
