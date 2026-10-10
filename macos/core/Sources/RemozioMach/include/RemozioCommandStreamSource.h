#ifndef REMOZIO_COMMAND_STREAM_SOURCE_H
#define REMOZIO_COMMAND_STREAM_SOURCE_H
#include <stdbool.h>

/* Metadata only. This does not establish caller identity or execution authority. */
int remozio_command_stream_source_is_terminal_alias(int source, bool * _Nonnull alias);

/* Caller-side only. Owns a CLOEXEC descriptor without reading bytes or changing source flags.
 * /dev/tty resolves from this process's kernel terminal identity before cross-session transfer.
 * Other streams retain their original open-file description. The caller closes the returned FD. */
int remozio_command_stream_source_retain(int source, int * _Nonnull output);
#endif
