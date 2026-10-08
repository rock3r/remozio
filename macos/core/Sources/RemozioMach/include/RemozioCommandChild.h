#ifndef REMOZIO_COMMAND_CHILD_H
#define REMOZIO_COMMAND_CHILD_H
#include <stddef.h>
#include <stdint.h>
#define REMOZIO_CHILD_MAX_BYTES (8U * 1024U * 1024U)
#define REMOZIO_CHILD_MAX_ENTRIES 262144U
#define REMOZIO_CHILD_HEADER_BYTES 40U
/* This decoder only owns data. It grants no execution permission. */
typedef struct {
    uint32_t uid, gid, group_count, argument_count, environment_count;
    uint32_t preparation_milliseconds, file_creation_mask, io_mode;
    uint32_t *groups;
    char *executable;
    char **arguments;
    char **environment;
    char *storage;
    size_t storage_count;
} remozio_child_spec_t;
/* Output must be fresh or closed. Close wipes and frees the decoded string storage. */
int remozio_child_spec_decode(const void *bytes, size_t count, remozio_child_spec_t *output);
void remozio_child_spec_close(remozio_child_spec_t *spec);
/* Output has room for 16 entries. The approved primary GID occupies the first slot. */
int remozio_child_spec_groups(const remozio_child_spec_t *spec, uint32_t *groups, uint32_t *count);
#endif
