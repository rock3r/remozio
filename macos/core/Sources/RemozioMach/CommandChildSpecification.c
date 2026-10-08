#include "include/RemozioCommandChild.h"
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

static uint32_t word(const unsigned char *bytes) {
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) | ((uint32_t)bytes[2] << 8) | bytes[3];
}
void remozio_child_spec_close(remozio_child_spec_t *spec) {
    if (!spec) return;
    if (spec->storage) {
        volatile unsigned char *bytes = (volatile unsigned char *)spec->storage;
        for (size_t index = 0; index < spec->storage_count; ++index) bytes[index] = 0;
    }
    free(spec->groups); free(spec->arguments); free(spec->environment); free(spec->storage);
    memset(spec, 0, sizeof(*spec));
}
static int string(const unsigned char *bytes, size_t count, size_t *cursor, remozio_child_spec_t *spec,
                  size_t *used, char **output) {
    if (*cursor > count || count - *cursor < 4) return EINVAL;
    uint32_t length = word(bytes + *cursor); *cursor += 4;
    if (length > count - *cursor || memchr(bytes + *cursor, 0, length) || *used > count || length + 1U > count - *used) return EINVAL;
    *output = spec->storage + *used;
    memcpy(*output, bytes + *cursor, length); (*output)[length] = 0;
    *used += length + 1U; *cursor += length;
    return 0;
}
int remozio_child_spec_groups(const remozio_child_spec_t *spec, uint32_t *groups, uint32_t *count) {
    if (!spec || !groups || !count || spec->gid == UINT32_MAX || spec->group_count > 16 || (spec->group_count && !spec->groups)) return EINVAL;
    *count = 1; groups[0] = spec->gid;
    for (uint32_t index = 0; index < spec->group_count; ++index) {
        uint32_t group = spec->groups[index];
        if (group == UINT32_MAX) return EINVAL;
        bool duplicate = false;
        for (uint32_t prior = 0; prior < *count; ++prior) if (groups[prior] == group) duplicate = true;
        if (!duplicate) {
            if (*count == 16) return EINVAL;
            groups[(*count)++] = group;
        }
    }
    return 0;
}
int remozio_child_spec_decode(const void *input, size_t count, remozio_child_spec_t *output) {
    if (!output) return EINVAL;
    memset(output, 0, sizeof(*output));
    if (!input || count < REMOZIO_CHILD_HEADER_BYTES || count > REMOZIO_CHILD_MAX_BYTES) return EINVAL;
    const unsigned char *bytes = input;
    if (word(bytes) != 0x524d4331 || word(bytes + 4) != count - REMOZIO_CHILD_HEADER_BYTES) return EINVAL;
    remozio_child_spec_t spec = {0};
    spec.uid = word(bytes + 8); spec.gid = word(bytes + 12); spec.group_count = word(bytes + 16);
    spec.argument_count = word(bytes + 20); spec.environment_count = word(bytes + 24);
    spec.preparation_milliseconds = word(bytes + 28); spec.file_creation_mask = word(bytes + 32); spec.io_mode = word(bytes + 36);
    if (spec.uid == UINT32_MAX || spec.gid == UINT32_MAX || spec.group_count > 16 || spec.argument_count == 0 ||
        spec.argument_count > REMOZIO_CHILD_MAX_ENTRIES || spec.environment_count > REMOZIO_CHILD_MAX_ENTRIES ||
        spec.io_mode > 1 || spec.preparation_milliseconds < 100 || spec.preparation_milliseconds > 60000 || spec.file_creation_mask > 0777) return EINVAL;
    size_t entries = 1U + spec.argument_count + spec.environment_count;
    if (spec.group_count * 4U + entries * 4U > count - REMOZIO_CHILD_HEADER_BYTES) return EINVAL;
    spec.groups = calloc(spec.group_count + 1U, sizeof(uint32_t));
    spec.arguments = calloc(spec.argument_count + 1U, sizeof(char *));
    spec.environment = calloc(spec.environment_count + 1U, sizeof(char *));
    spec.storage_count = count; spec.storage = malloc(count);
    if (!spec.groups || !spec.arguments || !spec.environment || !spec.storage) {
        remozio_child_spec_close(&spec); return ENOMEM;
    }
    size_t cursor = REMOZIO_CHILD_HEADER_BYTES, used = 0;
    int error = EINVAL;
    for (uint32_t index = 0; index < spec.group_count; ++index) {
        spec.groups[index] = word(bytes + cursor); cursor += 4;
        if (spec.groups[index] == UINT32_MAX) goto fail;
    }
    uint32_t groups[16], group_count;
    if (remozio_child_spec_groups(&spec, groups, &group_count)) goto fail;
    if (string(bytes, count, &cursor, &spec, &used, &spec.executable) || spec.executable[0] != '/') goto fail;
    for (uint32_t index = 0; index < spec.argument_count; ++index)
        if (string(bytes, count, &cursor, &spec, &used, &spec.arguments[index])) goto fail;
    for (uint32_t index = 0; index < spec.environment_count; ++index) {
        if (string(bytes, count, &cursor, &spec, &used, &spec.environment[index])) goto fail;
        char *separator = strchr(spec.environment[index], '=');
        if (!separator || separator == spec.environment[index]) goto fail;
        if (index != 0) {
            char *previous = spec.environment[index - 1], *end = strchr(previous, '=');
            size_t previous_length = (size_t)(end - previous), length = (size_t)(separator - spec.environment[index]);
            int order = memcmp(previous, spec.environment[index], previous_length < length ? previous_length : length);
            if (order > 0 || (order == 0 && previous_length >= length)) goto fail;
        }
    }
    if (cursor != count) goto fail;
    *output = spec; return 0;
fail:
    remozio_child_spec_close(&spec); return error;
}
