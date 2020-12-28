/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <stdbool.h>
#include <sys/types.h>

#include "sd-id128.h"

typedef struct Transfer Transfer;

#include "sysupdate-partition.h"
#include "sysupdate-resource.h"

struct Transfer {
        char *definition_path;
        char *min_version;
        char **protected_versions;

        Resource source, target;

        uint64_t instances_max;
        bool remove_temporary;

        /* When creating a new partition/file, optionally override these attributes explicitly */
        sd_id128_t partition_uuid;
        bool partition_uuid_set;
        uint64_t partition_flags;
        bool partition_flags_set;
        mode_t mode;
        uint64_t tries_left;

        /* If we create a new file/dir/subvol in the fs, the temporary and final path we create it under */
        char *temporary_path;
        char *final_path;

        /* If we write to a partition in a partition table, the metrics of it */
        PartitionInfo partition_info;
        PartitionChange partition_change;

        /* When we write an entry (regardless if file/dir/subvol or partition, shall we make it read-only? */
        int make_read_only;
};

Transfer *transfer_new(void);

Transfer *transfer_free(Transfer *t);
DEFINE_TRIVIAL_CLEANUP_FUNC(Transfer*, transfer_free);

int transfer_read_definition(Transfer *t, const char *path);

int transfer_make_room(Transfer *t, uint64_t space, const char *extra_protected_version);
