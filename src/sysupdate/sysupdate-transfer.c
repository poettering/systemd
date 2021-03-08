/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "conf-parser.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "gpt.h"
#include "parse-util.h"
#include "path-util.h"
#include "rm-rf.h"
#include "specifier.h"
#include "strv.h"
#include "sysupdate-pattern.h"
#include "sysupdate-resource.h"
#include "sysupdate-transfer.h"
#include "sysupdate-util.h"
#include "sysupdate.h"

Transfer *transfer_free(Transfer *t) {
        if (!t)
                return NULL;

        t->temporary_path = rm_rf_subvolume_and_free(t->temporary_path);

        free(t->definition_path);
        free(t->min_version);
        strv_free(t->protected_versions);
        free(t->current_symlink);
        free(t->final_path);

        partition_info_destroy(&t->partition_info);

        resource_destroy(&t->source);
        resource_destroy(&t->target);

        return mfree(t);
}

Transfer *transfer_new(void) {
        Transfer *t;

        t = new(Transfer, 1);
        if (!t)
                return NULL;

        *t = (Transfer) {
                .source.type = _RESOURCE_TYPE_INVALID,
                .target.type = _RESOURCE_TYPE_INVALID,
                .remove_temporary = true,
                .mode = MODE_INVALID,
                .tries_left = UINT64_MAX,
                .read_only = -1, /* user configured */
                .partition_info = PARTITION_INFO_NULL,
                .install_read_only = -1, /* ultimately determined */
        };

        return t;
}

static const Specifier specifier_table[] = {
        COMMON_SYSTEM_SPECIFIERS,
        {}
};

static int config_parse_protect_version(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_free_ char *resolved = NULL;
        char ***protected_versions = data;
        int r;

        assert(rvalue);
        assert(data);

        r = specifier_printf(rvalue, specifier_table, NULL, &resolved);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to expand specifiers in ProtectVersion=, ignoring: %s", rvalue);
                return 0;
        }

        if (!version_is_valid(rvalue))  {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "ProtectVersion= string is not valid, refusing: %s", resolved);
                return 0;
        }

        r = strv_extend(protected_versions, resolved);
        if (r < 0)
                return log_oom();

        return 0;
}

static int config_parse_min_version(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_free_ char *resolved = NULL;
        char **version = data;
        int r;

        assert(rvalue);
        assert(data);

        r = specifier_printf(rvalue, specifier_table, NULL, &resolved);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to expand specifiers in MinVersion=, ignoring: %s", rvalue);
                return 0;
        }

        if (!version_is_valid(rvalue)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "MinVersion= string is not valid, ignoring: %s", resolved);
                return 0;
        }

        return free_and_replace(*version, resolved);
}

static int config_parse_current_symlink(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_free_ char *resolved = NULL;
        char **current_symlink = data;
        int r;

        assert(rvalue);
        assert(data);

        r = specifier_printf(rvalue, specifier_table, NULL, &resolved);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to expand specifiers in CurrentSymlink=, ignoring: %s", rvalue);
                return 0;
        }

        r = path_simplify_and_warn(resolved, 0, unit, filename, line, lvalue);
        if (r < 0)
                return 0;

        return free_and_replace(*current_symlink, resolved);
}

static int config_parse_instances_max(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        uint64_t *instances_max = data, i;
        int r;

        assert(rvalue);
        assert(data);

        r = safe_atou64(rvalue, &i);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse InstancesMax= value, ignoring: %s", rvalue);
                return 0;
        }

        if (i < 2) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "InstancesMax= value must be at least 2, bumping: %s", rvalue);
                *instances_max = 2;
        } else
                *instances_max = i;

        return 0;
}

static int config_parse_resource_pattern(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_free_ char *resolved = NULL;
        char **pattern = data;
        int r;

        assert(rvalue);
        assert(data);

        r = specifier_printf(rvalue, specifier_table, NULL, &resolved);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to expand specifiers in Pattern=, ignoring: %s", rvalue);
                return 0;
        }

        if (!pattern_valid(resolved))
                return log_syntax(unit, LOG_ERR, filename, line, 0,
                                  "Pattern= string is not valid, refusing: %s", resolved);

        return free_and_replace(*pattern, resolved);
}

static int config_parse_resource_path(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_free_ char *resolved = NULL;
        char **path = data;
        int r;

        assert(rvalue);
        assert(data);

        r = specifier_printf(rvalue, specifier_table, NULL, &resolved);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to expand specifiers in Path=, ignoring: %s", rvalue);
                return 0;
        }

        if (!path_is_valid(resolved) || !path_is_absolute(resolved))
                return log_syntax(unit, LOG_ERR, filename, line, 0,
                                  "Path= string is not valid, refusing: %s", resolved);

        return free_and_replace(*path, resolved);
}

static DEFINE_CONFIG_PARSE_ENUM(config_parse_resource_type, resource_type, ResourceType, "Invalid resource type");

static int config_parse_resource_ptype(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Resource *rr = data;
        int r;

        assert(rvalue);
        assert(data);

        r = gpt_partition_type_uuid_from_string(rvalue, &rr->partition_type);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed parse partition type, ignoring: %s", rvalue);
                return 0;
        }

        rr->partition_type_set = true;
        return 0;
}

static int config_parse_partition_uuid(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Transfer *t = data;
        int r;

        assert(rvalue);
        assert(data);

        r = sd_id128_from_string(rvalue, &t->partition_uuid);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed parse partition UUID, ignoring: %s", rvalue);
                return 0;
        }

        t->partition_uuid_set = true;
        return 0;
}

static int config_parse_partition_flags(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Transfer *t = data;
        int r;

        assert(rvalue);
        assert(data);

        r = safe_atou64(rvalue, &t->partition_flags);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed parse partition flags, ignoring: %s", rvalue);
                return 0;
        }

        t->partition_flags_set = true;
        return 0;
}

int transfer_read_definition(Transfer *t, const char *path) {

        ConfigTableItem table[] = {
                { "Transfer",    "MinVersion",      config_parse_min_version,      0, &t->min_version        },
                { "Source",      "Type",            config_parse_resource_type,    0, &t->source.type        },
                { "Source",      "Path",            config_parse_resource_path,    0, &t->source.path        },
                { "Source",      "Pattern",         config_parse_resource_pattern, 0, &t->source.pattern     },
                { "Source",      "PartitionType",   config_parse_resource_ptype,   0, &t->source             },
                { "Target",      "Type",            config_parse_resource_type,    0, &t->target.type        },
                { "Target",      "Path",            config_parse_resource_path,    0, &t->target.path        },
                { "Target",      "Pattern",         config_parse_resource_pattern, 0, &t->target.pattern     },
                { "Target",      "PartitionType",   config_parse_resource_ptype,   0, &t->target             },
                { "Target",      "PartitionUUID",   config_parse_partition_uuid,   0, t                      },
                { "Target",      "PartitionFlags",  config_parse_partition_flags,  0, t                      },
                { "Target",      "Mode",            config_parse_mode,             0, &t->mode               },
                { "Target",      "TriesLeft",       config_parse_uint64,           0, &t->tries_left         },
                { "Target",      "ReadOnly",        config_parse_tristate,         0, &t->read_only          },
                { "Target",      "InstancesMax",    config_parse_instances_max,    0, &t->instances_max      },
                { "Target",      "ProtectVersion",  config_parse_protect_version,  0, &t->protected_versions },
                { "Target",      "RemoveTemporary", config_parse_bool,             0, &t->remove_temporary   },
                { "Target",      "CurrentSymlink",  config_parse_current_symlink,  0, &t->current_symlink    },
                {}
        };
        int r;

        assert(t);
        assert(path);

        r = config_parse(NULL, path, NULL,
                         "Transfer\0"
                         "Source\0"
                         "Target\0",
                         config_item_table_lookup, table,
                         CONFIG_PARSE_WARN,
                         t,
                         NULL);
        if (r < 0)
                return r;

        if (!RESOURCE_IS_SOURCE(t->source.type))
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                  "Source Type= must be one of http-file, http-tar, tar, regular-file, directory, subvolume.");

        if (t->target.type < 0) {
                switch (t->source.type) {

                case RESOURCE_HTTP_FILE:
                case RESOURCE_REGULAR_FILE:
                        t->target.type =
                                t->target.path && path_startswith(t->target.path, "/dev/") ?
                                RESOURCE_PARTITION : RESOURCE_REGULAR_FILE;
                        break;

                case RESOURCE_HTTP_TAR:
                case RESOURCE_TAR:
                case RESOURCE_DIRECTORY:
                        t->target.type = RESOURCE_DIRECTORY;
                        break;

                case RESOURCE_SUBVOLUME:
                        t->target.type = RESOURCE_SUBVOLUME;
                        break;

                default:
                        assert_not_reached("Unexpected resource type");
                }
        }

        if (!RESOURCE_IS_TARGET(t->target.type))
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                  "Target Type= must be one of partition, regular-file, directory, subvolume.");

        if ((IN_SET(t->source.type, RESOURCE_HTTP_FILE, RESOURCE_PARTITION, RESOURCE_REGULAR_FILE) &&
             !IN_SET(t->target.type, RESOURCE_PARTITION, RESOURCE_REGULAR_FILE)) ||
            (IN_SET(t->source.type, RESOURCE_HTTP_TAR, RESOURCE_TAR, RESOURCE_DIRECTORY, RESOURCE_SUBVOLUME) &&
             !IN_SET(t->target.type, RESOURCE_DIRECTORY, RESOURCE_SUBVOLUME)))
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                  "Target type '%s' is incompatible with source type '%s', refusing.",
                                  resource_type_to_string(t->source.type), resource_type_to_string(t->target.type));

        if (!t->source.path || !t->source.pattern)
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                  "Source specification lacks Path= and Pattern=.");

        if (!t->target.path)
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                  "Target specification lacks Path= field.");

        if (!t->target.pattern) {
                t->target.pattern = strdup(t->source.pattern);
                if (!t->target.pattern)
                        return log_oom();
        }

        if (t->current_symlink && !RESOURCE_IS_FILESYSTEM(t->target.type) && !path_is_absolute(t->current_symlink))
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                  "Current symlink must be absolute path if target is partition.");

        /* When no instance limit is set, use all available partition slots in case of partitions, or 5 in case of fs objects */
        if (t->instances_max == 0)
                t->instances_max = t->target.type == RESOURCE_PARTITION ? UINT64_MAX : 5;

        return 0;
}

static void transfer_remove_temporary(Transfer *t) {
        _cleanup_(closedirp) DIR *d = NULL;
        int r;

        assert(t);

        if (!t->remove_temporary)
                return;

        if (!IN_SET(t->target.type, RESOURCE_REGULAR_FILE, RESOURCE_DIRECTORY, RESOURCE_SUBVOLUME))
                return;

        /* Removes all temporary files/dirs from previous runs in the target directory, i.e. all those starting with '.#' */

        d = opendir(t->target.path);
        if (!d) {
                if (errno == ENOENT)
                        return;

                log_debug_errno(errno, "Failed to open target directory '%s', ignoring: %m", t->target.path);
                return;
        }

        for (;;) {
                struct dirent *de;

                errno = 0;
                de = readdir_no_dot(d);
                if (!de) {
                        if (errno != 0)
                                log_debug_errno(errno, "Failed to read target directory '%s', ignoring: %m", t->target.path);
                        break;
                }

                if (!startswith(de->d_name, ".#"))
                        continue;

                r = rm_rf_child(dirfd(d), de->d_name, REMOVE_PHYSICAL|REMOVE_SUBVOLUME|REMOVE_CHMOD);
                if (r == -ENOENT)
                        continue;
                if (r < 0) {
                        log_warning_errno(r, "Failed to remove temporary resource instance '%s/%s', ignoring: %m", t->target.path, de->d_name);
                        continue;
                }

                log_debug("Removed temporary resource instance '%s/%s'.", t->target.path, de->d_name);
        }
}

int transfer_make_room(
                Transfer *t,
                uint64_t space,
                const char *extra_protected_version) {

        uint64_t limit;
        int r, count = 0;

        assert(t);

        transfer_remove_temporary(t);

        /* First, calculate how many instances to keep, based on the instance limit */
        limit = LESS_BY(arg_instances_max != UINT64_MAX ? arg_instances_max : t->instances_max, space);

        if (t->target.type == RESOURCE_PARTITION) {
                uint64_t rm, remain;

                /* If we are looking at a partition table, we also have to take into account how many
                 * partition slots of the right type are available */

                if (space > t->target.n_empty + t->target.n_instances)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOSPC),
                                               "Partition table does not have enough partition slots of right type for required partitions.");

                rm = LESS_BY(space, t->target.n_empty);
                remain = LESS_BY(t->target.n_instances, rm);
                if (remain < limit)
                        limit = remain;
        }

        while (t->target.n_instances > limit) {
                Instance *oldest;
                size_t p = t->target.n_instances - 1;

                for (;;) {
                        oldest = t->target.instances[p];

                        /* If this is listed among the protected versions, then let's not remove it */
                        if (!strv_contains(t->protected_versions, oldest->metadata.version) &&
                            (!extra_protected_version || !streq(extra_protected_version, oldest->metadata.version)))
                                break;

                        log_debug("Version '%s' is protected, not removing.", oldest->metadata.version);
                        if (p == 0) {
                                oldest = NULL;
                                break;
                        }

                        p--;
                }

                if (!oldest) /* Nothing more to remove */
                        break;

                log_info("Removing old '%s' (%s).", oldest->path, resource_type_to_string(oldest->resource->type));

                switch (t->target.type) {

                case RESOURCE_REGULAR_FILE:
                case RESOURCE_DIRECTORY:
                case RESOURCE_SUBVOLUME:
                        r = rm_rf(oldest->path, REMOVE_ROOT|REMOVE_PHYSICAL|REMOVE_SUBVOLUME|REMOVE_MISSING_OK|REMOVE_CHMOD);
                        if (r < 0 && r != -ENOENT)
                                return log_error_errno(r, "Failed to make room by deleting '%s': %m", oldest->path);

                        break;

                case RESOURCE_PARTITION: {
                        PartitionInfo pinfo = oldest->partition_info;

                        /* Empty label means "no contents" for our purposes */
                        pinfo.label = (char*) "";

                        r = patch_partition(t->target.path, &pinfo, PARTITION_LABEL);
                        if (r < 0)
                                return r;

                        t->target.n_empty++;
                        break;
                }

                default:
                        assert_not_reached("unexpected resource type");
                        break;
                }

                instance_free(oldest);
                memmove(t->target.instances + p, t->target.instances + p + 1, (t->target.n_instances - p - 1) * sizeof(Instance*));
                t->target.n_instances--;

                count++;
        }

        return count;
}
