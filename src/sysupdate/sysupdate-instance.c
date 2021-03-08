/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/stat.h>

#include "alloc-util.h"
#include "fs-util.h"
#include "gpt.h"
#include "hexdecoct.h"
#include "path-util.h"
#include "process-util.h"
#include "stdio-util.h"
#include "sysupdate-instance.h"
#include "sysupdate-pattern.h"
#include "sysupdate-transfer.h"
#include "sysupdate.h"
#include "tmpfile-util.h"

#undef SYSTEMD_IMPORT_PATH
#define SYSTEMD_IMPORT_PATH "/home/lennart/projects/systemd/build/systemd-import"

#undef SYSTEMD_IMPORT_FS_PATH
#define SYSTEMD_IMPORT_FS_PATH "/home/lennart/projects/systemd/build/systemd-import-fs"

#undef SYSTEMD_PULL_PATH
#define SYSTEMD_PULL_PATH "/home/lennart/projects/systemd/build/systemd-pull"

void instance_metadata_destroy(InstanceMetadata *m) {
        free(m->version);
}

int instance_new(
                Resource *rr,
                const char *path,
                const InstanceMetadata *f,
                Instance **ret) {

        _cleanup_(instance_freep) Instance *i = NULL;
        _cleanup_free_ char *p = NULL, *v = NULL;

        assert(rr);
        assert(path);
        assert(f);
        assert(f->version);
        assert(ret);

        p = strdup(path);
        if (!p)
                return log_oom();

        v = strdup(f->version);
        if (!v)
                return log_oom();

        i = new(Instance, 1);
        if (!i)
                return log_oom();

        *i = (Instance) {
                .resource = rr,
                .metadata = *f,
                .path = TAKE_PTR(p),
                .partition_info = PARTITION_INFO_NULL,
        };

        i->metadata.version = TAKE_PTR(v);

        *ret = TAKE_PTR(i);
        return 0;
}

Instance *instance_free(Instance *i) {
        if (!i)
                return NULL;

        instance_metadata_destroy(&i->metadata);

        free(i->path);
        partition_info_destroy(&i->partition_info);

        return mfree(i);
}

static void compile_pattern_fields(
                const Transfer *t,
                const Instance *i,
                InstanceMetadata *ret) {

        assert(t);
        assert(i);

        *ret = (InstanceMetadata) {
                .version = i->metadata.version,

                /* We generally prefer explicitly configured values for the transfer over those automatically
                 * derived from the source instance. Also, if the source is a tar archive, then let's not
                 * patch mtime/mode and use the one embedded in the tar file */
                .partition_uuid = t->partition_uuid_set ? t->partition_uuid : i->metadata.partition_uuid,
                .partition_uuid_set = t->partition_uuid_set || i->metadata.partition_uuid_set,
                .partition_flags = t->partition_flags_set ? t->partition_flags : i->metadata.partition_flags,
                .partition_flags_set = t->partition_flags_set || i->metadata.partition_flags_set,
                .mtime = RESOURCE_IS_TAR(i->resource->type) ? USEC_INFINITY : i->metadata.mtime,
                .mode = t->mode != MODE_INVALID ? t->mode : (RESOURCE_IS_TAR(i->resource->type) ? MODE_INVALID : i->metadata.mode),
                .size = i->metadata.size,
                .tries_done = i->metadata.tries_done,
                .tries_left = t->tries_left != UINT64_MAX ? t->tries_left : i->metadata.tries_left,
                .read_only = t->read_only >= 0 ? t->read_only : i->metadata.read_only,
                .sha256sum_set = i->metadata.sha256sum_set,
        };

        memcpy(ret->sha256sum, i->metadata.sha256sum, sizeof(ret->sha256sum));
}

int instance_acquire(Instance *i) {
        _cleanup_free_ char *formatted_pattern = NULL, *digest = NULL;
        char offset[DECIMAL_STR_MAX(uint64_t)], max_size[DECIMAL_STR_MAX(uint64_t)];
        InstanceMetadata f;
        Instance *existing;
        Transfer *t;
        int r;

        assert(i);
        assert(i->resource);
        assert_se(t = container_of(i->resource, Transfer, source));

        /* Does this instance already exist in the target? Then we don't need to acquire anything */
        existing = resource_find_instance(&t->target, i->metadata.version);
        if (existing) {
                log_info("No need to acquire '%s', already installed.", i->path);
                return 0;
        }

        assert(!t->final_path);
        assert(!t->temporary_path);

        compile_pattern_fields(t, i, &f);
        r = pattern_format(t->target.pattern, &f, &formatted_pattern);
        if (r < 0)
                return log_error_errno(r, "Failed to format target pattern: %m");

        if (RESOURCE_IS_FILESYSTEM(t->target.type)) {

                if (!filename_is_valid(formatted_pattern))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Formatted pattern is not suitable as file name, refusing: %s", formatted_pattern);

                t->final_path = path_join(t->target.path, formatted_pattern);
                if (!t->final_path)
                        return log_oom();

                r = tempfn_random(t->final_path, "sysupdate", &t->temporary_path);
                if (r < 0)
                        return log_error_errno(r, "Failed to generate temporary target path: %m");
        }

        if (t->target.type == RESOURCE_PARTITION) {
                r = gpt_partition_label_valid(formatted_pattern);
                if (r < 0)
                        return log_error_errno(r, "Failed to determine if formatted pattern is suitable as GPT partition label: %s", formatted_pattern);
                if (!r)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Formatted pattern is not suitable as GPT partition label, refusing: %s", formatted_pattern);

                r = find_suitable_partition(
                                t->target.path,
                                i->metadata.size,
                                t->target.partition_type_set ? &t->target.partition_type : NULL,
                                &t->partition_info);
                if (r < 0)
                        return r;

                xsprintf(offset, "%" PRIu64, t->partition_info.start);
                xsprintf(max_size, "%" PRIu64, t->partition_info.size);
        }

        if (RESOURCE_IS_HTTP(i->resource->type)) {
                /* For HTTP sources we require the SHA256 sum to be known so that we can validate the
                 * download. */

                if (!i->metadata.sha256sum_set)
                        return log_error_errno(r, "SHA256 checksum not known for download '%s', refusing.", i->path);

                digest = hexmem(i->metadata.sha256sum, sizeof(i->metadata.sha256sum));
                if (!digest)
                        return log_oom();
        }

        switch (i->resource->type) { /* Source */

        case RESOURCE_REGULAR_FILE:

                switch (t->target.type) { /* Target */

                case RESOURCE_REGULAR_FILE:

                        /* regular file → regular file (why fork off systemd-import for such a simple file
                         * copy case? implicit decompression mostly, and thus also sandboxing. Also, the
                         * importer has some tricks up its sleeve, such as sparse file generation, which we
                         * want to take benefit of, too.) */

                        r = safe_fork("(sd-import-raw)", FORK_RESET_SIGNALS|FORK_DEATHSIG|FORK_LOG|FORK_WAIT, NULL);
                        if (r < 0)
                                return r;
                        if (r == 0) {
                                /* Child */

                                const char *cmdline[] = {
                                        "systemd-import",
                                        "raw",
                                        "--direct",          /* just copy/unpack the specified file, don't do anything else */
                                        arg_sync ? "--sync=yes" : "--sync=no",
                                        i->path,
                                        t->temporary_path,
                                        NULL
                                };

                                execv(SYSTEMD_IMPORT_PATH, (char *const*) cmdline);
                                log_error_errno(errno, "Failed to execute %s tool: %m", SYSTEMD_IMPORT_PATH);
                                _exit(EXIT_FAILURE);
                        }
                        break;

                case RESOURCE_PARTITION:

                        /* regular file → partition */

                        r = safe_fork("(sd-import-raw)", FORK_RESET_SIGNALS|FORK_DEATHSIG|FORK_LOG|FORK_WAIT, NULL);
                        if (r < 0)
                                return r;
                        if (r == 0) {
                                /* Child */

                                const char *cmdline[] = {
                                        "systemd-import",
                                        "raw",
                                        "--direct",          /* just copy/unpack the specified file, don't do anything else */
                                        "--offset", offset,
                                        "--size-max", max_size,
                                        arg_sync ? "--sync=yes" : "--sync=no",
                                        i->path,
                                        t->target.path,
                                        NULL
                                };

                                execv(SYSTEMD_IMPORT_PATH, (char *const*) cmdline);
                                log_error_errno(errno, "Failed to execute %s tool: %m", SYSTEMD_IMPORT_PATH);
                                _exit(EXIT_FAILURE);
                        }
                        break;

                default:
                        assert_not_reached("Unexpected target resource type");
                }

                break;

        case RESOURCE_DIRECTORY:
        case RESOURCE_SUBVOLUME:
                assert(IN_SET(t->target.type, RESOURCE_DIRECTORY, RESOURCE_SUBVOLUME));

                /* directory/subvolume → directory/subvolume */

                r = safe_fork("(sd-import-fs)", FORK_RESET_SIGNALS|FORK_DEATHSIG|FORK_LOG|FORK_WAIT, NULL);
                if (r < 0)
                        return r;
                if (r == 0) {
                        /* Child */

                        const char *cmdline[] = {
                                "systemd-import-fs",
                                "run",
                                "--direct",          /* just untar the specified file, don't do anything else */
                                arg_sync ? "--sync=yes" : "--sync=no",
                                t->target.type == RESOURCE_SUBVOLUME ? "--btrfs-subvol=yes" : "--btrfs-subvol=no",
                                i->path,
                                t->temporary_path,
                                NULL
                        };

                        execv(SYSTEMD_IMPORT_FS_PATH, (char *const*) cmdline);
                        log_error_errno(errno, "Failed to execute %s tool: %m", SYSTEMD_IMPORT_FS_PATH);
                        _exit(EXIT_FAILURE);
                }
                break;

        case RESOURCE_TAR:
                assert(IN_SET(t->target.type, RESOURCE_DIRECTORY, RESOURCE_SUBVOLUME));

                /* tar → directory/subvolume */

                r = safe_fork("(sd-import-tar)", FORK_RESET_SIGNALS|FORK_DEATHSIG|FORK_LOG|FORK_WAIT, NULL);
                if (r < 0)
                        return r;
                if (r == 0) {
                        /* Child */

                        const char *cmdline[] = {
                                "systemd-import",
                                "tar",
                                "--direct",          /* just untar the specified file, don't do anything else */
                                arg_sync ? "--sync=yes" : "--sync=no",
                                t->target.type == RESOURCE_SUBVOLUME ? "--btrfs-subvol=yes" : "--btrfs-subvol=no",
                                i->path,
                                t->temporary_path,
                                NULL
                        };

                        execv(SYSTEMD_IMPORT_PATH, (char *const*) cmdline);
                        log_error_errno(errno, "Failed to execute %s tool: %m", SYSTEMD_IMPORT_PATH);
                        _exit(EXIT_FAILURE);
                }
                break;

        case RESOURCE_HTTP_FILE:

                switch (t->target.type) {

                case RESOURCE_REGULAR_FILE:

                        /* http file → regular file */

                        r = safe_fork("(sd-pull-raw)", FORK_RESET_SIGNALS|FORK_DEATHSIG|FORK_LOG|FORK_WAIT, NULL);
                        if (r < 0)
                                return r;
                        if (r == 0) {
                                /* Child */

                                const char *cmdline[] = {
                                        "systemd-pull",
                                        "raw",
                                        "--direct",          /* just download the specified URL, don't download anything else */
                                        "--verify", digest,  /* validate by explicit SHA256 sum */
                                        arg_sync ? "--sync=yes" : "--sync=no",
                                        i->path,
                                        t->temporary_path,
                                        NULL
                                };

                                execv(SYSTEMD_PULL_PATH, (char *const*) cmdline);
                                log_error_errno(errno, "Failed to execute %s tool: %m", SYSTEMD_PULL_PATH);
                                _exit(EXIT_FAILURE);
                        }
                        break;

                case RESOURCE_PARTITION:

                        /* http file → partition */

                        r = safe_fork("(sd-pull-raw)", FORK_RESET_SIGNALS|FORK_DEATHSIG|FORK_LOG|FORK_WAIT, NULL);
                        if (r < 0)
                                return r;
                        if (r == 0) {
                                /* Child */

                                const char *cmdline[] = {
                                        "systemd-pull",
                                        "raw",
                                        "--direct",              /* just download the specified URL, don't download anything else */
                                        "--verify", digest,      /* validate by explicit SHA256 sum */
                                        "--offset", offset,
                                        "--size-max", max_size,
                                        arg_sync ? "--sync=yes" : "--sync=no",
                                        i->path,
                                        t->target.path,
                                        NULL
                                };

                                execv(SYSTEMD_PULL_PATH, (char *const*) cmdline);
                                log_error_errno(errno, "Failed to execute %s tool: %m", SYSTEMD_PULL_PATH);
                                _exit(EXIT_FAILURE);
                        }
                        break;

                default:
                        assert_not_reached("unexpected target resource type");
                }

                break;

        case RESOURCE_HTTP_TAR:
                assert(IN_SET(t->target.type, RESOURCE_DIRECTORY, RESOURCE_SUBVOLUME));

                r = safe_fork("(sd-pull-tar)", FORK_RESET_SIGNALS|FORK_DEATHSIG|FORK_LOG|FORK_WAIT, NULL);
                if (r < 0)
                        return r;
                if (r == 0) {
                        /* Child */

                        const char *cmdline[] = {
                                "systemd-pull",
                                "tar",
                                "--direct",          /* just download the specified URL, don't download anything else */
                                "--verify", digest,  /* validate by explicit SHA256 sum */
                                t->target.type == RESOURCE_SUBVOLUME ? "--btrfs-subvol=yes" : "--btrfs-subvol=no",
                                arg_sync ? "--sync=yes" : "--sync=no",
                                i->path,
                                t->temporary_path,
                                NULL
                        };

                        execv(SYSTEMD_PULL_PATH, (char *const*) cmdline);
                        log_error_errno(errno, "Failed to execute %s tool: %m", SYSTEMD_PULL_PATH);
                        _exit(EXIT_FAILURE);
                }
                break;

        default:
                assert_not_reached("Unexpected source resource type");
        }

        if (RESOURCE_IS_FILESYSTEM(t->target.type)) {
                bool need_sync = false;
                assert(t->temporary_path);

                /* Apply file attributes if set */
                if (f.mtime != USEC_INFINITY) {
                        struct timespec ts;

                        timespec_store(&ts, f.mtime);

                        if (utimensat(AT_FDCWD, t->temporary_path, (struct timespec[2]) { ts, ts }, AT_SYMLINK_NOFOLLOW) < 0)
                                return log_error_errno(errno, "Failed to adjust mtime of '%s': %m", t->temporary_path);

                        need_sync = true;
                }

                if (f.mode != MODE_INVALID) {
                        if (fchmodat(AT_FDCWD, t->temporary_path, f.mode, AT_SYMLINK_NOFOLLOW) < 0)
                                return log_error_errno(errno, "Failed to adjust mode of '%s': %m", t->temporary_path);

                        need_sync = true;
                }

                /* Synchronize */
                if (arg_sync && need_sync) {
                        if (t->target.type == RESOURCE_REGULAR_FILE)
                                r = fsync_path_and_parent_at(AT_FDCWD, t->temporary_path);
                        else {
                                assert(IN_SET(t->target.type, RESOURCE_DIRECTORY, RESOURCE_SUBVOLUME));
                                r = syncfs_path(AT_FDCWD, t->temporary_path);
                        }
                        if (r < 0)
                                return log_error_errno(r, "Failed to synchronize file system backing '%s': %m", t->temporary_path);
                }
        }

        if (t->target.type == RESOURCE_PARTITION) {
                free_and_replace(t->partition_info.label, formatted_pattern);
                t->partition_change = PARTITION_LABEL;

                if (f.partition_uuid_set) {
                        t->partition_info.uuid = f.partition_uuid;
                        t->partition_change |= PARTITION_UUID;
                }

                if (f.partition_flags_set) {
                        t->partition_info.flags = f.partition_flags;
                        t->partition_change |= PARTITION_FLAGS;
                }
        }

        t->install_read_only = f.read_only;

        /* For regular file cases the only step left is to install the file in place, which
         * instance_install() will do via rename(). For partition cases the only step left is to update the
         * partition table, which is done at the same place. */

        log_info("Successfully acquired '%s'.", i->path);
        return 0;
}

int instance_install(Instance *i) {
        Transfer *t;
        int r;

        assert(i);
        assert(i->resource);
        assert_se(t = container_of(i->resource, Transfer, source));

        if (t->temporary_path) {
                assert(RESOURCE_IS_FILESYSTEM(t->target.type));
                assert(t->final_path);

                r = install_file(AT_FDCWD, t->temporary_path,
                                 AT_FDCWD, t->final_path,
                                 INSTALL_REPLACE|
                                 (t->install_read_only > 0 ? INSTALL_READ_ONLY : 0)|
                                 (t->target.type == RESOURCE_REGULAR_FILE ? INSTALL_FSYNC_FULL : INSTALL_SYNCFS));
                if (r < 0)
                        return log_error_errno(r, "Failed to move '%s' into place: %m", t->final_path);

                log_info("Successfully installed '%s' (%s) as '%s' (%s).",
                         i->path,
                         resource_type_to_string(i->resource->type),
                         t->final_path,
                         resource_type_to_string(t->target.type));

                t->temporary_path = mfree(t->temporary_path);
        }

        if (t->partition_change != 0) {
                assert(t->target.type == RESOURCE_PARTITION);

                r = patch_partition(t->target.path, &t->partition_info, t->partition_change);
                if (r < 0)
                        return r;

                log_info("Successfully installed '%s' (%s) as '%s' (%s).",
                         i->path,
                         resource_type_to_string(i->resource->type),
                         t->partition_info.device,
                         resource_type_to_string(t->target.type));
        }

        if (t->current_symlink) {
                _cleanup_free_ char *buf = NULL, *parent = NULL, *relative = NULL;
                const char *link_path, *link_target;

                if (RESOURCE_IS_FILESYSTEM(t->target.type)) {

                        assert(t->target.path);

                        if (path_is_absolute(t->current_symlink))
                                link_path = t->current_symlink;
                        else {
                                buf = path_make_absolute(t->current_symlink, t->target.path);
                                if (!buf)
                                        return log_oom();

                                link_path = buf;
                        }

                        link_target = t->final_path;

                } else if (t->target.type == RESOURCE_PARTITION) {

                        assert(path_is_absolute(t->current_symlink));

                        link_path = t->current_symlink;
                        link_target = t->partition_info.device;
                } else
                        assert_not_reached("unexpected target resource type");

                if (link_target) {
                        r = path_extract_directory(link_path, &parent);
                        if (r < 0)
                                return log_error_errno(r, "Failed to extract directory of target path '%s': %m", link_path);

                        r = path_make_relative(parent, link_target, &relative);
                        if (r < 0)
                                return log_error_errno(r, "Failed to make symlink path '%s' relative to '%s': %m", link_target, parent);

                        r = symlink_atomic(relative, link_path);
                        if (r < 0)
                                return log_error_errno(r, "Failed to update current symlink '%s' → '%s': %m", link_path, relative);

                        log_info("Updated symlink '%s' → '%s'.", link_path, relative);
                }
        }

        return 0;
}
