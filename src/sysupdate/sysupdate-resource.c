/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "gpt.h"
#include "hexdecoct.h"
#include "import-util.h"
#include "macro.h"
#include "process-util.h"
#include "sort-util.h"
#include "string-table.h"
#include "sysupdate-instance.h"
#include "sysupdate-pattern.h"
#include "sysupdate-resource.h"

void resource_destroy(Resource *rr) {
        assert(rr);

        free(rr->path);
        free(rr->pattern);

        for (size_t i = 0; i < rr->n_instances; i++)
                instance_free(rr->instances[i]);
        free(rr->instances);
}

static int resource_add_instance(
                Resource *rr,
                const char *path,
                const InstanceMetadata *f,
                Instance **ret) {

        Instance **a, *i;
        int r;

        assert(rr);
        assert(path);
        assert(f);
        assert(f->version);

        a = reallocarray(rr->instances, rr->n_instances + 1, sizeof(Instance*));
        if (!a)
                return log_oom();

        rr->instances = a;

        r = instance_new(rr, path, f, &i);
        if (r < 0)
                return r;

        if (ret)
                *ret = i;

        rr->instances[rr->n_instances++] = i;
        return 0;
}

static int resource_load_from_directory(
                Resource *rr,
                mode_t m) {

        _cleanup_(closedirp) DIR *d = NULL;
        int r;

        assert(rr);
        assert(IN_SET(rr->type, RESOURCE_TAR, RESOURCE_REGULAR_FILE, RESOURCE_DIRECTORY, RESOURCE_SUBVOLUME));
        assert(IN_SET(m, S_IFREG, S_IFDIR));

        d = opendir(rr->path);
        if (!d)
                return log_error_errno(errno, "Failed to open directory '%s': %m", rr->path);

        for (;;) {
                _cleanup_(instance_metadata_destroy) InstanceMetadata extracted_fields = INSTANCE_METADATA_NULL;
                _cleanup_free_ char *joined = NULL;
                Instance *instance;
                struct dirent *de;
                struct stat st;

                errno = 0;
                de = readdir_no_dot(d);
                if (!de) {
                        if (errno != 0)
                                return log_error_errno(errno, "Failed to read directory '%s': %m", rr->path);
                        break;
                }

                switch (de->d_type) {

                case DT_UNKNOWN:
                        break;

                case DT_DIR:
                        if (m != S_IFDIR)
                                continue;

                        break;

                case DT_REG:
                        if (m != S_IFREG)
                                continue;
                        break;

                default:
                        continue;
                }

                if (fstatat(dirfd(d), de->d_name, &st, AT_NO_AUTOMOUNT) < 0) {
                        if (errno == ENOENT) /* Gone by now? */
                                continue;

                        return log_error_errno(errno, "Failed to stat %s/%s: %m", rr->path, de->d_name);
                }

                if ((st.st_mode & S_IFMT) != m)
                        continue;

                r = pattern_match(rr->pattern, de->d_name, &extracted_fields);
                if (r < 0)
                        return log_error_errno(r, "Failed to match pattern %s: %m", rr->pattern);
                if (r == 0)
                        continue;

                joined = path_join(rr->path, de->d_name);
                if (!joined)
                        return log_oom();

                r = resource_add_instance(rr, joined, &extracted_fields, &instance);
                if (r < 0)
                        return r;

                /* Inherit these from the source, if not explicitly overwritten */
                if (instance->metadata.mtime == USEC_INFINITY)
                        instance->metadata.mtime = timespec_load(&st.st_mtim) ?: USEC_INFINITY;

                if (instance->metadata.mode == MODE_INVALID)
                        instance->metadata.mode = st.st_mode & 0775; /* mask out world-writability and suid and stuff, for safety */
        }

        return 0;
}

static int resource_load_from_blockdev(Resource *rr) {
        _cleanup_(fdisk_unref_contextp) struct fdisk_context *c = NULL;
        _cleanup_(fdisk_unref_tablep) struct fdisk_table *t = NULL;
        size_t n_partitions;
        int r;

        assert(rr);

        c = fdisk_new_context();
        if (!c)
                return log_oom();

        r = fdisk_assign_device(c, rr->path, /* readonly= */ true);
        if (r < 0)
                return log_error_errno(r, "Failed to open device '%s': %m", rr->path);

        if (!fdisk_is_labeltype(c, FDISK_DISKLABEL_GPT))
                return log_error_errno(SYNTHETIC_ERRNO(EHWPOISON), "Disk %s has no GPT disk label, not suitable.", rr->path);

        r = fdisk_get_partitions(c, &t);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire partition table: %m");

        n_partitions = fdisk_table_get_nents(t);
        for (size_t i = 0; i < n_partitions; i++)  {
                _cleanup_(instance_metadata_destroy) InstanceMetadata extracted_fields = INSTANCE_METADATA_NULL;
                _cleanup_(partition_info_destroy) PartitionInfo pinfo = PARTITION_INFO_NULL;
                Instance *instance;

                r = read_partition_info(c, t, i, &pinfo);
                if (r < 0)
                        return r;
                if (r == 0) /* not assigned */
                        continue;

                /* Check if partition type matches */
                if (rr->partition_type_set && !sd_id128_equal(pinfo.type, rr->partition_type))
                        continue;

                /* An empty label means "not used so far" for us */
                if (isempty(pinfo.label)) {
                        rr->n_empty++;
                        continue;
                }

                r = pattern_match(rr->pattern, pinfo.label, &extracted_fields);
                if (r < 0)
                        return log_error_errno(r, "Failed to match pattern %s: %m", rr->pattern);
                if (r == 0)
                        continue;

                r = resource_add_instance(rr, pinfo.device, &extracted_fields, &instance);
                if (r < 0)
                        return r;

                instance->partition_info = pinfo;
                pinfo = (PartitionInfo) PARTITION_INFO_NULL;

                /* Inherit data from source if not configured explicitly */
                if (!instance->metadata.partition_uuid_set) {
                        instance->metadata.partition_uuid = instance->partition_info.uuid;
                        instance->metadata.partition_uuid_set = true;
                }

                if (!instance->metadata.partition_flags_set) {
                        instance->metadata.partition_flags = instance->partition_info.flags;
                        instance->metadata.partition_flags_set = true;
                }

                if (instance->metadata.read_only < 0)
                        instance->metadata.read_only = instance->partition_info.read_only;
        }

        return 0;
}

static int download_manifest(const char *url, char **ret_buffer, size_t *ret_size) {
        _cleanup_(close_pairp) int pfd[2] = { -1, -1 };
        _cleanup_fclose_ FILE *manifest = NULL;
        _cleanup_free_ char *buffer = NULL;
        size_t size;
        pid_t pid;
        int r;

        assert(url);
        assert(ret_buffer);
        assert(ret_size);

        /* Download a SHA256SUMS file as manifest */

        if (pipe2(pfd, O_CLOEXEC) < 0)
                return log_error_errno(errno, "Failed to allocate pipe: %m");

        r = safe_fork("(sd-pull)", FORK_RESET_SIGNALS|FORK_DEATHSIG|FORK_LOG, &pid);
        if (r < 0)
                return r;
        if (r == 0) {
                /* Child */

                const char *cmdline[] = {
                        "systemd-pull",
                        "raw",
                        "--direct",           /* just download the specified URL, don't download anything else */
                        "--verify=signature", /* verify the manifest file */
                        url,
                        "-",                  /* write to stdout */
                        NULL
                };

                pfd[0] = safe_close(pfd[0]);

                r = rearrange_stdio(-1, pfd[1], STDERR_FILENO);
                if (r < 0) {
                        log_error_errno(r, "Failed to rearrange stdin/stdout: %m");
                        _exit(EXIT_FAILURE);
                }

                execv(SYSTEMD_PULL_PATH, (char *const*) cmdline);
                log_error_errno(errno, "Failed to execute %s tool: %m", SYSTEMD_PULL_PATH);
                _exit(EXIT_FAILURE);
        };

        pfd[1] = safe_close(pfd[1]);

        /* We'll first load the entire manifest into memory before parsing it. That's because the
         * systemd-pull tool can validate the download only after its completion, but still pass the data to
         * us as it runs. We thus need to check the return value of the process *before* parsing, to be
         * reasonably safe. */

        manifest = fdopen(pfd[0], "r");
        if (!manifest)
                return log_error_errno(r, "Failed allocate FILE object for manifest file: %m");

        TAKE_FD(pfd[0]);

        r = read_full_stream(manifest, &buffer, &size);
        if (r < 0)
                return log_error_errno(r, "Failed to read manifest file from child: %m");

        manifest = safe_fclose(manifest);

        r = wait_for_terminate_and_check("(sd-pull)", pid, WAIT_LOG);
        if (r < 0)
                return r;

        *ret_buffer = TAKE_PTR(buffer);
        *ret_size = size;

        return 0;
}

static int resource_load_from_web(Resource *rr) {
        _cleanup_free_ char *manifest = NULL;
        size_t manifest_size, left;
        const char *p;
        size_t line_nr = 1;
        int r;

        r = download_manifest(rr->path, &manifest, &manifest_size);
        if (r < 0)
                return r;

        if (memchr(manifest, 0, manifest_size))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Manifest file has embedded NUL byte, refusing.");

        p = manifest;
        left = manifest_size;

        while (left > 0) {
                _cleanup_(instance_metadata_destroy) InstanceMetadata extracted_fields = INSTANCE_METADATA_NULL;
                _cleanup_free_ char *fn = NULL, *path = NULL;
                _cleanup_free_ void *h = NULL;
                Instance *instance;
                const char *e;
                size_t hlen;

                /* 64 character hash + separator + filename + newline */
                if (left < 67)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Corrupt manifest at line %zu, refusing.", line_nr);

                if (p[0] == '\\')
                        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "File names with escapes not supported in manifest at line %zu, refusing.", line_nr);

                r = unhexmem(p, 64, &h, &hlen);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse digest at manifest line %zu, refusing.", line_nr);

                p += 64, left -= 64;

                if (*p != ' ')
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Missing space separator at manifest line %zu, refusing.", line_nr);
                p++, left--;

                if (!IN_SET(*p, '*', ' '))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Missing binary/text input marker at manifest line %zu, refusing.", line_nr);
                p++, left--;

                e = memchr(p, '\n', left);
                if (!e)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Truncated manifest file at line %zu, refusing.", line_nr);
                if (e == p)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Empty filename specified at manifest line %zu, refusing.", line_nr);

                fn = strndup(p, e - p);
                if (!fn)
                        return log_oom();

                if (!filename_is_valid(fn))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid filename specified at manifest line %zu, refusing.", line_nr);

                r = pattern_match(rr->pattern, fn, &extracted_fields);
                if (r < 0)
                        return log_error_errno(r, "Failed to match pater %s: %m", rr->pattern);
                if (r == 0)
                        continue;

                r = import_url_change_last_component(rr->path, fn, &path);
                if (r < 0)
                        return log_error_errno(r, "Failed to build instance URL: %m");

                r = resource_add_instance(rr, path, &extracted_fields, &instance);
                if (r < 0)
                        return r;

                assert(hlen == sizeof(instance->metadata.sha256sum));

                if (instance->metadata.sha256sum_set) {
                        if (memcmp(instance->metadata.sha256sum, h, hlen) != 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "SHA256 sum pared from filename and manifest don't match at line %zu, refusing.", line_nr);
                } else {
                        memcpy(instance->metadata.sha256sum, h, hlen);
                        instance->metadata.sha256sum_set = true;
                }

                line_nr++;
        }

        return 0;
}

static int instance_cmp(Instance *const*a, Instance *const*b) {
        assert(*a);
        assert(*b);
        assert((*a)->metadata.version);
        assert((*b)->metadata.version);

        /* Newest version at the beginning */
        return -strverscmp((*a)->metadata.version, (*b)->metadata.version);
}

int resource_load_instances(Resource *rr) {
        int r;

        assert(rr);

        switch (rr->type) {

        case RESOURCE_TAR:
        case RESOURCE_REGULAR_FILE:
                r = resource_load_from_directory(rr, S_IFREG);
                break;

        case RESOURCE_DIRECTORY:
        case RESOURCE_SUBVOLUME:
                r = resource_load_from_directory(rr, S_IFDIR);
                break;

        case RESOURCE_PARTITION:
                r = resource_load_from_blockdev(rr);
                break;

        case RESOURCE_HTTP_FILE:
        case RESOURCE_HTTP_TAR:
                r = resource_load_from_web(rr);
                break;

        default:
                assert_not_reached("Unknown resource type");
        }
        if (r < 0)
                return r;

        typesafe_qsort(rr->instances, rr->n_instances, instance_cmp);
        return 0;
}

Instance* resource_find_instance(Resource *rr, const char *version) {
        Instance key = {
                .metadata.version = (char*) version,
        }, *k = &key;

        return typesafe_bsearch(&k, rr->instances, rr->n_instances, instance_cmp);
}

static const char *resource_type_table[_RESOURCE_TYPE_MAX] = {
        [RESOURCE_HTTP_FILE]    = "http-file",
        [RESOURCE_HTTP_TAR]     = "http-tar",
        [RESOURCE_TAR]          = "tar",
        [RESOURCE_PARTITION]    = "partition",
        [RESOURCE_REGULAR_FILE] = "regular-file",
        [RESOURCE_DIRECTORY]    = "directory",
        [RESOURCE_SUBVOLUME]    = "subvolume",
};

DEFINE_STRING_TABLE_LOOKUP(resource_type, ResourceType);
