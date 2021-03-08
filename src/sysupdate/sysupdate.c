/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <unistd.h>

#include "conf-files.h"
#include "def.h"
#include "format-table.h"
#include "hexdecoct.h"
#include "locale-util.h"
#include "main-func.h"
#include "pager.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "pretty-print.h"
#include "sort-util.h"
#include "strv.h"
#include "sysupdate-transfer.h"
#include "sysupdate-update-set.h"
#include "sysupdate.h"
#include "terminal-util.h"
#include "verbs.h"

/* TODO:
 *
 *   --root=/--image= support
 *   boot assessment counter support
 *   TPM2 support
 *   casync support
 *   bsd blockdev lock
 *   "reboot" verb
 *   optionally mark generated files/partitions/subvols read-only
 */

static char *arg_definitions = NULL;
bool arg_sync = true;
uint64_t arg_instances_max = UINT64_MAX;
static JsonFormatFlags arg_json_format_flags = JSON_FORMAT_OFF;
static PagerFlags arg_pager_flags = 0;
static bool arg_legend = true;

STATIC_DESTRUCTOR_REGISTER(arg_definitions, freep);

typedef struct Context Context;

struct Context {
        Transfer **transfers;
        size_t n_transfers;

        UpdateSet **update_sets;
        size_t n_update_sets;

        UpdateSet *newest_installed, *candidate;
};

static Context *context_free(Context *c) {
        if (!c)
                return NULL;

        for (size_t i = 0; i < c->n_transfers; i++)
                transfer_free(c->transfers[i]);
        free(c->transfers);

        for (size_t i = 0; i < c->n_update_sets; i++)
                update_set_free(c->update_sets[i]);
        free(c->update_sets);

        return mfree(c);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Context*, context_free);

static Context *context_new(void) {
        Context *c;

        c = new(Context, 1);
        if (!c)
                return NULL;

        *c = (Context) {
        };

        return c;
}

static int context_read_definitions(
                Context *c,
                const char *directory,
                const char *root) {

        _cleanup_strv_free_ char **files = NULL;
        char **f;
        int r;

        assert(c);

        if (directory)
                r = conf_files_list_strv(&files, ".conf", NULL, CONF_FILES_REGULAR|CONF_FILES_FILTER_MASKED, (const char**) STRV_MAKE(directory));
        else
                r = conf_files_list_strv(&files, ".conf", root, CONF_FILES_REGULAR|CONF_FILES_FILTER_MASKED, (const char**) CONF_PATHS_STRV("sysupdate.d"));
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate *.conf files: %m");

        STRV_FOREACH(f, files) {
                _cleanup_(transfer_freep) Transfer *t = NULL;
                Transfer **a;

                a = reallocarray(c->transfers, c->n_transfers + 1, sizeof(Transfer*));
                if (!a)
                        return log_oom();

                c->transfers = a;

                t = transfer_new();
                if (!t)
                        return log_oom();

                t->definition_path = strdup(*f);
                if (!t->definition_path)
                        return log_oom();

                r = transfer_read_definition(t, *f);
                if (r < 0)
                        return r;

                c->transfers[c->n_transfers++] = TAKE_PTR(t);
        }

        if (c->n_transfers == 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT),
                                       "No transfer definitions loaded.");

        for (size_t i = 0; i < c->n_transfers; i++) {
                r = transfer_resolve_paths(c->transfers[i]);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int context_load_installed_instances(Context *c) {
        int r;

        assert(c);

        log_info("Discovering installed instances...");

        for (size_t i = 0; i < c->n_transfers; i++) {
                r = resource_load_instances(&c->transfers[i]->target);
                if (r < 0)
                        return r;
        }

        return 0;
}


static int context_load_available_instances(Context *c) {
        int r;

        assert(c);

        log_info("Discovering available instances...");

        for (size_t i = 0; i < c->n_transfers; i++) {
                r = resource_load_instances(&c->transfers[i]->source);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int context_discover_update_sets_by_flag(Context *c, UpdateSetFlags flags) {
        _cleanup_free_ Instance **cursor_instances = NULL;
        _cleanup_free_ char *boundary = NULL;
        _cleanup_(strv_freep) char **l = NULL;
        bool newest_found = false;
        int r;

        assert(c);
        assert(IN_SET(flags, UPDATE_AVAILABLE, UPDATE_INSTALLED));

        for (;;) {
                bool incomplete = false, exists = false;
                UpdateSetFlags extra_flags = 0;
                _cleanup_free_ char *cursor = NULL;
                UpdateSet **a = NULL, *us = NULL;

                for (size_t k = 0; k < c->n_transfers; k++) {
                        Transfer *t = c->transfers[k];
                        bool cursor_found = false;
                        Resource *rr;

                        if (flags == UPDATE_AVAILABLE)
                                rr = &t->source;
                        else {
                                assert(flags == UPDATE_INSTALLED);
                                rr = &t->target;
                        }

                        for (size_t j = 0; j < rr->n_instances; j++) {
                                Instance *i = rr->instances[j];

                                /* Is the instance we are looking at equal or newer than the boundary? If so, we
                                 * already checked this version, and it wasn't complete, let's ignore it. */
                                if (boundary && strverscmp(i->metadata.version, boundary) >= 0)
                                        continue;

                                if (cursor) {
                                        if (strverscmp(i->metadata.version, cursor) != 0)
                                                continue;

                                } else {
                                        cursor = strdup(i->metadata.version);
                                        if (!cursor)
                                                return log_oom();
                                }

                                cursor_found = true;

                                if (!cursor_instances) {
                                        cursor_instances = new(Instance*, c->n_transfers);
                                        if (!cursor_instances)
                                                return -ENOMEM;
                                }
                                cursor_instances[k] = i;
                                break;
                        }

                        if (!cursor) /* No suitable instance beyond the boundary found? Then we are done! */
                                break;

                        if (!cursor_found) {
                                /* Hmm, we didn't find the version indicated by 'cursor' among the instances
                                 * of this transfer, let's skip it. */
                                incomplete = true;
                                break;
                        }

                        if (t->min_version && strverscmp(t->min_version, cursor) > 0)
                                extra_flags |= UPDATE_OBSOLETE;

                        if (strv_contains(t->protected_versions, cursor))
                                extra_flags |= UPDATE_PROTECTED;
                }

                if (!cursor) /* EOL */
                        break;

                r = free_and_strdup_warn(&boundary, cursor);
                if (r < 0)
                        return r;

                if (incomplete) /* One transfer was missing this version, ignore the whole thing */
                        continue;

                /* See if we already have this update set in our table */
                for (size_t i = 0; i < c->n_update_sets; i++)
                        if (strverscmp(c->update_sets[i]->version, cursor) == 0) {
                                /* We only store the instances we found first, but we remember we also found it again */
                                c->update_sets[i]->flags |= flags | extra_flags;
                                exists = true;
                                newest_found = true;
                                break;
                        }

                if (exists)
                        continue;

                /* Doesn't exist yet, let's add it */
                a = reallocarray(c->update_sets, c->n_update_sets + 1, sizeof(UpdateSet*));
                if (!a)
                        return log_oom();

                c->update_sets = a;

                us = new(UpdateSet, 1);
                if (!us)
                        return log_oom();

                *us = (UpdateSet) {
                        .flags = flags | (newest_found ? 0 : UPDATE_NEWEST) | extra_flags,
                        .version = TAKE_PTR(cursor),
                        .instances = TAKE_PTR(cursor_instances),
                        .n_instances = c->n_transfers,
                };

                c->update_sets[c->n_update_sets++] = us;

                newest_found = true;

                /* Remember which one is the newest installed */
                if ((us->flags & (UPDATE_NEWEST|UPDATE_INSTALLED)) == (UPDATE_NEWEST|UPDATE_INSTALLED))
                        c->newest_installed = us;

                /* Remember which is the newest non-obsolete, available (and not installed) version, which we declare the "candidate" */
                if ((us->flags & (UPDATE_NEWEST|UPDATE_INSTALLED|UPDATE_AVAILABLE|UPDATE_OBSOLETE)) == (UPDATE_NEWEST|UPDATE_AVAILABLE))
                        c->candidate = us;
        }

        /* Newest installed is newer than or equal to candidate? Then suppress the candidate */
        if (c->newest_installed && c->candidate && strverscmp(c->newest_installed->version, c->candidate->version) >= 0)
                c->candidate = NULL;

        return 0;
}

static int context_discover_update_sets(Context *c) {
        int r;

        assert(c);

        log_info("Determining installed update sets...");

        r = context_discover_update_sets_by_flag(c, UPDATE_INSTALLED);
        if (r < 0)
                return r;

        log_info("Determining available update sets...");

        r = context_discover_update_sets_by_flag(c, UPDATE_AVAILABLE);
        if (r < 0)
                return r;

        typesafe_qsort(c->update_sets, c->n_update_sets, update_set_cmp);
        return 0;
}

static const char *update_set_flags_to_string(UpdateSetFlags flags) {

        switch ((unsigned) flags) {

        case 0:
                return "n/a";

        case UPDATE_INSTALLED|UPDATE_NEWEST:
        case UPDATE_INSTALLED|UPDATE_NEWEST|UPDATE_PROTECTED:
        case UPDATE_INSTALLED|UPDATE_AVAILABLE|UPDATE_NEWEST:
        case UPDATE_INSTALLED|UPDATE_AVAILABLE|UPDATE_NEWEST|UPDATE_PROTECTED:
                return "current";

        case UPDATE_AVAILABLE|UPDATE_NEWEST:
        case UPDATE_AVAILABLE|UPDATE_NEWEST|UPDATE_PROTECTED:
                return "candidate";

        case UPDATE_INSTALLED:
        case UPDATE_INSTALLED|UPDATE_AVAILABLE:
                return "installed";

        case UPDATE_INSTALLED|UPDATE_PROTECTED:
        case UPDATE_INSTALLED|UPDATE_AVAILABLE|UPDATE_PROTECTED:
                return "protected";

        case UPDATE_AVAILABLE:
        case UPDATE_AVAILABLE|UPDATE_PROTECTED:
                return "available";

        case UPDATE_INSTALLED|UPDATE_OBSOLETE|UPDATE_NEWEST:
        case UPDATE_INSTALLED|UPDATE_OBSOLETE|UPDATE_NEWEST|UPDATE_PROTECTED:
        case UPDATE_INSTALLED|UPDATE_AVAILABLE|UPDATE_OBSOLETE|UPDATE_NEWEST:
        case UPDATE_INSTALLED|UPDATE_AVAILABLE|UPDATE_OBSOLETE|UPDATE_NEWEST|UPDATE_PROTECTED:
                return "current+obsolete";

        case UPDATE_INSTALLED|UPDATE_OBSOLETE:
        case UPDATE_INSTALLED|UPDATE_AVAILABLE|UPDATE_OBSOLETE:
                return "installed+obsolete";

        case UPDATE_INSTALLED|UPDATE_OBSOLETE|UPDATE_PROTECTED:
        case UPDATE_INSTALLED|UPDATE_AVAILABLE|UPDATE_OBSOLETE|UPDATE_PROTECTED:
                return "protected+obsolete";

        case UPDATE_AVAILABLE|UPDATE_OBSOLETE:
        case UPDATE_AVAILABLE|UPDATE_OBSOLETE|UPDATE_PROTECTED:
        case UPDATE_AVAILABLE|UPDATE_OBSOLETE|UPDATE_NEWEST:
        case UPDATE_AVAILABLE|UPDATE_OBSOLETE|UPDATE_NEWEST|UPDATE_PROTECTED:
                return "available+obsolete";

        default:
                assert_not_reached("Unexpected flags");
        }
}


static int context_show_table(Context *c) {
        _cleanup_(table_unrefp) Table *t = NULL;
        int r;

        assert(c);

        t = table_new("", "version", "i", "a", "assessment");
        if (!t)
                return log_oom();

        (void) table_set_align_percent(t, table_get_cell(t, 0, 0), 100);

        for (size_t i = 0; i < c->n_update_sets; i++) {
                UpdateSet *us = c->update_sets[i];
                const char *color;

                color = update_set_flags_to_color(us->flags);

                r = table_add_many(t,
                                   TABLE_STRING,    update_set_flags_to_glyph(us->flags),
                                   TABLE_SET_COLOR, color,
                                   TABLE_STRING,    us->version,
                                   TABLE_SET_COLOR, color,
                                   TABLE_STRING,    special_glyph_check_mark_space(FLAGS_SET(us->flags, UPDATE_INSTALLED)),
                                   TABLE_SET_COLOR, color,
                                   TABLE_STRING,    special_glyph_check_mark_space(FLAGS_SET(us->flags, UPDATE_AVAILABLE)),
                                   TABLE_SET_COLOR, color,
                                   TABLE_STRING,    update_set_flags_to_string(us->flags),
                                   TABLE_SET_COLOR, color);
                if (r < 0)
                        return table_log_add_error(r);
        }

        return table_print_with_pager(t, arg_json_format_flags, arg_pager_flags, arg_legend);
}

static UpdateSet *context_update_set_by_version(Context *c, const char *version) {
        assert(c);
        assert(version);

        for (size_t i = 0; i < c->n_update_sets; i++)
                if (streq(c->update_sets[i]->version, version))
                        return c->update_sets[i];

        return NULL;
}

static int context_show_version(Context *c, const char *version) {
        bool show_fs_columns = false, show_partition_columns = false,
                have_fs_attributes = false, have_partition_attributes = false,
                have_size = false, have_tries = false, have_ro = false, have_sha256 = false;
        _cleanup_(table_unrefp) Table *t = NULL;
        UpdateSet *us;
        int r;

        assert(c);
        assert(version);

        us = context_update_set_by_version(c, version);
        if (!us)
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "Update '%s' not found.", version);

        if (arg_json_format_flags & (JSON_FORMAT_OFF|JSON_FORMAT_PRETTY|JSON_FORMAT_PRETTY_AUTO))
                (void) pager_open(arg_pager_flags);

        printf("%s%s%s Version: %s\n"
               "    State: %s%s%s\n"
               "Installed: %s%s\n"
               "Available: %s%s\n"
               "Protected: %s%s%s\n"
               " Obsolete: %s%s%s\n\n",
               strempty(update_set_flags_to_color(us->flags)), update_set_flags_to_glyph(us->flags), ansi_normal(), us->version,
               strempty(update_set_flags_to_color(us->flags)), update_set_flags_to_string(us->flags), ansi_normal(),
               yes_no(us->flags & UPDATE_INSTALLED), FLAGS_SET(us->flags, UPDATE_INSTALLED|UPDATE_NEWEST) ? " (newest)" : "",
               yes_no(us->flags & UPDATE_AVAILABLE), (us->flags & (UPDATE_INSTALLED|UPDATE_AVAILABLE|UPDATE_NEWEST)) == (UPDATE_AVAILABLE|UPDATE_NEWEST) ? " (newest)" : "",
               FLAGS_SET(us->flags, UPDATE_INSTALLED|UPDATE_PROTECTED) ? ansi_highlight() : "", yes_no(FLAGS_SET(us->flags, UPDATE_INSTALLED|UPDATE_PROTECTED)), ansi_normal(),
               us->flags & UPDATE_OBSOLETE ? ansi_highlight_red() : "", yes_no(us->flags & UPDATE_OBSOLETE), ansi_normal());

        t = table_new("type", "path", "ptuuid", "ptflags", "mtime", "mode", "size", "tries-done", "tries-left", "ro", "sha256");
        if (!t)
                return log_oom();

        (void) table_set_align_percent(t, table_get_cell(t, 0, 3), 100);
        (void) table_set_align_percent(t, table_get_cell(t, 0, 4), 100);
        (void) table_set_align_percent(t, table_get_cell(t, 0, 5), 100);
        (void) table_set_align_percent(t, table_get_cell(t, 0, 6), 100);
        (void) table_set_align_percent(t, table_get_cell(t, 0, 7), 100);
        (void) table_set_align_percent(t, table_get_cell(t, 0, 8), 100);
        (void) table_set_empty_string(t, "-");

        /* Determine if the target will make use of partition/fs attributes for any of the transfers */
        for (size_t n = 0; n < c->n_transfers; n++) {
                Transfer *tr = c->transfers[n];

                if (tr->target.type == RESOURCE_PARTITION)
                        show_partition_columns = true;
                if (RESOURCE_IS_FILESYSTEM(tr->target.type))
                        show_fs_columns = true;
        }

        for (size_t n = 0; n < us->n_instances; n++) {
                Instance *i = us->instances[n];

                r = table_add_many(t,
                                   TABLE_STRING, resource_type_to_string(i->resource->type),
                                   TABLE_PATH, i->path);
                if (r < 0)
                        return table_log_add_error(r);

                if (i->metadata.partition_uuid_set) {
                        have_partition_attributes = true;
                        r = table_add_cell(t, NULL, TABLE_UUID, &i->metadata.partition_uuid);
                } else
                        r = table_add_cell(t, NULL, TABLE_EMPTY, NULL);
                if (r < 0)
                        return table_log_add_error(r);

                if (i->metadata.partition_flags_set) {
                        have_partition_attributes = true;
                        r = table_add_cell(t, NULL, TABLE_UINT64_HEX, &i->metadata.partition_flags);
                } else
                        r = table_add_cell(t, NULL, TABLE_EMPTY, NULL);
                if (r < 0)
                        return table_log_add_error(r);

                if (i->metadata.mtime != USEC_INFINITY) {
                        have_fs_attributes = true;
                        r = table_add_cell(t, NULL, TABLE_TIMESTAMP, &i->metadata.mtime);
                } else
                        r = table_add_cell(t, NULL, TABLE_EMPTY, NULL);
                if (r < 0)
                        return table_log_add_error(r);

                if (i->metadata.mode != MODE_INVALID) {
                        have_fs_attributes = true;
                        r = table_add_cell(t, NULL, TABLE_MODE, &i->metadata.mode);
                } else
                        r = table_add_cell(t, NULL, TABLE_EMPTY, NULL);
                if (r < 0)
                        return table_log_add_error(r);

                if (i->metadata.size != UINT64_MAX) {
                        have_size = true;
                        r = table_add_cell(t, NULL, TABLE_SIZE, &i->metadata.size);
                } else
                        r = table_add_cell(t, NULL, TABLE_EMPTY, NULL);
                if (r < 0)
                        return table_log_add_error(r);

                if (i->metadata.tries_done != UINT64_MAX) {
                        have_tries = true;
                        r = table_add_cell(t, NULL, TABLE_UINT64, &i->metadata.tries_done);
                } else
                        r = table_add_cell(t, NULL, TABLE_EMPTY, NULL);
                if (r < 0)
                        return table_log_add_error(r);

                if (i->metadata.tries_left != UINT64_MAX) {
                        have_tries = true;
                        r = table_add_cell(t, NULL, TABLE_UINT64, &i->metadata.tries_left);
                } else
                        r = table_add_cell(t, NULL, TABLE_EMPTY, NULL);
                if (r < 0)
                        return table_log_add_error(r);

                if (i->metadata.read_only >= 0) {
                        bool b;

                        have_ro = true;
                        b = i->metadata.read_only;
                        r = table_add_cell(t, NULL, TABLE_BOOLEAN, &b);
                } else
                        r = table_add_cell(t, NULL, TABLE_EMPTY, NULL);
                if (r < 0)
                        return table_log_add_error(r);

                if (i->metadata.sha256sum_set) {
                        _cleanup_free_ char *formatted = NULL;

                        have_sha256 = true;

                        formatted = hexmem(i->metadata.sha256sum, sizeof(i->metadata.sha256sum));
                        if (!formatted)
                                return log_oom();

                        r = table_add_cell(t, NULL, TABLE_STRING, formatted);
                } else
                        r = table_add_cell(t, NULL, TABLE_EMPTY, NULL);
                if (r < 0)
                        return table_log_add_error(r);
        }

        /* Hide the fs/partition columns if we don't have any data to show there */
        if (!have_fs_attributes)
                show_fs_columns = false;
        if (!have_partition_attributes)
                show_partition_columns = false;

        if (!show_partition_columns)
                (void) table_hide_column_from_display(t, 2, 3);
        if (!show_fs_columns)
                (void) table_hide_column_from_display(t, 4, 5);
        if (!have_size)
                (void) table_hide_column_from_display(t, 6);
        if (!have_tries)
                (void) table_hide_column_from_display(t, 7, 8);
        if (!have_ro)
                (void) table_hide_column_from_display(t, 9);
        if (!have_sha256)
                (void) table_hide_column_from_display(t, 10);

        return table_print_with_pager(t, arg_json_format_flags, arg_pager_flags, arg_legend);
}

static int context_make_room(
                Context *c,
                uint64_t space,
                const char *extra_protected_version) {

        int r, count = 0;

        assert(c);

        if (space == 0)
                log_info("Making room...");
        else
                log_info("Making room for %" PRIu64 " updates...", space);

        for (size_t i = 0; i < c->n_transfers; i++) {
                r = transfer_make_room(c->transfers[i], space, extra_protected_version);
                if (r < 0)
                        return r;

                count = MAX(count, r);
        }

        if (count > 0)
                log_info("Removed %i instances.", count);
        else
                log_info("Removed no instances.");

        return 0;
}

static int context_make_offline(Context **ret) {
        _cleanup_(context_freep) Context* context = NULL;
        int r;

        assert(ret);

        /* Allocates a context object and initializes everything we can initialize offline, i.e. without
         * checking on the update source (i.e. the Internet) what versions are available */

        context = context_new();
        if (!context)
                return log_oom();

        r = context_read_definitions(context, arg_definitions, NULL);
        if (r < 0)
                return r;

        r = context_load_installed_instances(context);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(context);
        return 0;
}

static int context_make_online(Context **ret) {
        _cleanup_(context_freep) Context* context = NULL;
        int r;

        assert(ret);

        /* Like context_make_offline(), but also communicates with the update source looking for new
         * versions. */

        r = context_make_offline(&context);
        if (r < 0)
                return r;

        r = context_load_available_instances(context);
        if (r < 0)
                return r;

        r = context_discover_update_sets(context);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(context);
        return 0;
}

static int context_apply(
                Context *c,
                const char *version) {

        UpdateSet *us = NULL;
        int r;

        assert(c);

        if (version) {
                us = context_update_set_by_version(c, version);
                if (!us)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "Update '%s' not found.", version);
        } else {
                if (!c->candidate) {
                        log_info("No update needed.");
                        return 0;
                }

                us = c->candidate;
        }

        if (FLAGS_SET(us->flags, UPDATE_INSTALLED)) {
                log_info("Selected update '%s' is already installed. Skipping update.", us->version);
                return 0;
        }
        if (!FLAGS_SET(us->flags, UPDATE_AVAILABLE))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Selected update '%s' is not available, can't work.", us->version);
        if (FLAGS_SET(us->flags, UPDATE_OBSOLETE))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Selected update '%s' is obsolete, refusing.", us->version);

        assert((us->flags & (UPDATE_AVAILABLE|UPDATE_INSTALLED|UPDATE_OBSOLETE)) == UPDATE_AVAILABLE);

        if (!FLAGS_SET(us->flags, UPDATE_NEWEST))
                log_notice("Selected update '%s' is not the newest, proceeding anyway.", us->version);
        if (c->newest_installed && strverscmp(c->newest_installed->version, us->version) > 0)
                log_notice("Selected update '%s' is older than newest installed version, proceeding anyway.", us->version);

        log_info("Selected update '%s' for install.", us->version);

        /* Let's make some room. We make sure for each transfer we have one free space to fill. While
         * removing stuff we'll protect the version we are trying to acquire. Why that? Maybe an earlier
         * download succeeded already, in which case we shouldn't remove it just to acquire it again */
        r = context_make_room(
                        c,
                        /* space = */ 1,
                        /* extra_protected_version = */ us->version);
        if (r < 0)
                return r;

        if (arg_sync)
                sync();

        for (size_t i = 0; i < us->n_instances; i++) {
                r = instance_acquire(us->instances[i]);
                if (r < 0)
                        return r;
        }

        if (arg_sync)
                sync();

        for (size_t i = 0; i < us->n_instances; i++) {
                r = instance_install(us->instances[i]);
                if (r < 0)
                        return r;
        }

        log_info("Successfully installed update '%s'.", us->version);
        return 0;
}

static int verb_list(int argc, char **argv, void *userdata) {
        _cleanup_(context_freep) Context* context = NULL;
        const char *version;
        int r;

        assert(argc <= 2);
        version = argc >= 2 ? argv[1] : NULL;

        r = context_make_online(&context);
        if (r < 0)
                return r;

        if (version)
                return context_show_version(context, version);
        else
                return context_show_table(context);
}

static int verb_test(int argc, char **argv, void *userdata) {
        _cleanup_(context_freep) Context* context = NULL;
        int r;

        assert(argc <= 1);

        r = context_make_online(&context);
        if (r < 0)
                return r;

        if (!context->candidate) {
                log_debug("No candidate found.");
                return EXIT_FAILURE;
        }

        puts(context->candidate->version);
        return EXIT_SUCCESS;
}

static int verb_make_room(int argc, char **argv, void *userdata) {
        _cleanup_(context_freep) Context* context = NULL;
        int r;

        assert(argc <= 1);

        r = context_make_offline(&context);
        if (r < 0)
                return r;

        return context_make_room(context, 0, NULL);
}

static int verb_now(int argc, char **argv, void *userdata) {
        _cleanup_(context_freep) Context* context = NULL;
        const char *version;
        int r;

        assert(argc <= 2);
        version = argc >= 2 ? argv[1] : NULL;

        r = context_make_online(&context);
        if (r < 0)
                return r;

        return context_apply(context, version);
}

static int verb_help(int argc, char **argv, void *userdata) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-sysupdate", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s [OPTIONS...] [VERSION]\n"
               "\n%5$sUpdate OS images.%6$s\n"
               "\n%3$sCommands:%4$s\n"
               "  list [VERSION]          Show installed and available versions\n"
               "  test                    Test if there's a new version to upgrade to\n"
               "  now [VERSION]           Update now\n"
               "  make-room               Make room, by deleting old instances\n"
               "  -h --help               Show this help\n"
               "     --version            Show package version\n"
               "\n%3$sOptions:%4$s\n"
               "     --no-pager           Do not pipe output into a pager\n"
               "     --no-legend          Do not show the headers and footers\n"
               "     --definitions=DIR    Find transfer definitions in specified directory\n"
               "     --instances-max=INT  How many instances to maintain\n"
               "     --sync=BOOL          Controls whether to sync data to disk\n"
               "     --json=pretty|short|off\n"
               "                          Generate JSON output\n"
               "\nSee the %2$s for details.\n"
               , program_invocation_short_name
               , link
               , ansi_underline(), ansi_normal()
               , ansi_highlight(), ansi_normal()
        );

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_NO_PAGER,
                ARG_NO_LEGEND,
                ARG_TEST,
                ARG_NOW,
                ARG_MAKE_ROOM,
                ARG_SYNC,
                ARG_DEFINITIONS,
                ARG_JSON,
        };

        static const struct option options[] = {
                { "help",              no_argument,       NULL, 'h'                   },
                { "version",           no_argument,       NULL, ARG_VERSION           },
                { "no-pager",          no_argument,       NULL, ARG_NO_PAGER          },
                { "no-legend",         no_argument,       NULL, ARG_NO_LEGEND         },
                { "definitions",       required_argument, NULL, ARG_DEFINITIONS       },
                { "instances-max",     required_argument, NULL, 'm'                   },
                { "sync",              required_argument, NULL, ARG_SYNC              },
                { "json",              required_argument, NULL, ARG_JSON              },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hm:", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        return verb_help(0, NULL, NULL);

                case ARG_VERSION:
                        return version();

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case ARG_NO_LEGEND:
                        arg_legend = false;
                        break;

                case 'm':
                        r = safe_atou64(optarg, &arg_instances_max);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --instances-max= parameter: %s", optarg);

                        break;

                case ARG_SYNC:
                        r = parse_boolean_argument("--sync=", optarg, &arg_sync);
                        if (r < 0)
                                return r;
                        break;

                case ARG_DEFINITIONS:
                        r = parse_path_argument(optarg, false, &arg_definitions);
                        if (r < 0)
                                return r;
                        break;

                case ARG_JSON:
                        r = parse_json_argument(optarg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;

                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }
        }

        return 1;
}

static int sysupdate_main(int argc, char *argv[]) {

        static const Verb verbs[] = {
                { "list",      VERB_ANY, 2, VERB_DEFAULT, verb_list      },
                { "test",      VERB_ANY, 1, 0,            verb_test      },
                { "now",       VERB_ANY, 2, 0,            verb_now       },
                { "make-room", VERB_ANY, 1, 0,            verb_make_room },
                { "help",      VERB_ANY, 1, 0,            verb_help      },
                {}
        };

        return dispatch_verb(argc, argv, verbs, NULL);
}

static int run(int argc, char *argv[]) {
        int r;

        log_set_max_level(LOG_DEBUG); // FIXME
        log_setup();

        arg_definitions = strdup("/home/lennart/projects/systemd/sysupdate-test/"); // FIXME

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        return sysupdate_main(argc, argv);
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
