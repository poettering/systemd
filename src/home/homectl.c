/* SPDX-License-Identifier: LGPL-2.1+ */

#include <getopt.h>

#include "sd-bus.h"

#include "alloc-util.h"
#include "ask-password-api.h"
#include "bus-common-errors.h"
#include "bus-error.h"
#include "bus-util.h"
#include "cgroup-util.h"
#include "dns-domain.h"
#include "env-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-table.h"
#include "format-util.h"
#include "fs-util.h"
#include "home-util.h"
#include "locale-util.h"
#include "main-func.h"
#include "memory-util.h"
#include "pager.h"
#include "parse-util.h"
#include "path-util.h"
#include "pretty-print.h"
#include "process-util.h"
#include "pwquality-util.h"
#include "rlimit-util.h"
#include "spawn-polkit-agent.h"
#include "terminal-util.h"
#include "user-record-show.h"
#include "user-record-util.h"
#include "user-record.h"
#include "user-util.h"
#include "verbs.h"

static PagerFlags arg_pager_flags = 0;
static bool arg_legend = true;
static bool arg_ask_password = true;
static BusTransport arg_transport = BUS_TRANSPORT_LOCAL;
static const char *arg_host = NULL;
static const char *arg_identity = NULL;
static JsonVariant *arg_identity_extra = NULL;
static JsonVariant *arg_identity_extra_privileged = NULL;
static JsonVariant *arg_identity_extra_this_machine = NULL;
static JsonVariant *arg_identity_extra_rlimits = NULL;
static char **arg_identity_filter = NULL; /* this one is also applied to 'privileged' and 'thisMachine' subobjects */
static char **arg_identity_filter_rlimits = NULL;
static uint64_t arg_disk_size = UINT64_MAX;
static uint64_t arg_disk_size_relative = UINT64_MAX;
static bool arg_json = false;
static JsonFormatFlags arg_json_format_flags = 0;
static enum {
        EXPORT_FORMAT_FULL,          /* export the full record */
        EXPORT_FORMAT_STRIPPED,      /* strip "state" + "binding", but leave signature in place */
        EXPORT_FORMAT_MINIMAL,       /* also strip signature */
} arg_export_format = EXPORT_FORMAT_FULL;

STATIC_DESTRUCTOR_REGISTER(arg_identity_extra, json_variant_unrefp);
STATIC_DESTRUCTOR_REGISTER(arg_identity_extra_this_machine, json_variant_unrefp);
STATIC_DESTRUCTOR_REGISTER(arg_identity_extra_privileged, json_variant_unrefp);
STATIC_DESTRUCTOR_REGISTER(arg_identity_extra_rlimits, json_variant_unrefp);
STATIC_DESTRUCTOR_REGISTER(arg_identity_filter, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_identity_filter_rlimits, strv_freep);

static int acquire_bus(sd_bus **bus) {
        int r;

        assert(bus);

        if (*bus)
                return 0;

        r = bus_connect_transport(arg_transport, arg_host, false, bus);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to bus: %m");

        (void) sd_bus_set_allow_interactive_authorization(*bus, arg_ask_password);

        return 0;
}

static int list_homes(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL, *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(table_unrefp) Table *table = NULL;
        int r;

        (void) pager_open(arg_pager_flags);

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        r = sd_bus_call_method(
                        bus,
                        "org.freedesktop.home1",
                        "/org/freedesktop/home1",
                        "org.freedesktop.home1.Manager",
                        "ListHomes",
                        &error,
                        &reply,
                        NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to list homes: %s", bus_error_message(&error, r));

        table = table_new("name", "uid", "gid", "state", "realname", "home", "shell");
        if (!table)
                return log_oom();

        r = sd_bus_message_enter_container(reply, 'a', "(susussso)");
        if (r < 0)
                return bus_log_parse_error(r);

        for (;;) {
                const char *name, *state, *realname, *home, *shell, *color;
                TableCell *cell;
                uint32_t uid, gid;

                r = sd_bus_message_read(reply, "(susussso)", &name, &uid, &state, &gid, &realname, &home, &shell, NULL);
                if (r < 0)
                        return bus_log_parse_error(r);
                if (r == 0)
                        break;

                r = table_add_many(table,
                                   TABLE_STRING, name,
                                   TABLE_UID, uid,
                                   TABLE_GID, gid);
                if (r < 0)
                        return log_error_errno(r, "Failed to add row to table: %m");


                r = table_add_cell(table, &cell, TABLE_STRING, state);
                if (r < 0)
                        return log_error_errno(r, "Failed to add field to table: %m");

                color = user_record_state_color(state);
                if (color)
                        (void) table_set_color(table, cell, color);

                r = table_add_many(table,
                                   TABLE_STRING, strna(empty_to_null(realname)),
                                   TABLE_STRING, home,
                                   TABLE_STRING, strna(empty_to_null(shell)));
                if (r < 0)
                        return log_error_errno(r, "Failed to add row to table: %m");
        }

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                return bus_log_parse_error(r);

        if (table_get_rows(table) > 1 || arg_json) {
                r = table_set_sort(table, (size_t) 0, (size_t) -1);
                if (r < 0)
                        return log_error_errno(r, "Failed to sort table: %m");

                table_set_header(table, arg_legend);

                if (arg_json)
                        r = table_print_json(table, stdout, arg_json_format_flags);
                else
                        r = table_print(table, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to show table: %m");
        }

        if (arg_legend && !arg_json) {
                if (table_get_rows(table) > 1)
                        printf("\n%zu homes listed.\n", table_get_rows(table) - 1);
                else
                        printf("No homes.\n");
        }

        return 0;
}

static int acquire_existing_password(const char *user_name, UserRecord *hr) {
        _cleanup_(strv_free_erasep) char **password = NULL;
        _cleanup_free_ char *question = NULL;
        char *e;
        int r;

        assert(user_name);
        assert(hr);

        e = getenv("PASSWORD");
        if (e) {
                /* People really shouldn't use environment variables for passing passwords. We support this
                 * only for testing purposes, and do not document the behaviour, so that people won't
                 * actually use this outside of testing. */

                r = user_record_set_password(hr, STRV_MAKE(e), true);
                if (r < 0)
                        return log_error_errno(r, "Failed to store password: %m");

                string_erase(e);

                if (unsetenv("PASSWORD") < 0)
                        return log_error_errno(errno, "Failed to unset $PASSWORD: %m");

                return 0;
        }

        if (asprintf(&question, "Please enter password for user %s:", user_name) < 0)
                return log_oom();

        r = ask_password_tty(-1, question, NULL, USEC_INFINITY, 0, NULL, &password);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire password: %m");

        r = user_record_set_password(hr, password, true);
        if (r < 0)
                return log_error_errno(r, "Failed to store password: %m");

        return 0;
}

static int activate_home(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r, ret = EXIT_SUCCESS;
        char **i;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        STRV_FOREACH(i, strv_skip(argv, 1)) {
                _cleanup_(user_record_unrefp) UserRecord *secret = NULL;

                secret = user_record_new();
                if (!secret)
                        return log_oom();

                for (;;) {
                        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;

                        r = acquire_existing_password(*i, secret);
                        if (r < 0)
                                return r;

                        r = sd_bus_message_new_method_call(
                                        bus,
                                        &m,
                                        "org.freedesktop.home1",
                                        "/org/freedesktop/home1",
                                        "org.freedesktop.home1.Manager",
                                        "ActivateHome");
                        if (r < 0)
                                return bus_log_create_error(r);

                        r = sd_bus_message_append(m, "s", *i);
                        if (r < 0)
                                return bus_log_create_error(r);

                        r = bus_message_append_secret(m, secret);
                        if (r < 0)
                                return bus_log_create_error(r);

                        r = sd_bus_call(bus, m, HOME_SLOW_BUS_CALL_TIMEOUT_USEC, &error, NULL);
                        if (r < 0) {
                                if (sd_bus_error_has_name(&error, BUS_ERROR_BAD_PASSWORD))
                                        log_error("Password incorrect, please try again.");
                                else {
                                        log_error_errno(r, "Failed to activate user home: %s", bus_error_message(&error, r));
                                        if (ret == EXIT_SUCCESS)
                                                ret = r;

                                        break;
                                }
                        } else
                                break;
                }
        }

        return ret;
}

static int deactivate_home(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r, ret = EXIT_SUCCESS;
        char **i;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        STRV_FOREACH(i, strv_skip(argv, 1)) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;

                r = sd_bus_message_new_method_call(
                                bus,
                                &m,
                                "org.freedesktop.home1",
                                "/org/freedesktop/home1",
                                "org.freedesktop.home1.Manager",
                                "DeactivateHome");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(m, "s", *i);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_call(bus, m, HOME_SLOW_BUS_CALL_TIMEOUT_USEC, &error, NULL);
                if (r < 0) {
                        log_error_errno(r, "Failed to deactivate user home: %s", bus_error_message(&error, r));
                        if (ret == EXIT_SUCCESS)
                                ret = r;
                }
        }

        return ret;
}

static void dump_home_record(UserRecord *hr) {
        int r;

        assert(hr);

        if (hr->incomplete) {
                fflush(stdout);
                log_warning("Warning: lacking rights to acquire privileged fields of user record of '%s', output incomplete.", hr->user_name);
        }

        if (arg_json) {
                _cleanup_(user_record_unrefp) UserRecord *stripped = NULL;

                if (arg_export_format == EXPORT_FORMAT_STRIPPED)
                        r = user_record_clone(hr, USER_RECORD_EXTRACT_EMBEDDED, &stripped);
                else if (arg_export_format == EXPORT_FORMAT_MINIMAL)
                        r = user_record_clone(hr, USER_RECORD_EXTRACT_SIGNABLE, &stripped);
                else
                        r = 0;
                if (r < 0)
                        log_warning_errno(r, "Failed to strip user record, ignoring: %m");
                if (stripped)
                        hr = stripped;

                json_variant_dump(hr->json, arg_json_format_flags, stdout, NULL);
        } else
                user_record_show(hr, true);
}

static char **mangle_user_list(char **list, char ***ret_allocated) {
        _cleanup_free_ char *myself = NULL;
        char **l;

        if (!strv_isempty(list)) {
                *ret_allocated = NULL;
                return list;
        }

        myself = getusername_malloc();
        if (!myself)
                return NULL;

        l = new(char*, 2);
        if (!l)
                return NULL;

        l[0] = TAKE_PTR(myself);
        l[1] = NULL;

        *ret_allocated = l;
        return l;
}

static int inspect_home(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(strv_freep) char **mangled_list = NULL;
        int r, ret = EXIT_SUCCESS;
        char **items, **i;

        (void) pager_open(arg_pager_flags);

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        items = mangle_user_list(strv_skip(argv, 1), &mangled_list);
        if (!items)
                return log_oom();

        STRV_FOREACH(i, items) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
                _cleanup_(user_record_unrefp) UserRecord *hr = NULL;
                const char *json;
                int incomplete;
                uid_t uid;

                r = parse_uid(*i, &uid);
                if (r < 0) {
                        if (!valid_user_group_name(*i)) {
                                log_error("Invalid user name '%s'.", *i);
                                if (ret == EXIT_SUCCESS)
                                        ret = -EINVAL;

                                continue;
                        }

                        r = sd_bus_call_method(
                                        bus,
                                        "org.freedesktop.home1",
                                        "/org/freedesktop/home1",
                                        "org.freedesktop.home1.Manager",
                                        "GetUserRecordByName",
                                        &error,
                                        &reply,
                                        "s",
                                        *i);
                } else {
                        r = sd_bus_call_method(
                                        bus,
                                        "org.freedesktop.home1",
                                        "/org/freedesktop/home1",
                                        "org.freedesktop.home1.Manager",
                                        "GetUserRecordByUID",
                                        &error,
                                        &reply,
                                        "u",
                                        (uint32_t) uid);
                }

                if (r < 0) {
                        log_error_errno(r, "Failed to inspect home: %s", bus_error_message(&error, r));
                        if (ret == EXIT_SUCCESS)
                                ret = r;

                        continue;
                }

                r = sd_bus_message_read(reply, "sbo", &json, &incomplete, NULL);
                if (r < 0) {
                        bus_log_parse_error(r);
                        if (ret == EXIT_SUCCESS)
                                ret = r;

                        continue;
                }

                r = json_parse(json, JSON_PARSE_SENSITIVE, &v, NULL, NULL);
                if (r < 0) {
                        log_error_errno(r, "Failed to parse JSON identity: %m");
                        if (ret == EXIT_SUCCESS)
                                ret = r;

                        continue;
                }

                hr = user_record_new();
                if (!hr)
                        return log_oom();

                r = user_record_load(hr, v, USER_RECORD_LOAD_REFUSE_SECRET|USER_RECORD_LOG);
                if (r < 0) {
                        if (ret == EXIT_SUCCESS)
                                ret = r;

                        continue;
                }

                hr->incomplete = incomplete;
                dump_home_record(hr);
        }

        return ret;
}

static int ssh_authorized_keys(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_(user_record_unrefp) UserRecord *hr = NULL;
        const char *json;
        int r;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        if (!valid_user_group_name(argv[1]))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid user name '%s'.", argv[1]);

        r = sd_bus_call_method(
                        bus,
                        "org.freedesktop.home1",
                        "/org/freedesktop/home1",
                        "org.freedesktop.home1.Manager",
                        "GetUserRecordByName",
                        &error,
                        &reply,
                        "s",
                        argv[1]);
        if (r < 0) {
                if (sd_bus_error_has_name(&error, SD_BUS_ERROR_SERVICE_UNKNOWN) ||
                    sd_bus_error_has_name(&error, SD_BUS_ERROR_NAME_HAS_NO_OWNER)) {
                        log_debug_errno(r, "systemd-homed is not available: %s", bus_error_message(&error, r));
                        return EXIT_SUCCESS;
                }

                if (sd_bus_error_has_name(&error, BUS_ERROR_NO_SUCH_HOME)) {
                        log_debug_errno(r, "Not a user managed by systemd-homed: %s", bus_error_message(&error, r));
                        return EXIT_SUCCESS;
                }

                return log_error_errno(r, "Failed to query user record for %s: %m", argv[1]);
        }

        r = sd_bus_message_read(reply, "sbo", &json, NULL, NULL);
        if (r < 0)
                return bus_log_parse_error(r);

        r = json_parse(json, JSON_PARSE_SENSITIVE, &v, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to parse JSON record: %m");

        hr = user_record_new();
        if (!hr)
                return log_oom();

        r = user_record_load(hr, v, USER_RECORD_LOAD_REFUSE_SECRET|USER_RECORD_LOG);
        if (r < 0)
                return r;

        if (strv_isempty(hr->ssh_authorized_keys))
                log_debug("User record for %s has no public SSH keys.", argv[1]);
        else {
                char **i;

                STRV_FOREACH(i, hr->ssh_authorized_keys)
                        printf("%s\n", *i);
        }

        return EXIT_SUCCESS;
}

static int authenticate_home(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(strv_freep) char **mangled_list = NULL;
        int r, ret = EXIT_SUCCESS;
        char **i, **items;

        items = mangle_user_list(strv_skip(argv, 1), &mangled_list);
        if (!items)
                return log_oom();

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        STRV_FOREACH(i, items) {
                _cleanup_(user_record_unrefp) UserRecord *secret = NULL;

                secret = user_record_new();
                if (!secret)
                        return log_oom();

                for (;;) {
                        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;

                        r = acquire_existing_password(*i, secret);
                        if (r < 0)
                                return r;

                        r = sd_bus_message_new_method_call(
                                        bus,
                                        &m,
                                        "org.freedesktop.home1",
                                        "/org/freedesktop/home1",
                                        "org.freedesktop.home1.Manager",
                                        "AuthenticateHome");
                        if (r < 0)
                                return bus_log_create_error(r);

                        r = sd_bus_message_append(m, "s", *i);
                        if (r < 0)
                                return bus_log_create_error(r);

                        r = bus_message_append_secret(m, secret);
                        if (r < 0)
                                return bus_log_create_error(r);

                        r = sd_bus_call(bus, m, HOME_SLOW_BUS_CALL_TIMEOUT_USEC, &error, NULL);
                        if (r < 0) {
                                if (sd_bus_error_has_name(&error, BUS_ERROR_BAD_PASSWORD))
                                        log_error("Password incorrect, please try again.");
                                else {
                                        log_error_errno(r, "Failed to authenticate user home: %s", bus_error_message(&error, r));
                                        if (ret == EXIT_SUCCESS)
                                                ret = r;

                                        break;
                                }
                        } else
                                break;
                }
        }

        return ret;
}

static int update_last_change(JsonVariant **v, bool override) {
        JsonVariant *c;
        usec_t n;
        int r;

        assert(v);

        n = now(CLOCK_REALTIME);

        c = json_variant_by_key(*v, "lastChangeUSec");
        if (c) {
                uintmax_t u;

                if (!override)
                        return 0;

                if (!json_variant_is_unsigned(c))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "lastChangeUSec field is not an unsigned integer, refusing.");

                u = json_variant_unsigned(c);
                if (u >= n)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "lastChangeUSec is from the future, can't update.");
        }

        r = json_variant_set_field_unsigned(v, "lastChangeUSec", n);
        if (r < 0)
                return log_error_errno(r, "Failed to merge identities: %m");

        return 1;
}

static int apply_identity_changes(JsonVariant **_v) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        int r;

        assert(_v);

        v = json_variant_ref(*_v);

        r = json_variant_filter(&v, arg_identity_filter);
        if (r < 0)
                return log_error_errno(r, "Failed to filter identity: %m");

        r = json_variant_merge(&v, arg_identity_extra);
        if (r < 0)
                return log_error_errno(r, "Failed to merge identities: %m");

        if (arg_identity_extra_this_machine || !strv_isempty(arg_identity_filter)) {
                _cleanup_(json_variant_unrefp) JsonVariant *per_machine = NULL, *mmid = NULL;
                char mids[SD_ID128_STRING_MAX];
                sd_id128_t mid;

                r = sd_id128_get_machine(&mid);
                if (r < 0)
                        return log_error_errno(r, "Failed to acquire machine ID: %m");

                r = json_variant_new_string(&mmid, sd_id128_to_string(mid, mids));
                if (r < 0)
                        return log_error_errno(r, "Failed to allocate matchMachineId object: %m");

                per_machine = json_variant_ref(json_variant_by_key(v, "perMachine"));
                if (per_machine) {
                        _cleanup_(json_variant_unrefp) JsonVariant *npm = NULL, *add = NULL;
                        _cleanup_free_ JsonVariant **array = NULL;
                        JsonVariant *z;
                        size_t i = 0;

                        if (!json_variant_is_array(per_machine))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "perMachine field is not an array, refusing.");

                        array = new(JsonVariant*, json_variant_elements(per_machine) + 1);
                        if (!array)
                                return log_oom();

                        JSON_VARIANT_ARRAY_FOREACH(z, per_machine) {
                                JsonVariant *u;

                                if (!json_variant_is_object(z))
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "perMachine entry is not an object, refusing.");

                                array[i++] = z;

                                u = json_variant_by_key(z, "matchMachineId");
                                if (!u)
                                        continue;

                                if (!json_variant_equal(u, mmid))
                                        continue;

                                r = json_variant_merge(&add, z);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to merge perMachine entry: %m");

                                i--;
                        }

                        r = json_variant_filter(&add, arg_identity_filter);
                        if (r < 0)
                                return log_error_errno(r, "Failed to filter perMachine: %m");

                        r = json_variant_merge(&add, arg_identity_extra_this_machine);
                        if (r < 0)
                                return log_error_errno(r, "Failed to merge in perMachine fields: %m");

                        if (arg_identity_filter_rlimits || arg_identity_extra_rlimits) {
                                _cleanup_(json_variant_unrefp) JsonVariant *rlv = NULL;

                                rlv = json_variant_ref(json_variant_by_key(add, "resourceLimits"));

                                r = json_variant_filter(&rlv, arg_identity_filter_rlimits);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to filter resource limits: %m");

                                r = json_variant_merge(&rlv, arg_identity_extra_rlimits);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to set resource limits: %m");

                                if (json_variant_is_blank_object(rlv)) {
                                        r = json_variant_filter(&add, STRV_MAKE("resourceLimits"));
                                        if (r < 0)
                                                return log_error_errno(r, "Failed to drop resource limits field from identity: %m");
                                } else {
                                        r = json_variant_set_field(&add, "resourceLimits", rlv);
                                        if (r < 0)
                                                return log_error_errno(r, "Failed to update resource limits of identity: %m");
                                }
                        }

                        if (!json_variant_is_blank_object(add)) {
                                r = json_variant_set_field(&add, "matchMachineId", mmid);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to set matchMachineId field: %m");

                                array[i++] = add;
                        }

                        r = json_variant_new_array(&npm, array, i);
                        if (r < 0)
                                return log_error_errno(r, "Failed to allocate new perMachine array: %m");

                        json_variant_unref(per_machine);
                        per_machine = TAKE_PTR(npm);
                } else {
                        _cleanup_(json_variant_unrefp) JsonVariant *item = json_variant_ref(arg_identity_extra_this_machine);

                        if (arg_identity_extra_rlimits) {
                                r = json_variant_set_field(&item, "resourceLimits", arg_identity_extra_rlimits);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to update resource limits of identity: %m");
                        }

                        r = json_variant_set_field(&item, "matchMachineId", mmid);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set matchMachineId field: %m");

                        r = json_variant_append_array(&per_machine, item);
                        if (r < 0)
                                return log_error_errno(r, "Failed to append to perMachine array: %m");
                }

                r = json_variant_set_field(&v, "perMachine", per_machine);
                if (r < 0)
                        return log_error_errno(r, "Failed to update per machine record: %m");
        }

        if (arg_identity_extra_privileged || arg_identity_filter) {
                _cleanup_(json_variant_unrefp) JsonVariant *privileged = NULL;

                privileged = json_variant_ref(json_variant_by_key(v, "privileged"));

                r = json_variant_filter(&privileged, arg_identity_filter);
                if (r < 0)
                        return log_error_errno(r, "Failed to filter identity (privileged part): %m");

                r = json_variant_merge(&privileged, arg_identity_extra_privileged);
                if (r < 0)
                        return log_error_errno(r, "Failed to merge identities (privileged part): %m");

                if (json_variant_is_blank_object(privileged)) {
                        r = json_variant_filter(&v, STRV_MAKE("privileged"));
                        if (r < 0)
                                return log_error_errno(r, "Failed to drop privileged part from identity: %m");
                } else {
                        r = json_variant_set_field(&v, "privileged", privileged);
                        if (r < 0)
                                return log_error_errno(r, "Failed to update privileged part of identity: %m");
                }
        }

        if (arg_identity_filter_rlimits) {
                _cleanup_(json_variant_unrefp) JsonVariant *rlv = NULL;

                rlv = json_variant_ref(json_variant_by_key(v, "resourceLimits"));

                r = json_variant_filter(&rlv, arg_identity_filter_rlimits);
                if (r < 0)
                        return log_error_errno(r, "Failed to filter resource limits: %m");

                /* Note that we only filter resource limits here, but don't apply them. We do that in the perMachine section */

                if (json_variant_is_blank_object(rlv)) {
                        r = json_variant_filter(&v, STRV_MAKE("resourceLimits"));
                        if (r < 0)
                                return log_error_errno(r, "Failed to drop resource limits field from identity: %m");
                } else {
                        r = json_variant_set_field(&v, "resourceLimits", rlv);
                        if (r < 0)
                                return log_error_errno(r, "Failed to update resource limits of identity: %m");
                }
        }

        if (DEBUG_LOGGING)
                json_variant_dump(v, JSON_FORMAT_PRETTY, NULL, NULL);

        json_variant_unref(*_v);
        *_v = TAKE_PTR(v);

        return 0;
}

static int add_disposition(JsonVariant **v) {
        int r;

        assert(v);

        if (json_variant_by_key(*v, "disposition"))
                return 0;

        /* Set the disposition to regular, if not configured explicitly */
        r = json_variant_set_field_string(v, "disposition", "regular");
        if (r < 0)
                return log_error_errno(r, "Failed to set disposition field: %m");

        return 1;
}

static int acquire_home_record(UserRecord **ret) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_(user_record_unrefp) UserRecord *hr = NULL;
        int r;

        assert(ret);

        hr = user_record_new();
        if (!hr)
                return log_oom();

        if (arg_identity) {
                unsigned line, column;

                r = json_parse_file(
                                streq(arg_identity, "-") ? stdin : NULL,
                                streq(arg_identity, "-") ? "<stdin>" : arg_identity, JSON_PARSE_SENSITIVE, &v, &line, &column);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse identity at %u:%u: %m", line, column);
        }

        r = apply_identity_changes(&v);
        if (r < 0)
                return r;

        r = update_last_change(&v, false);
        if (r < 0)
                return r;

        r = add_disposition(&v);
        if (r < 0)
                return r;

        r = user_record_load(hr, v, USER_RECORD_REQUIRE_REGULAR|USER_RECORD_ALLOW_SECRET|USER_RECORD_ALLOW_PRIVILEGED|USER_RECORD_ALLOW_PER_MACHINE|USER_RECORD_ALLOW_SIGNATURE|USER_RECORD_LOG);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(hr);
        return 0;
}

static int acquire_new_password(
                const char *user_name,
                UserRecord *hr,
                bool suggest) {

        unsigned i = 5;
        char *e;
        int r;

        assert(user_name);
        assert(hr);

        e = getenv("NEWPASSWORD");
        if (e) {
                /* As above, this is not for use, just for testing */

                r = user_record_set_password(hr, STRV_MAKE(e), false);
                if (r < 0)
                        return log_error_errno(r, "Failed to store password: %m");

                string_erase(e);

                if (unsetenv("NEWPASSWORD") < 0)
                        return log_error_errno(errno, "Failed to unse $NEWPASSWORD: %m");

                return 0;
        }

        if (suggest)
                (void) suggest_passwords();

        for (;;) {
                _cleanup_(strv_free_erasep) char **first = NULL, **second = NULL;
                _cleanup_free_ char *question = NULL;

                if (--i == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOKEY), "Too many attempts, giving up:");

                if (asprintf(&question, "Please enter new password for user %s:", user_name) < 0)
                        return log_oom();

                r = ask_password_tty(-1, question, NULL, USEC_INFINITY, 0, NULL, &first);
                if (r < 0)
                        return log_error_errno(r, "Failed to acquire password: %m");

                question = mfree(question);
                if (asprintf(&question, "Please enter new password for user %s (repeat):", user_name) < 0)
                        return log_oom();

                r = ask_password_tty(-1, question, NULL, USEC_INFINITY, 0, NULL, &second);
                if (r < 0)
                        return log_error_errno(r, "Failed to acquire password: %m");

                if (strv_equal(first, second)) {
                        r = user_record_set_password(hr, first, false);
                        if (r < 0)
                                return log_error_errno(r, "Failed to store password: %m");

                        return 0;
                }

                log_error("Password didn't mach, try again.");
        }
}

static int create_home(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(user_record_unrefp) UserRecord *hr = NULL;
        int r;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        if (argc >= 2) {
                /* If a username was specified, use it */

                if (valid_user_group_name(argv[1]))
                        r = json_variant_set_field_string(&arg_identity_extra, "userName", argv[1]);
                else {
                        _cleanup_free_ char *un = NULL, *rr = NULL;

                        /* Before we consider the user name invalid, let's check if we can split it? */
                        r = split_user_name_realm(argv[1], &un, &rr);
                        if (r < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "User name '%s' is not valid: %m", argv[1]);

                        if (rr) {
                                r = json_variant_set_field_string(&arg_identity_extra, "realm", rr);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to set realm field: %m");
                        }

                        r = json_variant_set_field_string(&arg_identity_extra, "userName", un);
                }
                if (r < 0)
                        return log_error_errno(r, "Failed to set userName field: %m");
        } else {
                /* If neither a username nor an identity have been specified we cannot operate. */
                if (!arg_identity)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "User name required.");
        }

        r = acquire_home_record(&hr);
        if (r < 0)
                return r;

        /* If the JSON record carries no secrets, then let's query them manually */
        if (!FLAGS_SET(hr->mask, USER_RECORD_SECRET)) {

                if (strv_isempty(hr->hashed_password)) {
                        /* No hashed passwords set in the record, let's fix that. */
                        r = acquire_new_password(hr->user_name, hr, /* suggest = */ true);
                        if (r < 0)
                                return r;

                        r = user_record_make_hashed_password(hr, hr);
                        if (r < 0)
                                return log_error_errno(r, "Failed to hash password: %m");
                } else {
                        /* There's a hash password set in the record, acquire the unhashed version of it. */
                        r = acquire_existing_password(hr->user_name, hr);
                        if (r < 0)
                                return r;

                        r = user_record_test_secret(hr, hr);
                        if (r < 0)
                                return log_error_errno(r, "Password does not match record.");
                }
        }

        if (hr->enforce_password_policy == 0) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                /* If password quality enforcement is disabled, let's at least warn client side */

                r = quality_check_password(hr, hr, &error);
                if (r < 0)
                        log_warning_errno(r, "Specified password does not pass quality checks (%s), proceeding anyway.", bus_error_message(&error, r));
        }

        for (;;) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
                _cleanup_(erase_and_freep) char *formatted = NULL;

                r = json_variant_format(hr->json, 0, &formatted);
                if (r < 0)
                        return r;

                r = sd_bus_message_new_method_call(
                                bus,
                                &m,
                                "org.freedesktop.home1",
                                "/org/freedesktop/home1",
                                "org.freedesktop.home1.Manager",
                                "CreateHome");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(m, "s", formatted);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_call(bus, m, HOME_SLOW_BUS_CALL_TIMEOUT_USEC, &error, NULL);
                if (r < 0) {
                        if (!sd_bus_error_has_name(&error, BUS_ERROR_LOW_PASSWORD_QUALITY))
                                return log_error_errno(r, "Failed to create user home: %s", bus_error_message(&error, r));

                        log_error_errno(r, "%s", bus_error_message(&error, r));
                        log_info("(Use --enforce-password-policy=no to turn off password quality checks for this account.)");
                } else
                        break; /* done */

                r = acquire_new_password(hr->user_name, hr, /* suggest = */ false);
                if (r < 0)
                        return r;

                r = user_record_make_hashed_password(hr, hr);
                if (r < 0)
                        return log_error_errno(r, "Failed to hash passwords: %m");
        }

        return EXIT_SUCCESS;
}

static int remove_home(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r, ret = EXIT_SUCCESS;
        char **i;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        STRV_FOREACH(i, strv_skip(argv, 1)) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;

                r = sd_bus_message_new_method_call(
                                bus,
                                &m,
                                "org.freedesktop.home1",
                                "/org/freedesktop/home1",
                                "org.freedesktop.home1.Manager",
                                "RemoveHome");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(m, "s", *i);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_call(bus, m, HOME_SLOW_BUS_CALL_TIMEOUT_USEC, &error, NULL);
                if (r < 0) {
                        log_error_errno(r, "Failed to remove home: %s", bus_error_message(&error, r));
                        if (ret == EXIT_SUCCESS)
                                ret = r;
                }
        }

        return ret;
}

static int update_home(int argc, char *argv[], void *userdata) {
        _cleanup_(json_variant_unrefp) JsonVariant *json = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(user_record_unrefp) UserRecord *hr = NULL;
        _cleanup_free_ char *buffer = NULL;
        const char *username;
        int r;

        if (argc >= 2)
                username = argv[1];
        else if (!arg_identity) {
                buffer = getusername_malloc();
                if (!buffer)
                        return log_oom();

                username = buffer;
        } else
                username = NULL;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        if (arg_identity) {
                unsigned line, column;
                JsonVariant *un;

                r = json_parse_file(
                                streq(arg_identity, "-") ? stdin : NULL,
                                streq(arg_identity, "-") ? "<stdin>" : arg_identity, JSON_PARSE_SENSITIVE, &json, &line, &column);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse identity at %u:%u: %m", line, column);

                un = json_variant_by_key(json, "userName");
                if (un) {
                        if (!json_variant_is_string(un) || (username && !streq(json_variant_string(un), username)))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "User name specified on command line and in JSON record do not match.");

                        if (!username) {
                                buffer = strdup(json_variant_string(un));
                                if (!buffer)
                                        return log_oom();

                                username = buffer;
                        }
                } else {
                        if (!username)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No username specified.");

                        r = json_variant_set_field_string(&arg_identity_extra, "userName", username);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set userName field: %m");
                }

        } else {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                int incomplete;
                const char *text;

                if (!arg_identity_extra &&
                    !arg_identity_extra_this_machine &&
                    !arg_identity_extra_privileged &&
                    !arg_identity_extra_rlimits &&
                    strv_isempty(arg_identity_filter) &&
                    strv_isempty(arg_identity_filter_rlimits))
                        return log_error_errno(SYNTHETIC_ERRNO(EALREADY), "No field to change specified.");

                r = sd_bus_call_method(
                                bus,
                                "org.freedesktop.home1",
                                "/org/freedesktop/home1",
                                "org.freedesktop.home1.Manager",
                                "GetUserRecordByName",
                                &error,
                                &reply,
                                "s",
                                username);
                if (r < 0)
                        return log_error_errno(r, "Failed to acquire user home record: %s", bus_error_message(&error, r));

                r = sd_bus_message_read(reply, "sbo", &text, &incomplete, NULL);
                if (r < 0)
                        return bus_log_parse_error(r);

                if (incomplete)
                        return log_error_errno(SYNTHETIC_ERRNO(EACCES), "Lacking rights to acquire user record including privileged metadata, can't update record.");

                r = json_parse(text, JSON_PARSE_SENSITIVE, &json, NULL, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse JSON identity: %m");

                reply = sd_bus_message_unref(reply);

                r = json_variant_filter(&json, STRV_MAKE("binding", "status", "signature"));
                if (r < 0)
                        return log_error_errno(r, "Failed to strip binding and status from record to update: %m");
        }

        r = apply_identity_changes(&json);
        if (r < 0)
                return r;

        /* If the user supplied a full record, then add in lastChange, but do not override. Otherwise always override. */
        r = update_last_change(&json, !arg_identity);
        if (r < 0)
                return r;

        hr = user_record_new();
        if (!hr)
                return log_oom();

        r = user_record_load(hr, json, USER_RECORD_REQUIRE_REGULAR|USER_RECORD_ALLOW_PRIVILEGED|USER_RECORD_ALLOW_PER_MACHINE|USER_RECORD_ALLOW_SECRET|USER_RECORD_ALLOW_SIGNATURE|USER_RECORD_LOG);
        if (r < 0)
                return r;

        if (!FLAGS_SET(hr->mask, USER_RECORD_SECRET)) {
                r = acquire_existing_password(username, hr);
                if (r < 0)
                        return r;
        }

        for (;;) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
                _cleanup_free_ char *formatted = NULL;

                r = sd_bus_message_new_method_call(
                                bus,
                                &m,
                                "org.freedesktop.home1",
                                "/org/freedesktop/home1",
                                "org.freedesktop.home1.Manager",
                                "UpdateHome");
                if (r < 0)
                        return bus_log_create_error(r);

                r = json_variant_format(hr->json, 0, &formatted);
                if (r < 0)
                        return r;

                r = sd_bus_message_append(m, "s", formatted);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_call(bus, m, HOME_SLOW_BUS_CALL_TIMEOUT_USEC, &error, NULL);
                if (r < 0) {
                        if (!sd_bus_error_has_name(&error, BUS_ERROR_BAD_PASSWORD))
                                return log_error_errno(r, "Failed to update home: %s", bus_error_message(&error, r));
                } else
                        break;

                log_error("Password incorrect, please try again.");

                r = acquire_existing_password(username, hr);
                if (r < 0)
                        return r;
        }

        return EXIT_SUCCESS;
}

static int passwd_home(int argc, char *argv[], void *userdata) {
        _cleanup_(user_record_unrefp) UserRecord *old_secret = NULL, *new_secret = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_free_ char *buffer = NULL;
        const char *username;
        int r;

        if (argc >= 2)
                username = argv[1];
        else {
                buffer = getusername_malloc();
                if (!buffer)
                        return log_oom();

                username = buffer;
        }

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        old_secret = user_record_new();
        if (!old_secret)
                return log_oom();

        r = acquire_existing_password(username, old_secret);
        if (r < 0)
                return r;

        new_secret = user_record_new();
        if (!new_secret)
                return log_oom();

        r = acquire_new_password(username, new_secret, /* suggest = */ true);
        if (r < 0)
                return r;

        for (;;) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;

                r = sd_bus_message_new_method_call(
                                bus,
                                &m,
                                "org.freedesktop.home1",
                                "/org/freedesktop/home1",
                                "org.freedesktop.home1.Manager",
                                "ChangePasswordHome");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(m, "s", username);
                if (r < 0)
                        return bus_log_create_error(r);

                r = bus_message_append_secret(m, new_secret);
                if (r < 0)
                        return bus_log_create_error(r);

                r = bus_message_append_secret(m, old_secret);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_call(bus, m, HOME_SLOW_BUS_CALL_TIMEOUT_USEC, &error, NULL);
                if (r < 0) {
                        if (sd_bus_error_has_name(&error, BUS_ERROR_LOW_PASSWORD_QUALITY)) {

                                log_error_errno(r, "%s", bus_error_message(&error, r));

                                r = acquire_new_password(username, new_secret, /* suggest = */ false);
                                if (r < 0)
                                        return r;

                                continue;

                        } else if (sd_bus_error_has_name(&error, BUS_ERROR_BAD_PASSWORD)) {

                                log_notice("Old password incorrect, please try again.");

                                r = acquire_existing_password(username, old_secret);
                                if (r < 0)
                                        return r;

                                continue;
                        } else
                                return log_error_errno(r, "Failed to change password for home: %s", bus_error_message(&error, r));
                } else
                        break;
        }

        return EXIT_SUCCESS;
}

static int resize_home(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(user_record_unrefp) UserRecord *secret = NULL;
        uint64_t ds = UINT64_MAX;
        int r;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        if (arg_disk_size_relative != UINT64_MAX ||
            (argc > 2 && parse_percent(argv[2]) >= 0))
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                               "Relative disk size specification currently not supported when resizing.");

        if (argc > 2) {
                r = parse_size(argv[2], 1024, &ds);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse disk size parameter: %s", argv[2]);
        }

        if (arg_disk_size != UINT64_MAX) {
                if (ds != UINT64_MAX && ds != arg_disk_size)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Disk size specified twice and doesn't match, refusing.");

                ds = arg_disk_size;
        }

        secret = user_record_new();
        if (!secret)
                return log_oom();

        for (;;) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;

                r = acquire_existing_password(argv[1], secret);
                if (r < 0)
                        return r;

                r = sd_bus_message_new_method_call(
                                bus,
                                &m,
                                "org.freedesktop.home1",
                                "/org/freedesktop/home1",
                                "org.freedesktop.home1.Manager",
                                "ResizeHome");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(m, "st", argv[1], ds);
                if (r < 0)
                        return bus_log_create_error(r);

                r = bus_message_append_secret(m, secret);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_call(bus, m, HOME_SLOW_BUS_CALL_TIMEOUT_USEC, &error, NULL);
                if (r < 0) {
                        if (!sd_bus_error_has_name(&error, BUS_ERROR_BAD_PASSWORD))
                                return log_error_errno(r, "Failed to resize home: %s", bus_error_message(&error, r));
                } else
                        break;

                log_error("Password incorrect, please try again.");
        }

        return EXIT_SUCCESS;
}

static int lock_home(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r, ret = EXIT_SUCCESS;
        char **i;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        STRV_FOREACH(i, strv_skip(argv, 1)) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;

                r = sd_bus_message_new_method_call(
                                bus,
                                &m,
                                "org.freedesktop.home1",
                                "/org/freedesktop/home1",
                                "org.freedesktop.home1.Manager",
                                "LockHome");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(m, "s", *i);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_call(bus, m, HOME_SLOW_BUS_CALL_TIMEOUT_USEC, &error, NULL);
                if (r < 0) {
                        log_error_errno(r, "Failed to lock home: %s", bus_error_message(&error, r));
                        if (ret == EXIT_SUCCESS)
                                ret = r;
                }
        }

        return ret;
}

static int unlock_home(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r, ret = EXIT_SUCCESS;
        char **i;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        STRV_FOREACH(i, strv_skip(argv, 1)) {
                _cleanup_(user_record_unrefp) UserRecord *secret = NULL;

                secret = user_record_new();
                if (!secret)
                        return log_oom();

                for (;;) {
                        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;

                        r = acquire_existing_password(*i, secret);
                        if (r < 0)
                                return r;

                        r = sd_bus_message_new_method_call(
                                        bus,
                                        &m,
                                        "org.freedesktop.home1",
                                        "/org/freedesktop/home1",
                                        "org.freedesktop.home1.Manager",
                                        "UnlockHome");
                        if (r < 0)
                                return bus_log_create_error(r);

                        r = sd_bus_message_append(m, "s", *i);
                        if (r < 0)
                                return bus_log_create_error(r);

                        r = bus_message_append_secret(m, secret);
                        if (r < 0)
                                return bus_log_create_error(r);

                        r = sd_bus_call(bus, m, HOME_SLOW_BUS_CALL_TIMEOUT_USEC, &error, NULL);
                        if (r < 0) {
                                if (sd_bus_error_has_name(&error, BUS_ERROR_BAD_PASSWORD))
                                        log_error("Password incorrect, please try again.");
                                else {
                                        log_error_errno(r, "Failed to unlock user home: %s", bus_error_message(&error, r));
                                        if (ret == EXIT_SUCCESS)
                                                ret = r;

                                        break;
                                }
                        } else
                                break;
                }
        }

        return ret;
}

static int with_home(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL, *reply = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(user_record_unrefp) UserRecord *secret = NULL;
        _cleanup_close_ int acquired_fd = -1;
        _cleanup_strv_free_ char **cmdline  = NULL;
        const char *home;
        int r, ret;
        pid_t pid;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        if (argc < 3) {
                _cleanup_free_ char *shell = NULL;

                /* If no command is specified, spawn a shell */
                r = get_shell(&shell);
                if (r < 0)
                        return log_error_errno(r, "Failed to acquire shell: %m");

                cmdline = strv_new(shell);
        } else
                cmdline = strv_copy(argv + 2);
        if (!cmdline)
                return log_oom();

        secret = user_record_new();
        if (!secret)
                return log_oom();

        for (;;) {
                r = acquire_existing_password(argv[1], secret);
                if (r < 0)
                        return r;

                r = sd_bus_message_new_method_call(
                                bus,
                                &m,
                                "org.freedesktop.home1",
                                "/org/freedesktop/home1",
                                "org.freedesktop.home1.Manager",
                                "AcquireHome");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(m, "s", argv[1]);
                if (r < 0)
                        return bus_log_create_error(r);

                r = bus_message_append_secret(m, secret);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(m, "b", /* please_suspend = */ getenv_bool("SYSTEMD_PLEASE_SUSPEND_HOME") > 0);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_call(bus, m, HOME_SLOW_BUS_CALL_TIMEOUT_USEC, &error, &reply);
                m = sd_bus_message_unref(m);
                if (r < 0) {
                        if (!sd_bus_error_has_name(&error, BUS_ERROR_BAD_PASSWORD))
                                return log_error_errno(r, "Failed to activate user home: %s", bus_error_message(&error, r));

                        log_error("Password incorrect, please try again.");
                        sd_bus_error_free(&error);
                } else {
                        int fd;

                        r = sd_bus_message_read(reply, "h", &fd);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        acquired_fd = fcntl(fd, F_DUPFD_CLOEXEC, 3);
                        if (acquired_fd < 0)
                                return log_error_errno(errno, "Failed to duplicate acquired fd: %m");

                        reply = sd_bus_message_unref(reply);
                        break;
                }
        }

        r = sd_bus_call_method(
                        bus,
                        "org.freedesktop.home1",
                        "/org/freedesktop/home1",
                        "org.freedesktop.home1.Manager",
                        "GetHomeByName",
                        &error,
                        &reply,
                        "s",
                        argv[1]);
        if (r < 0)
                return log_error_errno(r, "Failed to inspect home: %s", bus_error_message(&error, r));

        r = sd_bus_message_read(reply, "usussso", NULL, NULL, NULL, NULL, &home, NULL, NULL);
        if (r < 0)
                return bus_log_parse_error(r);

        r = safe_fork("(with)", FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG|FORK_LOG|FORK_RLIMIT_NOFILE_SAFE|FORK_REOPEN_LOG, &pid);
        if (r < 0)
                return r;
        if (r == 0) {
                if (chdir(home) < 0) {
                        log_error_errno(errno, "Failed to change to directory %s: %m", home);
                        _exit(255);
                }

                execvp(cmdline[0], cmdline);
                log_error_errno(errno, "Failed to execute %s: %m", cmdline[0]);
                _exit(255);
        }

        ret = wait_for_terminate_and_check(cmdline[0], pid, WAIT_LOG_ABNORMAL);

        /* Close the fd that pings the home now. */
        acquired_fd = safe_close(acquired_fd);

        r = sd_bus_message_new_method_call(
                        bus,
                        &m,
                        "org.freedesktop.home1",
                        "/org/freedesktop/home1",
                        "org.freedesktop.home1.Manager",
                        "ReleaseHome");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(m, "s", argv[1]);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_call(bus, m, HOME_SLOW_BUS_CALL_TIMEOUT_USEC, &error, NULL);
        if (r < 0) {
                if (sd_bus_error_has_name(&error, BUS_ERROR_HOME_BUSY))
                        log_notice("Not deactivating home directory of %s, as it is still used.", argv[1]);
                else
                        return log_error_errno(r, "Failed to release user home: %s", bus_error_message(&error, r));
        }

        return ret;
}

static int lock_all_homes(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        r = sd_bus_message_new_method_call(
                        bus,
                        &m,
                        "org.freedesktop.home1",
                        "/org/freedesktop/home1",
                        "org.freedesktop.home1.Manager",
                        "LockAllHomes");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_call(bus, m, HOME_SLOW_BUS_CALL_TIMEOUT_USEC, &error, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to lock home: %s", bus_error_message(&error, r));

        return EXIT_SUCCESS;
}

static int drop_from_identity(const char *field) {
        int r;

        assert(field);

        /* If we are called to update an identity record and drop some field, let's keep track of what to
         * remove from the old record */
        r = strv_extend(&arg_identity_filter, field);
        if (r < 0)
                return log_oom();

        /* Let's also drop the field if it was previously set to a new value on the same command line */
        r = json_variant_filter(&arg_identity_extra, STRV_MAKE(field));
        if (r < 0)
                return log_error_errno(r, "Failed to filter JSON identity data: %m");

        r = json_variant_filter(&arg_identity_extra_this_machine, STRV_MAKE(field));
        if (r < 0)
                return log_error_errno(r, "Failed to filter JSON identity data: %m");

        return 0;
}

static int help(int argc, char *argv[], void *userdata) {
        _cleanup_free_ char *link = NULL;
        int r;

        (void) pager_open(arg_pager_flags);

        r = terminal_urlify_man("homectl", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s [OPTIONS...] {COMMAND} ...\n\n"
               "Create, manipulate or inspect home directories.\n\n"
               "  -h --help                   Show this help\n"
               "     --version                Show package version\n"
               "     --no-pager               Do not pipe output into a pager\n"
               "     --no-legend              Do not show the headers and footers\n"
               "     --no-ask-password        Do not ask for system passwords\n"
               "  -H --host=[USER@]HOST       Operate on remote host\n"
               "  -M --machine=CONTAINER      Operate on local container\n"
               "     --identity=PATH          Read JSON identity from file\n"
               "     --json=FORMAT            Output inspection data in JSON (takes one of\n"
               "                              pretty, short, off)\n"
               "  -j                          Equivalent to --json=pretty (on TTY) or\n"
               "                              --json=short (otherwise)\n"
               "     --export-format=         Strip JSON inspection data (full, stripped,\n"
               "                              minimal)\n"
               "  -E                          When specified once equals -j --export-format=\n"
               "                              stripped, when specified twice equals\n"
               "                              -j --export-format=minimal\n"
               "\n%3$sGeneral User Record Properties:%4$s\n"
               "  -c --real-name=REALNAME     Real name for user\n"
               "     --realm=REALM            Realm to create user in\n"
               "     --email-address=EMAIL    Email address for user\n"
               "     --location=LOCATION      Set location of user on earth\n"
               "     --password-hint=HINT     Set Password hint\n"
               "     --icon-name=NAME         Icon name for user\n"
               "  -d --home-dir=PATH          Home directory\n"
               "     --uid=UID                Numeric UID for user\n"
               "  -G --member-of=GROUP        Add user to group\n"
               "     --skel=PATH              Skeleton directory to use\n"
               "     --shell=PATH             Shell for account\n"
               "     --setenv=VARIABLE=VALUE  Set an environment variable at log-in\n"
               "     --timezone=TIMEZONE      Set a time-zone\n"
               "     --language=LOCALE        Set preferred language\n"
               "     --ssh-authorized-keys=KEYS\n"
               "                              Specify SSH public keys\n"
               "\n%3$sAccount Management User Record Properties:%4$s\n"
               "     --locked=BOOL            Set locked account state\n"
               "     --not-before=TIMESTAMP   Do not allow logins before\n"
               "     --not-after=TIMESTAMP    Do not allow logins after\n"
               "     --rate-limit-interval=SECS\n"
               "                              Login rate-limit interval in seconds\n"
               "     --rate-limit-burst=NUMBER\n"
               "                              Login rate-limit attempts per interval\n"
               "     --enforce-password-policy=BOOL\n"
               "                              Control whether to enforce system's password\n"
               "                              policy for this user\n"
               "  -P                          Equivalent to --enforce-password-password=no\n"
               "\n%3$sResource Management User Record Properties:%4$s\n"
               "     --disk-size=BYTES        Size to assign the user on disk\n"
               "     --access-mode=MODE       User home directory access mode\n"
               "     --umask=MODE             Umask for user when logging in\n"
               "     --nice=NICE              Nice level for user\n"
               "     --rlimit=LIMIT=VALUE[:VALUE]\n"
               "                              Set resource limits\n"
               "     --tasks-max=MAX          Set maximum number of per-user tasks\n"
               "     --memory-high=BYTES      Set high memory threshold in bytes\n"
               "     --memory-max=BYTES       Set maximum memory limit\n"
               "     --cpu-weight=WEIGHT      Set CPU weight\n"
               "     --io-weight=WEIGHT       Set IO weight\n"
               "\n%3$sStorage User Record Properties:%4$s\n"
               "     --storage=STORAGE        Storage type to use (luks, fscrypt, directory,\n"
               "                              subvolume, cifs)\n"
               "     --image-path=PATH        Path to image file/directory\n"
               "\n%3$sLUKS Storage User Record Properties:%4$s\n"
               "     --fs-type=TYPE           File system type to use in case of luks\n"
               "                              storage (ext4, xfs, btrfs)\n"
               "     --luks-discard=BOOL      Whether to use 'discard' feature of file system\n"
               "     --luks-cipher=CIPHER     Cipher to use for LUKS encryption\n"
               "     --luks-cipher-mode=MODE  Cipher mode to use for LUKS encryption\n"
               "     --luks-volume-key-size=BITS\n"
               "                              Volume key size to use for LUKS encryption\n"
               "     --luks-pbkdf-type=TYPE   Password-based Key Derivation Function to use\n"
               "     --luks-pbkdf-hash-algorithm=ALGORITHM\n"
               "                              PBKDF hash algorithm to use\n"
               "     --luks-pbkdf-time-cost=SECS\n"
               "                              Time cost for PBKDF in seconds\n"
               "     --luks-pbkdf-memory-cost=BYTES\n"
               "                              Memory cost for PBKDF in bytes\n"
               "     --luks-pbkdf-parallel-threads=NUMBER\n"
               "                              Number of parallel threads for PKBDF\n"
               "\n%3$sMounting User Record Properties:%4$s\n"
               "     --nosuid=BOOL            Control the 'nosuid' flag of the home mount\n"
               "     --nodev=BOOL             Control the 'nodev' flag of the home mount\n"
               "     --noexec=BOOL            Control the 'noexec' flag of the home mount\n"
               "\n%3$sCIFS User Record Properties:%4$s\n"
               "     --cifs-domain=DOMAIN     CIFS (Windows) domain\n"
               "     --cifs-user-name=USER    CIFS (Windows) user name\n"
               "     --cifs-service=SERVICE   CIFS (Windows) service to mount as home\n"
               "\n%3$sLogin Behaviour User Record Properties:%4$s\n"
               "     --stop-delay=SECS        How long to leave user services running after\n"
               "                              logout\n"
               "     --kill-processes=BOOL    Whether to kill user processes when sessions\n"
               "                              terminate\n"
               "     --auto-login=BOOL        Try to log this user in automatically\n"
               "\n%3$sCommands:%4$s\n"
               "  list                        List homes\n"
               "  activate USER…              Activate home\n"
               "  deactivate USER…            Deactivate home\n"
               "  inspect USER…               Inspect home\n"
               "  authenticate USER…          Authenticate home\n"
               "  create USER                 Create a home\n"
               "  remove USER…                Remove a home\n"
               "  update USER                 Update a home\n"
               "  passwd USER                 Change password of a home\n"
               "  resize USER SIZE            Resize a home\n"
               "  lock USER…                  Temporarily lock an active home\n"
               "  unlock USER…                Unlock a temporarily locked home\n"
               "  lock-all                    Lock all suitable homes\n"
               "  with USER [COMMAND…]        Run shell or command with access to home\n"
               "\nSee the %2$s for details.\n"
               , program_invocation_short_name
               , link
               , ansi_underline(), ansi_normal()
        );

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_NO_PAGER,
                ARG_NO_LEGEND,
                ARG_NO_ASK_PASSWORD,
                ARG_REALM,
                ARG_EMAIL_ADDRESS,
                ARG_DISK_SIZE,
                ARG_ACCESS_MODE,
                ARG_STORAGE,
                ARG_FS_TYPE,
                ARG_IMAGE_PATH,
                ARG_UMASK,
                ARG_LUKS_DISCARD,
                ARG_JSON,
                ARG_SETENV,
                ARG_TIMEZONE,
                ARG_LANGUAGE,
                ARG_LOCKED,
                ARG_SSH_AUTHORIZED_KEYS,
                ARG_LOCATION,
                ARG_ICON_NAME,
                ARG_PASSWORD_HINT,
                ARG_NICE,
                ARG_RLIMIT,
                ARG_NOT_BEFORE,
                ARG_NOT_AFTER,
                ARG_LUKS_CIPHER,
                ARG_LUKS_CIPHER_MODE,
                ARG_LUKS_VOLUME_KEY_SIZE,
                ARG_NOSUID,
                ARG_NODEV,
                ARG_NOEXEC,
                ARG_CIFS_DOMAIN,
                ARG_CIFS_USER_NAME,
                ARG_CIFS_SERVICE,
                ARG_TASKS_MAX,
                ARG_MEMORY_HIGH,
                ARG_MEMORY_MAX,
                ARG_CPU_WEIGHT,
                ARG_IO_WEIGHT,
                ARG_LUKS_PBKDF_TYPE,
                ARG_LUKS_PBKDF_HASH_ALGORITHM,
                ARG_LUKS_PBKDF_TIME_COST,
                ARG_LUKS_PBKDF_MEMORY_COST,
                ARG_LUKS_PBKDF_PARALLEL_THREADS,
                ARG_RATE_LIMIT_INTERVAL,
                ARG_RATE_LIMIT_BURST,
                ARG_STOP_DELAY,
                ARG_KILL_PROCESSES,
                ARG_ENFORCE_PASSWORD_POLICY,
                ARG_EXPORT_FORMAT,
                ARG_AUTO_LOGIN,
        };

        static const struct option options[] = {
                { "help",                        no_argument,       NULL, 'h'                             },
                { "version",                     no_argument,       NULL, ARG_VERSION                     },
                { "no-pager",                    no_argument,       NULL, ARG_NO_PAGER                    },
                { "no-legend",                   no_argument,       NULL, ARG_NO_LEGEND                   },
                { "no-ask-password",             no_argument,       NULL, ARG_NO_ASK_PASSWORD             },
                { "host",                        required_argument, NULL, 'H'                             },
                { "machine",                     required_argument, NULL, 'M'                             },
                { "identity",                    required_argument, NULL, 'I'                             },
                { "real-name",                   required_argument, NULL, 'c'                             },
                { "comment",                     required_argument, NULL, 'c'                             }, /* Compat alias to keep thing in sync with useradd(8) */
                { "realm",                       required_argument, NULL, ARG_REALM                       },
                { "email-address",               required_argument, NULL, ARG_EMAIL_ADDRESS               },
                { "location",                    required_argument, NULL, ARG_LOCATION                    },
                { "password-hint",               required_argument, NULL, ARG_PASSWORD_HINT               },
                { "icon-name",                   required_argument, NULL, ARG_ICON_NAME                   },
                { "home-dir",                    required_argument, NULL, 'd'                             }, /* Compatible with useradd(8) */
                { "uid",                         required_argument, NULL, 'u'                             }, /* Compatible with useradd(8) */
                { "member-of",                   required_argument, NULL, 'G'                             },
                { "groups",                      required_argument, NULL, 'G'                             }, /* Compat alias to keep thing in sync with useradd(8) */
                { "skel",                        required_argument, NULL, 'k'                             }, /* Compatible with useradd(8) */
                { "shell",                       required_argument, NULL, 's'                             }, /* Compatible with useradd(8) */
                { "setenv",                      required_argument, NULL, ARG_SETENV                      },
                { "timezone",                    required_argument, NULL, ARG_TIMEZONE                    },
                { "language",                    required_argument, NULL, ARG_LANGUAGE                    },
                { "locked",                      required_argument, NULL, ARG_LOCKED                      },
                { "not-before",                  required_argument, NULL, ARG_NOT_BEFORE                  },
                { "not-after",                   required_argument, NULL, ARG_NOT_AFTER                   },
                { "expiredate",                  required_argument, NULL, 'e'                             }, /* Compat alias to keep thing in sync with useradd(8) */
                { "ssh-authorized-keys",         required_argument, NULL, ARG_SSH_AUTHORIZED_KEYS         },
                { "disk-size",                   required_argument, NULL, ARG_DISK_SIZE                   },
                { "access-mode",                 required_argument, NULL, ARG_ACCESS_MODE                 },
                { "umask",                       required_argument, NULL, ARG_UMASK                       },
                { "nice",                        required_argument, NULL, ARG_NICE                        },
                { "rlimit",                      required_argument, NULL, ARG_RLIMIT                      },
                { "tasks-max",                   required_argument, NULL, ARG_TASKS_MAX                   },
                { "memory-high",                 required_argument, NULL, ARG_MEMORY_HIGH                 },
                { "memory-max",                  required_argument, NULL, ARG_MEMORY_MAX                  },
                { "cpu-weight",                  required_argument, NULL, ARG_CPU_WEIGHT                  },
                { "io-weight",                   required_argument, NULL, ARG_IO_WEIGHT                   },
                { "storage",                     required_argument, NULL, ARG_STORAGE                     },
                { "image-path",                  required_argument, NULL, ARG_IMAGE_PATH                  },
                { "fs-type",                     required_argument, NULL, ARG_FS_TYPE                     },
                { "luks-discard",                required_argument, NULL, ARG_LUKS_DISCARD                },
                { "luks-cipher",                 required_argument, NULL, ARG_LUKS_CIPHER                 },
                { "luks-cipher-mode",            required_argument, NULL, ARG_LUKS_CIPHER_MODE            },
                { "luks-volume-key-size",        required_argument, NULL, ARG_LUKS_VOLUME_KEY_SIZE        },
                { "luks-pbkdf-type",             required_argument, NULL, ARG_LUKS_PBKDF_TYPE             },
                { "luks-pbkdf-hash-algorithm",   required_argument, NULL, ARG_LUKS_PBKDF_HASH_ALGORITHM   },
                { "luks-pbkdf-time-cost",        required_argument, NULL, ARG_LUKS_PBKDF_TIME_COST        },
                { "luks-pbkdf-memory-cost",      required_argument, NULL, ARG_LUKS_PBKDF_MEMORY_COST      },
                { "luks-pbkdf-parallel-threads", required_argument, NULL, ARG_LUKS_PBKDF_PARALLEL_THREADS },
                { "nosuid",                      required_argument, NULL, ARG_NOSUID                      },
                { "nodev",                       required_argument, NULL, ARG_NODEV                       },
                { "noexec",                      required_argument, NULL, ARG_NOEXEC                      },
                { "cifs-user-name",              required_argument, NULL, ARG_CIFS_USER_NAME              },
                { "cifs-domain",                 required_argument, NULL, ARG_CIFS_DOMAIN                 },
                { "cifs-service",                required_argument, NULL, ARG_CIFS_SERVICE                },
                { "rate-limit-interval",         required_argument, NULL, ARG_RATE_LIMIT_INTERVAL         },
                { "rate-limit-burst",            required_argument, NULL, ARG_RATE_LIMIT_BURST            },
                { "stop-delay",                  required_argument, NULL, ARG_STOP_DELAY                  },
                { "kill-processes",              required_argument, NULL, ARG_KILL_PROCESSES              },
                { "enforce-password-policy",     required_argument, NULL, ARG_ENFORCE_PASSWORD_POLICY     },
                { "auto-login",                  required_argument, NULL, ARG_AUTO_LOGIN                  },
                { "json",                        required_argument, NULL, ARG_JSON                        },
                { "export-format",               required_argument, NULL, ARG_EXPORT_FORMAT               },
                {}
        };

        int r;

        assert(argc >= 0);
        assert(argv);

        for (;;) {
                int c;

                c = getopt_long(argc, argv, "hH:M:I:c:d:u:k:s:e:G:jPE", options, NULL);
                if (c < 0)
                        break;

                switch (c) {

                case 'h':
                        return help(0, NULL, NULL);

                case ARG_VERSION:
                        return version();

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case ARG_NO_LEGEND:
                        arg_legend = false;
                        break;

                case ARG_NO_ASK_PASSWORD:
                        arg_ask_password = false;
                        break;

                case 'H':
                        arg_transport = BUS_TRANSPORT_REMOTE;
                        arg_host = optarg;
                        break;

                case 'M':
                        arg_transport = BUS_TRANSPORT_MACHINE;
                        arg_host = optarg;
                        break;

                case 'I':
                        arg_identity = optarg;
                        break;

                case 'c':
                        if (isempty(optarg)) {
                                r = drop_from_identity("realName");
                                if (r < 0)
                                        return r;

                                break;
                        }

                        if (!valid_gecos(optarg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Real name '%s' not a valid GECOS field.", optarg);

                        r = json_variant_set_field_string(&arg_identity_extra, "realName", optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set realName field: %m");

                        break;

                case 'd': {
                        _cleanup_free_ char *hd = NULL;

                        if (isempty(optarg)) {
                                r = drop_from_identity("homeDirectory");
                                if (r < 0)
                                        return r;

                                break;
                        }

                        r = parse_path_argument_and_warn(optarg, false, &hd);
                        if (r < 0)
                                return r;

                        if (!valid_home(hd))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Home directory '%s' not valid.", hd);

                        r = json_variant_set_field_string(&arg_identity_extra, "homeDirectory", hd);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set homeDirectory field: %m");

                        break;
                }

                case ARG_REALM:
                        if (isempty(optarg)) {
                                r = drop_from_identity("realm");
                                if (r < 0)
                                        return r;

                                break;
                        }

                        r = dns_name_is_valid(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to determine whether realm '%s' is a valid DNS domain: %m", optarg);
                        if (r == 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Realm '%s' is not a valid DNS domain: %m", optarg);

                        r = json_variant_set_field_string(&arg_identity_extra, "realm", optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set realm field: %m");
                        break;

                case ARG_EMAIL_ADDRESS:
                case ARG_LOCATION:
                case ARG_ICON_NAME:
                case ARG_CIFS_USER_NAME:
                case ARG_CIFS_DOMAIN:
                case ARG_CIFS_SERVICE: {

                        const char *field =
                                c == ARG_EMAIL_ADDRESS ? "emailAddress" :
                                     c == ARG_LOCATION ? "location" :
                                    c == ARG_ICON_NAME ? "iconName" :
                               c == ARG_CIFS_USER_NAME ? "cifsUserName" :
                                  c == ARG_CIFS_DOMAIN ? "cifsDomain" :
                                 c == ARG_CIFS_SERVICE ? "cifsService" :
                                                         NULL;

                        assert(field);

                        if (isempty(optarg)) {
                                r = drop_from_identity(field);
                                if (r < 0)
                                        return r;

                                break;
                        }

                        r = json_variant_set_field_string(&arg_identity_extra, field, optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set %s field: %m", field);

                        break;
                }

                case ARG_PASSWORD_HINT:
                        if (isempty(optarg)) {
                                r = drop_from_identity("passwordHint");
                                if (r < 0)
                                        return r;

                                break;
                        }

                        r = json_variant_set_field_string(&arg_identity_extra_privileged, "passwordHint", optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set passwordHint field: %m");

                        string_erase(optarg);
                        break;

                case ARG_NICE: {
                        int nc;

                        if (isempty(optarg)) {
                                r = drop_from_identity("niceLevel");
                                if (r < 0)
                                        return r;
                                break;
                        }

                        r = parse_nice(optarg, &nc);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse nice level: %s", optarg);

                        r = json_variant_set_field_integer(&arg_identity_extra, "niceLevel", nc);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set niceLevel field: %m");

                        break;
                }

                case ARG_RLIMIT: {
                        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL, *jcur = NULL, *jmax = NULL;
                        _cleanup_free_ char *field = NULL, *t = NULL;
                        const char *eq;
                        struct rlimit rl;
                        int l;

                        if (isempty(optarg)) {
                                /* Remove all resource limits */

                                r = drop_from_identity("resourceLimits");
                                if (r < 0)
                                        return r;

                                arg_identity_filter_rlimits = strv_free(arg_identity_filter_rlimits);
                                arg_identity_extra_rlimits = json_variant_unref(arg_identity_extra_rlimits);
                                break;
                        }

                        eq = strchr(optarg, '=');
                        if (!eq)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Can't parse resource limit assignment: %s", optarg);

                        field = strndup(optarg, eq - optarg);
                        if (!field)
                                return log_oom();

                        l = rlimit_from_string_harder(field);
                        if (l < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown resource limit type: %s", field);

                        if (isempty(eq + 1)) {
                                /* Remove only the specific rlimit */

                                r = strv_extend(&arg_identity_filter_rlimits, rlimit_to_string(l));
                                if (r < 0)
                                        return r;

                                r = json_variant_filter(&arg_identity_extra_rlimits, STRV_MAKE(field));
                                if (r < 0)
                                        return log_error_errno(r, "Failed to filter JSON identity data: %m");

                                break;
                        }

                        r = rlimit_parse(l, eq + 1, &rl);
                        if (r < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to parse resource limit value: %s", eq + 1);

                        r = rl.rlim_cur == RLIM_INFINITY ? json_variant_new_null(&jcur) : json_variant_new_unsigned(&jcur, rl.rlim_cur);
                        if (r < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to allocate current integer: %m");

                        r = rl.rlim_max == RLIM_INFINITY ? json_variant_new_null(&jmax) : json_variant_new_unsigned(&jmax, rl.rlim_max);
                        if (r < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to allocate maximum integer: %m");

                        r = json_build(&v,
                                       JSON_BUILD_OBJECT(
                                                       JSON_BUILD_PAIR("cur", JSON_BUILD_VARIANT(jcur)),
                                                       JSON_BUILD_PAIR("max", JSON_BUILD_VARIANT(jmax))));
                        if (r < 0)
                                return log_error_errno(r, "Failed to build resource limit: %m");

                        t = strjoin("RLIMIT_", rlimit_to_string(l));
                        if (!t)
                                return log_oom();

                        r = json_variant_set_field(&arg_identity_extra_rlimits, t, v);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set %s field: %m", rlimit_to_string(l));

                        break;
                }

                case 'u': {
                        uid_t uid;

                        if (isempty(optarg)) {
                                r = drop_from_identity("uid");
                                if (r < 0)
                                        return r;

                                break;
                        }

                        r = parse_uid(optarg, &uid);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse UID '%s'.", optarg);

                        if (uid_is_system(uid))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "UID " UID_FMT " is in system range, refusing.", uid);
                        if (uid_is_dynamic(uid))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "UID " UID_FMT " is in dynamic range, refusing.", uid);
                        if (uid == UID_NOBODY)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "UID " UID_FMT " is nobody UID, refusing.", uid);

                        r = json_variant_set_field_unsigned(&arg_identity_extra, "uid", uid);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set realm field: %m");

                        break;
                }

                case 'k':
                case ARG_IMAGE_PATH: {
                        const char *field = c == 'k' ? "skeletonDirectory" : "imagePath";
                        _cleanup_free_ char *v = NULL;

                        if (isempty(optarg)) {
                                r = drop_from_identity(field);
                                if (r < 0)
                                        return r;

                                break;
                        }

                        r = parse_path_argument_and_warn(optarg, false, &v);
                        if (r < 0)
                                return r;

                        r = json_variant_set_field_string(&arg_identity_extra_this_machine, field, v);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set %s field: %m", v);

                        break;
                }

                case 's':
                        if (isempty(optarg)) {
                                r = drop_from_identity("shell");
                                if (r < 0)
                                        return r;

                                break;
                        }

                        if (!valid_shell(optarg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Shell '%s' not valid.", optarg);

                        r = json_variant_set_field_string(&arg_identity_extra, "shell", optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set shell field: %m");

                        break;

                case ARG_SETENV: {
                        _cleanup_free_ char **l = NULL, **k = NULL;
                        _cleanup_(json_variant_unrefp) JsonVariant *ne = NULL;
                        JsonVariant *e;

                        if (isempty(optarg)) {
                                r = drop_from_identity("environment");
                                if (r < 0)
                                        return r;

                                break;
                        }

                        if (!env_assignment_is_valid(optarg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Environment assignment '%s' not valid.", optarg);

                        e = json_variant_by_key(arg_identity_extra, "environment");
                        if (e) {
                                r = json_variant_strv(e, &l);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse JSON environment field: %m");
                        }

                        k = strv_env_set(l, optarg);
                        if (!k)
                                return log_oom();

                        strv_sort(k);

                        r = json_variant_new_array_strv(&ne, k);
                        if (r < 0)
                                return log_error_errno(r, "Failed to allocate environment list JSON: %m");

                        r = json_variant_set_field(&arg_identity_extra, "environment", ne);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set environent list: %m");

                        break;
                }

                case ARG_TIMEZONE:

                        if (isempty(optarg)) {
                                r = drop_from_identity("timeZone");
                                if (r < 0)
                                        return r;

                                break;
                        }

                        if (!timezone_is_valid(optarg, LOG_DEBUG))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Timezone '%s' is not valid.", optarg);

                        r = json_variant_set_field_string(&arg_identity_extra, "timeZone", optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set timezone field: %m");

                        break;

                case ARG_LANGUAGE:
                        if (isempty(optarg)) {
                                r = drop_from_identity("language");
                                if (r < 0)
                                        return r;

                                break;
                        }

                        if (!locale_is_valid(optarg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Locale '%s' is not valid.", optarg);

                        r = json_variant_set_field_string(&arg_identity_extra, "preferredLanguage", optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set preferredLanguage field: %m");

                        break;

                case ARG_NOSUID:
                case ARG_NODEV:
                case ARG_NOEXEC:
                case ARG_LOCKED:
                case ARG_KILL_PROCESSES:
                case ARG_ENFORCE_PASSWORD_POLICY:
                case ARG_AUTO_LOGIN: {
                        const char *field =
                                                 c == ARG_LOCKED ? "locked" :
                                                 c == ARG_NOSUID ? "mountNoSUID" :
                                                  c == ARG_NODEV ? "mountNoDevices" :
                                                 c == ARG_NOEXEC ? "mountNoExecute" :
                                         c == ARG_KILL_PROCESSES ? "killProcesses" :
                                c == ARG_ENFORCE_PASSWORD_POLICY ? "enforcePasswordPolicy" :
                                             c == ARG_AUTO_LOGIN ? "autoLogin" :
                                                                   NULL;

                        assert(field);

                        if (isempty(optarg)) {
                                r = drop_from_identity(field);
                                if (r < 0)
                                        return r;

                                break;
                        }

                        r = parse_boolean(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse %s boolean: %m", field);

                        r = json_variant_set_field_boolean(&arg_identity_extra, field, r > 0);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set %s field: %m", field);

                        break;
                }

                case 'P':
                        r = json_variant_set_field_boolean(&arg_identity_extra, "enforcePasswordPolicy", false);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set enforcePasswordPolicy field: %m");

                        break;

                case ARG_DISK_SIZE:
                        if (isempty(optarg)) {
                                r = drop_from_identity("diskSize");
                                if (r < 0)
                                        return r;

                                r = drop_from_identity("diskSizeRelative");
                                if (r < 0)
                                        return r;

                                arg_disk_size = arg_disk_size_relative = UINT64_MAX;
                                break;
                        }

                        r = parse_permille(optarg);
                        if (r < 0) {
                                r = parse_size(optarg, 1024, &arg_disk_size);
                                if (r < 0)
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Disk size '%s' not valid.", optarg);

                                r = drop_from_identity("diskSizeRelative");
                                if (r < 0)
                                        return r;

                                r = json_variant_set_field_unsigned(&arg_identity_extra_this_machine, "diskSize", arg_disk_size);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to set diskSize field: %m");

                                arg_disk_size_relative = UINT64_MAX;
                        } else {
                                /* Normalize to UINT32_MAX == 100% */
                                arg_disk_size_relative = (uint64_t) r * UINT32_MAX / 1000U;

                                r = drop_from_identity("diskSize");
                                if (r < 0)
                                        return r;

                                r = json_variant_set_field_unsigned(&arg_identity_extra_this_machine, "diskSizeRelative", arg_disk_size_relative);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to set diskSizeRelative field: %m");

                                arg_disk_size = UINT64_MAX;
                        }

                        break;

                case ARG_ACCESS_MODE: {
                        mode_t mode;

                        if (isempty(optarg)) {
                                r = drop_from_identity("accessMode");
                                if (r < 0)
                                        return r;

                                break;
                        }

                        r = parse_mode(optarg, &mode);
                        if (r < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Access mode '%s' not valid.", optarg);

                        r = json_variant_set_field_unsigned(&arg_identity_extra, "accessMode", mode);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set access mode field: %m");

                        break;
                }

                case ARG_LUKS_DISCARD:
                        if (isempty(optarg)) {
                                r = drop_from_identity("luksDiscard");
                                if (r < 0)
                                        return r;

                                break;
                        }

                        r = parse_boolean(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --luks-discard= parameter: %s", optarg);

                        r = json_variant_set_field_boolean(&arg_identity_extra, "luksDiscard", r);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set discard field: %m");

                        break;

                case ARG_LUKS_VOLUME_KEY_SIZE:
                case ARG_LUKS_PBKDF_PARALLEL_THREADS:
                case ARG_RATE_LIMIT_BURST: {
                        const char *field =
                                       c == ARG_LUKS_VOLUME_KEY_SIZE ? "luksVolumeKeySize" :
                                c == ARG_LUKS_PBKDF_PARALLEL_THREADS ? "luksPbkdfParallelThreads" :
                                           c == ARG_RATE_LIMIT_BURST ? "rateLimitBurst" : NULL;
                        unsigned n;

                        assert(field);

                        if (isempty(optarg)) {
                                r = drop_from_identity(field);
                                if (r < 0)
                                        return r;
                        }

                        r = safe_atou(optarg, &n);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse %s parameter: %s", field, optarg);

                        r = json_variant_set_field_unsigned(&arg_identity_extra, field, n);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set %s field: %m", field);

                        break;
                }

                case ARG_UMASK: {
                        mode_t m;

                        if (isempty(optarg)) {
                                r = drop_from_identity("umask");
                                if (r < 0)
                                        return r;

                                break;
                        }

                        r = parse_mode(optarg, &m);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse umask: %m");

                        r = json_variant_set_field_integer(&arg_identity_extra, "umask", m);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set umask field: %m");

                        break;
                }

                case ARG_SSH_AUTHORIZED_KEYS: {
                        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL, *p = NULL;
                        _cleanup_(strv_freep) char **l = NULL, **add = NULL;

                        if (isempty(optarg)) {
                                r = drop_from_identity("sshAuthorizedKeys");
                                if (r < 0)
                                        return r;

                                break;
                        }

                        if (optarg[0] == '@') {
                                _cleanup_fclose_ FILE *f = NULL;

                                /* If prefixed with '@' read from a file */

                                f = fopen(optarg+1, "re");
                                if (!f)
                                        return log_error_errno(errno, "Failed to open '%s': %m", optarg+1);

                                for (;;) {
                                        _cleanup_free_ char *line = NULL;

                                        r = read_line(f, LONG_LINE_MAX, &line);
                                        if (r < 0)
                                                return log_error_errno(r, "Faile dto read from '%s': %m", optarg+1);
                                        if (r == 0)
                                                break;

                                        if (isempty(line))
                                                continue;

                                        if (line[0] == '#')
                                                continue;

                                        r = strv_consume(&add, TAKE_PTR(line));
                                        if (r < 0)
                                                return log_oom();
                                }
                        } else {
                                /* Otherwise, assume it's a literal key. Let's do some superficial checks
                                 * before accept it though. */

                                if (string_has_cc(optarg, NULL))
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Authorized key contains control characters, refusing.");
                                if (optarg[0] == '#')
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Specified key is a comment?");

                                add = strv_new(optarg);
                                if (!add)
                                        return log_oom();
                        }

                        v = json_variant_ref(json_variant_by_key(arg_identity_extra_privileged, "sshAuthorizedKeys"));
                        if (v) {
                                r = json_variant_strv(v, &l);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse SSH authorized keys list: %m");
                        }

                        r = strv_extend_strv(&l, add, true);
                        if (r < 0)
                                return log_oom();

                        v = json_variant_unref(v);

                        r = json_variant_new_array_strv(&v, l);
                        if (r < 0)
                                return log_oom();

                        r = json_variant_set_field(&arg_identity_extra_privileged, "sshAuthorizedKeys", v);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set authorized keys: %m");

                        break;
                }

                case ARG_NOT_BEFORE:
                case ARG_NOT_AFTER:
                case 'e': {
                        const char *field;
                        usec_t n;

                        field =           c == ARG_NOT_BEFORE ? "notBeforeUSec" :
                                IN_SET(c, ARG_NOT_AFTER, 'e') ? "notAfterUSec" : NULL;

                        assert(field);

                        if (isempty(optarg)) {
                                r = drop_from_identity(field);
                                if (r < 0)
                                        return r;

                                break;
                        }

                        /* Note the minor discrepancy regarding -e parsing here: we support that for compat
                         * reasons, and in the original useradd(8) implementation it accepts dates in the
                         * format YYYY-MM-DD. Coincidentally, we accept dates formatted like that too, but
                         * with greater precision. */
                        r = parse_timestamp(optarg, &n);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse %s parameter: %m", field);

                        r = json_variant_set_field_unsigned(&arg_identity_extra, field, n);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set %s field: %m", field);
                        break;
                }

                case ARG_STORAGE:
                case ARG_FS_TYPE:
                case ARG_LUKS_CIPHER:
                case ARG_LUKS_CIPHER_MODE:
                case ARG_LUKS_PBKDF_TYPE:
                case ARG_LUKS_PBKDF_HASH_ALGORITHM: {

                        const char *field =
                                                  c == ARG_STORAGE ? "storage" :
                                                  c == ARG_FS_TYPE ?  "fileSytemType" :
                                              c == ARG_LUKS_CIPHER ? "luksCipher" :
                                         c == ARG_LUKS_CIPHER_MODE ? "luksCipherMode" :
                                          c == ARG_LUKS_PBKDF_TYPE ? "luksPbkdfType" :
                                c == ARG_LUKS_PBKDF_HASH_ALGORITHM ? "luksPbkdfHashAlgorithm" : NULL;

                        assert(field);

                        if (isempty(optarg)) {
                                r = drop_from_identity(field);
                                if (r < 0)
                                        return r;

                                break;
                        }

                        if (!string_is_safe(optarg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Parameter for %s field not valid: %s", field, optarg);

                        r = json_variant_set_field_string(
                                        IN_SET(c, ARG_STORAGE, ARG_FS_TYPE) ?
                                        &arg_identity_extra_this_machine :
                                        &arg_identity_extra, field, optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set %s field: %m", field);

                        break;
                }

                case ARG_LUKS_PBKDF_TIME_COST:
                case ARG_RATE_LIMIT_INTERVAL:
                case ARG_STOP_DELAY: {
                        const char *field =
                                c == ARG_LUKS_PBKDF_TIME_COST ? "luksPbkdfTimeCostUSec" :
                                 c == ARG_RATE_LIMIT_INTERVAL ? "rateLimitIntervalUSec" :
                                          c == ARG_STOP_DELAY ? "stopDelayUSec" :
                                                                NULL;
                        usec_t t;

                        assert(field);

                        if (isempty(optarg)) {
                                r = drop_from_identity(field);
                                if (r < 0)
                                        return r;

                                break;
                        }

                        r = parse_sec(optarg, &t);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse %s field: %s", field, optarg);

                        r = json_variant_set_field_unsigned(&arg_identity_extra, field, t);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set %s field: %m", field);

                        break;
                }

                case 'G': {
                        const char *p = optarg;

                        if (isempty(p)) {
                                r = drop_from_identity("memberOf");
                                if (r < 0)
                                        return r;

                                break;
                        }

                        for (;;) {
                                _cleanup_(json_variant_unrefp) JsonVariant *mo = NULL;
                                _cleanup_strv_free_ char **list = NULL;
                                _cleanup_free_ char *word = NULL;

                                r = extract_first_word(&p, &word, ",", 0);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse group list: %m");
                                if (r == 0)
                                        break;

                                if (!valid_user_group_name(word))
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid group name %s.", word);

                                mo = json_variant_ref(json_variant_by_key(arg_identity_extra, "memberOf"));

                                r = json_variant_strv(mo, &list);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse group list: %m");

                                r = strv_extend(&list, word);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to extend group list: %m");

                                strv_sort(list);
                                strv_uniq(list);

                                mo = json_variant_unref(mo);
                                r = json_variant_new_array_strv(&mo, list);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to create group list JSON: %m");

                                r = json_variant_set_field(&arg_identity_extra, "memberOf", mo);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to update group list: %m");
                        }

                        break;
                }

                case ARG_TASKS_MAX: {
                        uint64_t u;

                        if (isempty(optarg)) {
                                r = drop_from_identity("tasksMax");
                                if (r < 0)
                                        return r;
                                break;
                        }

                        r = safe_atou64(optarg, &u);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --tasks-max= parameter: %s", optarg);

                        r = json_variant_set_field_unsigned(&arg_identity_extra, "tasksMax", u);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set tasksMax field: %m");

                        break;
                }

                case ARG_MEMORY_MAX:
                case ARG_MEMORY_HIGH:
                case ARG_LUKS_PBKDF_MEMORY_COST: {
                        const char *field =
                                            c == ARG_MEMORY_MAX ? "memoryMax" :
                                           c == ARG_MEMORY_HIGH ? "memoryHigh" :
                                c == ARG_LUKS_PBKDF_MEMORY_COST ? "luksPbkdfMemoryCost" : NULL;

                        uint64_t u;

                        assert(field);

                        if (isempty(optarg)) {
                                r = drop_from_identity(field);
                                if (r < 0)
                                        return r;
                                break;
                        }

                        r = parse_size(optarg, 1024, &u);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse %s parameter: %s", field, optarg);

                        r = json_variant_set_field_unsigned(&arg_identity_extra_this_machine, field, u);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set %s field: %m", field);

                        break;
                }

                case ARG_CPU_WEIGHT:
                case ARG_IO_WEIGHT: {
                        const char *field = c == ARG_CPU_WEIGHT ? "cpuWeight" :
                                            c == ARG_IO_WEIGHT ? "ioWeight" : NULL;
                        uint64_t u;

                        assert(field);

                        if (isempty(optarg)) {
                                r = drop_from_identity(field);
                                if (r < 0)
                                        return r;
                                break;
                        }

                        r = safe_atou64(optarg, &u);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --cpu-weight=/--io-weight= parameter: %s", optarg);

                        if (!CGROUP_WEIGHT_IS_OK(u))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Weight %" PRIu64 " is out of valid weight range.", u);

                        r = json_variant_set_field_unsigned(&arg_identity_extra, field, u);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set %s field: %m", field);

                        break;
                }

                case 'j':
                        arg_json = true;
                        arg_json_format_flags = JSON_FORMAT_PRETTY_AUTO|JSON_FORMAT_COLOR_AUTO;
                        break;

                case ARG_JSON:
                        if (streq(optarg, "pretty")) {
                                arg_json = true;
                                arg_json_format_flags = JSON_FORMAT_PRETTY|JSON_FORMAT_COLOR_AUTO;
                        } else if (streq(optarg, "short")) {
                                arg_json = true;
                                arg_json_format_flags = JSON_FORMAT_NEWLINE;
                        } else if (streq(optarg, "off")) {
                                arg_json = false;
                                arg_json_format_flags = 0;
                        } else if (streq(optarg, "help")) {
                                puts("pretty\n"
                                     "short\n"
                                     "off");
                                return 0;
                        } else
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown argument to --json=: %s", optarg);

                        break;

                case 'E':
                        if (arg_export_format == EXPORT_FORMAT_FULL)
                                arg_export_format = EXPORT_FORMAT_STRIPPED;
                        else if (arg_export_format == EXPORT_FORMAT_STRIPPED)
                                arg_export_format = EXPORT_FORMAT_MINIMAL;
                        else
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Specifying -E more than twice is not supported.");

                        arg_json = true;
                        if (arg_json_format_flags == 0)
                                arg_json_format_flags = JSON_FORMAT_PRETTY_AUTO|JSON_FORMAT_COLOR_AUTO;
                        break;

                case ARG_EXPORT_FORMAT:
                        if (streq(optarg, "full"))
                                arg_export_format = EXPORT_FORMAT_FULL;
                        else if (streq(optarg, "stripped"))
                                arg_export_format = EXPORT_FORMAT_STRIPPED;
                        else if (streq(optarg, "minimal"))
                                arg_export_format = EXPORT_FORMAT_MINIMAL;
                        else if (streq(optarg, "help")) {
                                puts("full\n"
                                     "stripped\n"
                                     "minimal");
                                return 0;
                        }

                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }
        }

        return 1;
}

static int run(int argc, char *argv[]) {
        static const Verb verbs[] = {
                { "help",                VERB_ANY, VERB_ANY, 0,            help                },
                { "list",                VERB_ANY, 1,        VERB_DEFAULT, list_homes          },
                { "activate",            2,        VERB_ANY, 0,            activate_home       },
                { "deactivate",          2,        VERB_ANY, 0,            deactivate_home     },
                { "inspect",             VERB_ANY, VERB_ANY, 0,            inspect_home        },
                { "authenticate",        VERB_ANY, VERB_ANY, 0,            authenticate_home   },
                { "create",              VERB_ANY, 2,        0,            create_home         },
                { "remove",              2,        VERB_ANY, 0,            remove_home         },
                { "update",              VERB_ANY, 2,        0,            update_home         },
                { "passwd",              VERB_ANY, 2,        0,            passwd_home         },
                { "resize",              2,        3,        0,            resize_home         },
                { "lock",                2,        VERB_ANY, 0,            lock_home           },
                { "unlock",              2,        VERB_ANY, 0,            unlock_home         },
                { "with",                2,        VERB_ANY, 0,            with_home           },
                { "lock-all",            VERB_ANY, 1,        0,            lock_all_homes      },

                /* This one is a helper for sshd_config's AuthorizedKeysCommand= setting, it's not a
                 * user-facing verb and thus should not appear in man pages or --help texts. */
                { "ssh-authorized-keys", 2,        2,        0,            ssh_authorized_keys },
                {}
        };

        int r;

        log_show_color(true);
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        return dispatch_verb(argc, argv, verbs, NULL);
}

DEFINE_MAIN_FUNCTION(run);
