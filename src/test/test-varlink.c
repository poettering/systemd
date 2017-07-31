/***
  This file is part of systemd.

  Copyright 2017 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <pthread.h>

#include "sd-event.h"
#include "varlink.h"
#include "json.h"
#include "user-util.h"

static int n_done = 0;

static int method_something(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {
        _cleanup_(json_variant_unrefp) JsonVariant *ret = NULL;
        JsonVariant *a, *b;
        intmax_t x, y;
        int r;

        a = json_variant_by_key(parameters, "a");
        if (!a)
                return varlink_reply_error(link, NULL, "io.test.BadParameters");

        x = json_variant_integer(a);

        b = json_variant_by_key(parameters, "b");
        if (!b)
                return varlink_reply_error(link, NULL, "io.test.BadParameters");

        y = json_variant_integer(b);

        r = json_build(&ret, JSON_BUILD_OBJECT(JSON_BUILD_PAIR("sum", JSON_BUILD_INTEGER(x + y))));
        if (r < 0)
                return r;

        return varlink_reply(link, ret);
}

static int method_done(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {

        if (++n_done == 2)
                sd_event_exit(varlink_get_event(link), EXIT_FAILURE);

        return 0;
}

static int reply(Varlink *link, JsonVariant *parameters, const char *error_id, VarlinkReplyFlags flags, void *userdata) {
        JsonVariant *sum;

        sum = json_variant_by_key(parameters, "sum");

        assert_se(json_variant_integer(sum) == 7+22);

        if (++n_done == 2)
                sd_event_exit(varlink_get_event(link), EXIT_FAILURE);

        return 0;
}

static int on_connect(VarlinkServer *s, Varlink *link, void *userdata) {
        uid_t uid = UID_INVALID;

        assert(s);
        assert(link);

        assert_se(varlink_get_peer_uid(link, &uid) >= 0);
        assert_se(getuid() == uid);

        return 0;
}

static void *thread(void*arg) {
        _cleanup_(varlink_flush_close_unrefp) Varlink *c = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *i = NULL;
        JsonVariant *o = NULL;
        const char *e;

        assert_se(json_build(&i, JSON_BUILD_OBJECT(JSON_BUILD_PAIR("a", JSON_BUILD_INTEGER(88)),
                                                   JSON_BUILD_PAIR("b", JSON_BUILD_INTEGER(99)))) >= 0);

        assert_se(varlink_connect_address(&c, "/tmp/quux") >= 0);

        assert_se(varlink_call(c, "io.test.DoSomething", i, &o, &e, NULL) >= 0);
        assert_se(json_variant_integer(json_variant_by_key(o, "sum")) == 88 + 99);

        assert_se(varlink_send(c, "io.test.Done", NULL) >= 0);

        return NULL;
}

int main(int argc, char *argv[]) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(varlink_server_unrefp) VarlinkServer *s = NULL;
        _cleanup_(varlink_flush_close_unrefp) Varlink *c = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        pthread_t t;

        log_set_max_level(LOG_DEBUG);
        log_open();

        assert_se(sd_event_default(&e) >= 0);

        assert_se(varlink_server_new(&s) >= 0);
        assert_se(varlink_server_add_interface(s,
R"(interface io.test

method DoSomething(a : int, b : int) -> (sum : int)
method Done() -> ()
)") >= 0);

        assert_se(varlink_server_bind_method(s, "io.test.DoSomething", method_something) >= 0);
        assert_se(varlink_server_bind_method(s, "io.test.Done", method_done) >= 0);
        assert_se(varlink_server_bind_connect(s, on_connect) >= 0);
        assert_se(varlink_server_listen_address(s, "/tmp/quux") >= 0);
        assert_se(varlink_server_attach_event(s, e, 0) >= 0);

        assert_se(varlink_connect_address(&c, "/tmp/quux") >= 0);
        assert_se(varlink_bind_reply(c, reply) >= 0);
        assert_se(json_build(&v, JSON_BUILD_OBJECT(JSON_BUILD_PAIR("a", JSON_BUILD_INTEGER(7)),
                                                   JSON_BUILD_PAIR("b", JSON_BUILD_INTEGER(22)))) >= 0);

        assert_se(varlink_invoke(c, "io.test.DoSomething", v) >= 0);
        assert_se(varlink_attach_event(c, e, 0) >= 0);

        assert_se(pthread_create(&t, NULL, thread, NULL) == 0);

        assert_se(sd_event_loop(e) >= 0);

        assert_se(pthread_join(t, NULL) == 0);

        return 0;
}
