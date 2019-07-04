/* SPDX-License-Identifier: LGPL-2.1+ */

#if HAVE_CRYPT_H
#include <crypt.h>
#endif

#include "dns-domain.h"
#include "errno-util.h"
#include "home-util.h"
#include "memory-util.h"
#include "path-util.h"
#include "string-util.h"
#include "strv.h"
#include "user-util.h"

bool suitable_user_name(const char *name) {

        /* Checks whether the specified name is suitable for management via homed. Note that our client side
         * usually validate susing a simple valid_user_group_name(), while server side we are a bit more
         * restrictive, so that we can change the rules server side without having to update things client
         * side, too. */

        if (!valid_user_group_name(name))
                return false;

        /* We generally rely on NSS to tell us which users not to care for, but let's filter out some
         * particularly well-known users. */
        if (STR_IN_SET(name,
                       "root",
                       "nobody",
                       NOBODY_USER_NAME, NOBODY_GROUP_NAME))
                return false;

        /* Let's also defend our own namespace, as well as Debian's (unwritten?) logic of prefixing system
         * users with underscores. */
        if (STARTSWITH_SET(name, "systemd-", "_"))
                return false;

        return true;
}

int suitable_realm(const char *realm) {
        _cleanup_free_ char *normalized = NULL;
        int r;

        /* Similar to the above: let's validate the realm a bit stricter server-side than client side */

        r = dns_name_normalize(realm, 0, &normalized); /* this also checks general validity */
        if (r == -EINVAL)
                return 0;
        if (r < 0)
                return r;

        if (!streq(realm, normalized)) /* is this normalized? */
                return false;

        if (dns_name_is_root(realm) || dns_name_is_single_label(realm)) /* Don't allow top level domain nor single label domains */
                return false;

        return true;
}

int suitable_image_path(const char *path) {

        return !empty_or_root(path) &&
                path_is_valid(path) &&
                path_is_absolute(path);
}

int split_user_name_realm(const char *t, char **ret_user_name, char **ret_realm) {
        _cleanup_free_ char *un = NULL, *rr = NULL;
        const char *c;
        int r;

        assert(t);
        assert(ret_user_name);
        assert(ret_realm);

        c = strchr(t, '@');
        if (!c) {
                if (!suitable_user_name(t))
                        return -EINVAL;

                un = strdup(t);
                if (!un)
                        return -ENOMEM;
        } else {
                un = strndup(t, c - t);
                if (!un)
                        return -ENOMEM;

                if (!suitable_user_name(un))
                        return -EINVAL;

                r = suitable_realm(c + 1);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -EINVAL;

                rr = strdup(c + 1);
                if (!rr)
                        return -ENOMEM;
        }

        *ret_user_name = TAKE_PTR(un);
        *ret_realm = TAKE_PTR(rr);

        return 0;
}

int bus_message_append_secret(sd_bus_message *m, UserRecord *secret) {
        _cleanup_(erase_and_freep) char *formatted = NULL;
        JsonVariant *v;
        int r;

        assert(m);
        assert(secret);

        if (!FLAGS_SET(secret->mask, USER_RECORD_SECRET))
                return -EINVAL;

        v = json_variant_by_key(secret->json, "secret");
        if (!v)
                return -EINVAL;

        r = json_variant_format(v, 0, &formatted);
        if (r < 0)
                return r;

        return sd_bus_message_append(m, "s", formatted);
}

int test_password(char **hashed_password, const char *password) {
        char **hpw;

        STRV_FOREACH(hpw, hashed_password) {
                struct crypt_data cc = {};
                const char *k;
                bool b;

                errno = 0;
                k = crypt_r(password, *hpw, &cc);
                if (!k) {
                        explicit_bzero_safe(&cc, sizeof(cc));
                        return errno_or_else(EINVAL);
                }

                b = streq(k, *hpw);
                explicit_bzero_safe(&cc, sizeof(cc));

                if (b)
                        return true;
        }

        return false;
}
