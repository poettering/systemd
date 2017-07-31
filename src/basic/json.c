/***
  This file is part of systemd.

  Copyright 2014-2017 Lennart Poettering

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

#include <errno.h>
#include <math.h>
#include <stdarg.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "alloc-util.h"
#include "fileio.h"
#include "float.h"
#include "hexdecoct.h"
#include "json.h"
#include "macro.h"
#include "string-util.h"
#include "terminal-util.h"
#include "utf8.h"

struct JsonVariant {
        size_t n_ref;
        JsonVariantType type:6;

        /* In some conditions (for example, if this object is part of an array of strings or objects), we don't store
         * any data inline, but instead simply reference an external object and act as surrogate of it. In that case
         * this bool is set, and the external object is referenced through the .reference field below. */
        bool is_reference:1;

        /* While comparing two arrays, we use this for marking what we already have seen */
        bool marked:1;

        /* If this JsonVariant is part of an array, then this field is non-NULL and points to the surrounding
         * JSON_VARIANT_ARRAY object. */
        JsonVariant *parent;

        union {
                /* For simple types we store the value in-line. */
                JsonValue value;

                /* Strings are placed immediately after the structure */
                char string[0];

                /* For objects and arrays we store the number of elements and the number of elements that have a
                 * reference counter > 0 here. */
                size_t n_elements;

                /* If is_reference as indicated above is set, this is where the reference object is actually stored. */
                JsonVariant *reference;
        };
};

static bool json_variant_is_magic(const JsonVariant *v) {
        return v == JSON_VARIANT_MAGIC_TRUE ||
                v == JSON_VARIANT_MAGIC_FALSE ||
                v == JSON_VARIANT_MAGIC_NULL ||
                v == JSON_VARIANT_MAGIC_ZERO_INTEGER ||
                v == JSON_VARIANT_MAGIC_ZERO_REAL ||
                v == JSON_VARIANT_MAGIC_EMPTY_STRING ||
                v == JSON_VARIANT_MAGIC_EMPTY_ARRAY ||
                v == JSON_VARIANT_MAGIC_EMPTY_OBJECT;
}

static JsonVariant *json_variant_dereference(JsonVariant *v) {
        if (!v)
                return NULL;

        if (json_variant_is_magic(v))
                return v;

        if (!v->is_reference)
                return v;

        return json_variant_dereference(v->reference);
}

static JsonVariant *json_variant_normalize(JsonVariant *v) {
        if (!v)
                return NULL;

        v = json_variant_dereference(v);

        switch (json_variant_type(v)) {

        case JSON_VARIANT_BOOLEAN:
                return json_variant_boolean(v) ? JSON_VARIANT_MAGIC_TRUE : JSON_VARIANT_MAGIC_FALSE;

        case JSON_VARIANT_NULL:
                return JSON_VARIANT_MAGIC_NULL;

        case JSON_VARIANT_INTEGER:
                return json_variant_integer(v) == 0 ? JSON_VARIANT_MAGIC_ZERO_INTEGER : v;

        case JSON_VARIANT_REAL:
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wfloat-equal"
                return json_variant_real(v) == 0.0 ? JSON_VARIANT_MAGIC_ZERO_REAL : v;
#pragma GCC diagnostic pop

        case JSON_VARIANT_STRING:
                return isempty(json_variant_string(v)) ? JSON_VARIANT_MAGIC_EMPTY_STRING : v;

        case JSON_VARIANT_ARRAY:
                return json_variant_elements(v) == 0 ? JSON_VARIANT_MAGIC_EMPTY_ARRAY : v;

        case JSON_VARIANT_OBJECT:
                return json_variant_elements(v) == 0 ? JSON_VARIANT_MAGIC_EMPTY_OBJECT : v;

        default:
                return v;
        }
}

static int json_variant_new_value(JsonVariant **ret, JsonVariantType type) {
        JsonVariant *v;

        if (!ret)
                return -EINVAL;
        if (!IN_SET(type, JSON_VARIANT_INTEGER, JSON_VARIANT_REAL, JSON_VARIANT_BOOLEAN))
                return -EINVAL;

        v = malloc0(offsetof(JsonVariant, value) + sizeof(JsonValue));
        if (!v)
                return -ENOMEM;

        v->n_ref = 1;
        v->type = type;

        *ret = v;
        return 0;
}

int json_variant_new_integer(JsonVariant **ret, intmax_t i) {
        JsonVariant *v;
        int r;

        if (!ret)
                return -EINVAL;
        if (i == 0) {
                *ret = JSON_VARIANT_MAGIC_ZERO_INTEGER;
                return 0;
        }

        r = json_variant_new_value(&v, JSON_VARIANT_INTEGER);
        if (r < 0)
                return r;

        v->value.integer = i;
        *ret = v;

        return 0;
}

int json_variant_new_real(JsonVariant **ret, long double d) {
        JsonVariant *v;
        int r;

        if (!ret)
                return -EINVAL;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wfloat-equal"
        if (d == 0.0) {
#pragma GCC diagnostic pop
                *ret = JSON_VARIANT_MAGIC_ZERO_REAL;
                return 0;
        }

        r = json_variant_new_value(&v, JSON_VARIANT_REAL);
        if (r < 0)
                return r;

        v->value.real = d;
        *ret = v;

        return 0;
}

int json_variant_new_boolean(JsonVariant **ret, bool b) {
        if (!ret)
                return -EINVAL;

        if (b)
                *ret = JSON_VARIANT_MAGIC_TRUE;
        else
                *ret = JSON_VARIANT_MAGIC_FALSE;

        return 0;
}

int json_variant_new_null(JsonVariant **ret) {
        if (!ret)
                return -EINVAL;

        *ret = JSON_VARIANT_MAGIC_NULL;
        return 0;
}

int json_variant_new_string(JsonVariant **ret, const char *s) {
        JsonVariant *v;

        if (!ret)
                return -EINVAL;
        if (!s)
                return json_variant_new_null(ret);
        if (isempty(s)) {
                *ret = JSON_VARIANT_MAGIC_EMPTY_STRING;
                return 0;
        }

        v = malloc0(offsetof(JsonVariant, string) + strlen(s) + 1);
        if (!v)
                return -ENOMEM;

        v->n_ref = 1;
        v->type = JSON_VARIANT_STRING;

        strcpy(v->string, s);

        *ret = v;
        return 0;
}

static void json_variant_set(JsonVariant *a, JsonVariant *b) {
        assert(a);

        b = json_variant_dereference(b);
        if (!b) {
                a->type = JSON_VARIANT_NULL;
                return;
        }

        a->type = json_variant_type(b);
        switch (a->type) {

        case JSON_VARIANT_INTEGER:
                a->value.integer = json_variant_integer(b);
                break;

        case JSON_VARIANT_REAL:
                a->value.real = json_variant_real(b);
                break;

        case JSON_VARIANT_BOOLEAN:
                a->value.boolean = json_variant_boolean(b);
                break;

        case JSON_VARIANT_STRING:
        case JSON_VARIANT_ARRAY:
        case JSON_VARIANT_OBJECT:
                a->is_reference = true;
                a->reference = json_variant_ref(json_variant_normalize(b));
                break;

        case JSON_VARIANT_NULL:
                break;

        default:
                assert_not_reached("Unexpected variantt type");
        }
}

int json_variant_new_array(JsonVariant **ret, JsonVariant **array, size_t n) {
        JsonVariant *v;
        size_t i;

        if (!ret)
                return -EINVAL;
        if (n == 0) {
                *ret = JSON_VARIANT_MAGIC_EMPTY_ARRAY;
                return 0;
        }
        if (!array)
                return -EINVAL;

        v = new0(JsonVariant, n + 1);
        if (!v)
                return -ENOMEM;

        v->n_ref = 1;
        v->type = JSON_VARIANT_ARRAY;

        v->n_elements = n;

        for (i = 0; i < n; i++) {
                JsonVariant *w = v + 1 + i;

                w->parent = v;
                json_variant_set(w, array[i]);
        }

        *ret = v;
        return 0;
}

int json_variant_new_object(JsonVariant **ret, JsonVariant **array, size_t n) {
        JsonVariant *v;
        size_t i;

        if (!ret)
                return -EINVAL;
        if (n == 0) {
                *ret = JSON_VARIANT_MAGIC_EMPTY_OBJECT;
                return 0;
        }
        if (!array)
                return -EINVAL;
        if (n % 2 != 0)
                return -EINVAL;

        v = new0(JsonVariant, n + 1);
        if (!v)
                return -ENOMEM;

        v->n_ref = 1;
        v->type = JSON_VARIANT_OBJECT;

        v->n_elements = n;

        for (i = 0; i < n; i++) {
                JsonVariant *w = v + 1 + i;

                w->parent = v;
                json_variant_set(w, array[i]);
        }

        *ret = v;
        return 0;
}

static void json_variant_free_inner(JsonVariant *v) {
        assert(v);

        if (json_variant_is_magic(v))
                return;

        if (v->is_reference) {
                json_variant_unref(v->reference);
                return;
        }

        if (IN_SET(v->type, JSON_VARIANT_ARRAY, JSON_VARIANT_OBJECT)) {
                size_t i;

                for (i = 0; i < v->n_elements; i++)
                        json_variant_free_inner(v + 1 + i);
        }
}

JsonVariant *json_variant_ref(JsonVariant *v) {
        if (!v)
                return NULL;
        if (json_variant_is_magic(v))
                return v;

        assert(v->n_ref > 0 || v->parent);
        v->n_ref++;

        json_variant_ref(v->parent);
        return v;
}

JsonVariant *json_variant_unref(JsonVariant *v) {
        if (!v)
                return NULL;
        if (json_variant_is_magic(v))
                return NULL;

        assert(v->n_ref > 0);
        v->n_ref--;

        if (v->parent)
                json_variant_unref(v->parent);
        else if (v->n_ref == 0) {
                json_variant_free_inner(v);
                free(v);
        }

        return NULL;
}

const char *json_variant_string(JsonVariant *v) {
        if (!v)
                return NULL;
        if (v == JSON_VARIANT_MAGIC_EMPTY_STRING)
                return "";
        if (json_variant_is_magic(v))
                return NULL;
        if (v->is_reference)
                return json_variant_string(v->reference);
        if (v->type != JSON_VARIANT_STRING)
                return NULL;

        return v->string;
}

bool json_variant_boolean(JsonVariant *v) {
        if (!v)
                return false;
        if (v == JSON_VARIANT_MAGIC_TRUE)
                return true;
        if (json_variant_is_magic(v))
                return false;
        if (v->type != JSON_VARIANT_BOOLEAN)
                return false;
        if (v->is_reference)
                return json_variant_boolean(v->reference);

        return v->value.boolean;
}

intmax_t json_variant_integer(JsonVariant *v) {
        if (!v)
                return 0;
        if (json_variant_is_magic(v))
                return 0;
        if (v->is_reference)
                return json_variant_integer(v->reference);

        switch (v->type) {

        case JSON_VARIANT_INTEGER:
                return v->value.integer;

        case JSON_VARIANT_REAL: {
                intmax_t converted;

                converted = (intmax_t) v->value.real;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wfloat-equal"
                if ((long double) converted == v->value.real)
#pragma GCC diagnostic pop
                        return converted;

                return 0;
        }

        default:
                return 0;
        }
}

long double json_variant_real(JsonVariant *v) {
        if (!v)
                return 0.0;
        if (json_variant_is_magic(v))
                return 0.0;
        if (v->is_reference)
                return json_variant_real(v->reference);

        switch (v->type) {

        case JSON_VARIANT_REAL:
                return v->value.real;

        case JSON_VARIANT_INTEGER: {
                long double converted;

                converted = (long double) v->value.integer;

                if ((intmax_t) converted == v->value.integer)
                        return converted;

                return 0.0;
        }

        default:
                return 0.0;
        }
}

JsonVariantType json_variant_type(JsonVariant *v) {

        if (!v)
                return _JSON_VARIANT_INVALID;

        if (v == JSON_VARIANT_MAGIC_TRUE || v == JSON_VARIANT_MAGIC_FALSE)
                return JSON_VARIANT_BOOLEAN;

        if (v == JSON_VARIANT_MAGIC_NULL)
                return JSON_VARIANT_NULL;

        if (v == JSON_VARIANT_MAGIC_ZERO_INTEGER)
                return JSON_VARIANT_INTEGER;

        if (v == JSON_VARIANT_MAGIC_ZERO_REAL)
                return JSON_VARIANT_REAL;

        if (v == JSON_VARIANT_MAGIC_EMPTY_STRING)
                return JSON_VARIANT_STRING;

        if (v == JSON_VARIANT_MAGIC_EMPTY_ARRAY)
                return JSON_VARIANT_ARRAY;

        if (v == JSON_VARIANT_MAGIC_EMPTY_OBJECT)
                return JSON_VARIANT_OBJECT;

        return v->type;
}

bool json_variant_has_type(JsonVariant *v, JsonVariantType type) {
        JsonVariantType rt;

        v = json_variant_dereference(v);

        rt = json_variant_type(v);
        if (rt == type)
                return true;

        /* Both magic zeroes qualify as both integer and as real */
        if ((v == JSON_VARIANT_MAGIC_ZERO_INTEGER || v == JSON_VARIANT_MAGIC_ZERO_REAL) &&
            IN_SET(type, JSON_VARIANT_INTEGER, JSON_VARIANT_REAL))
                return true;

        /* Any integer that can be converted lossley to a real and back may also be consdiered a real */
        if (rt == JSON_VARIANT_INTEGER && type == JSON_VARIANT_REAL) {
                intmax_t i;

                i = json_variant_integer(v);

                return (intmax_t) (long double) i == i;
        }

        /* Any real that can be converted losslessly to an integer and back may also be considered an integer */
        if (rt == JSON_VARIANT_REAL && type == JSON_VARIANT_INTEGER) {
                long double d;

                d = json_variant_real(v);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wfloat-equal"
                return (long double) (intmax_t) d == d;
#pragma GCC diagnostic pop
        }

        return false;
}

size_t json_variant_elements(JsonVariant *v) {
        if (!v)
                return 0;
        if (json_variant_is_magic(v))
                return 0;
        if (!IN_SET(v->type, JSON_VARIANT_ARRAY, JSON_VARIANT_OBJECT))
                return 0;
        if (v->is_reference)
                return json_variant_elements(v->reference);

        return v->n_elements;
}

JsonVariant *json_variant_by_index(JsonVariant *v, size_t idx) {
        if (!v)
                return NULL;
        if (json_variant_is_magic(v))
                return NULL;
        if (!IN_SET(v->type, JSON_VARIANT_ARRAY, JSON_VARIANT_OBJECT))
                return NULL;
        if (v->is_reference)
                return json_variant_by_index(v->reference, idx);
        if (idx >= v->n_elements)
                return NULL;

        return json_variant_normalize(v + 1 + idx);
}

JsonVariant *json_variant_by_key(JsonVariant *v, const char *key) {
        size_t i;

        if (!v)
                return NULL;
        if (!key)
                return NULL;
        if (json_variant_is_magic(v))
                return NULL;
        if (v->type != JSON_VARIANT_OBJECT)
                return NULL;
        if (v->is_reference)
                return json_variant_by_key(v->reference, key);

        for (i = 0; i < v->n_elements; i += 2) {
                JsonVariant *p;

                p = json_variant_dereference(v + 1 + i);

                if (!json_variant_has_type(p, JSON_VARIANT_STRING))
                        continue;

                if (streq(json_variant_string(p), key))
                        return json_variant_normalize(v + 1 + i + 1);
        }

        return NULL;
}

bool json_variant_equal(JsonVariant *a, JsonVariant *b) {
        JsonVariantType t;

        a = json_variant_normalize(a);
        b = json_variant_normalize(b);

        if (a == b)
                return true;

        t = json_variant_type(a);
        if (!json_variant_has_type(b, t))
                return false;

        switch (t) {

        case JSON_VARIANT_STRING:
                return streq(json_variant_string(a), json_variant_string(b));

        case JSON_VARIANT_INTEGER:
                return json_variant_integer(a) == json_variant_integer(b);

        case JSON_VARIANT_REAL:
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wfloat-equal"
                return json_variant_real(a) == json_variant_real(b);
#pragma GCC diagnostic pop

        case JSON_VARIANT_BOOLEAN:
                return json_variant_boolean(a) == json_variant_boolean(b);

        case JSON_VARIANT_NULL:
                return true;

        case JSON_VARIANT_ARRAY: {
                size_t i, n;

                n = json_variant_elements(a);
                if (n != json_variant_elements(b))
                        return false;

                for (i = 0; i < n; i++) {
                        if (!json_variant_equal(json_variant_by_index(a, i), json_variant_by_index(b, i)))
                                return false;
                }

                return true;
        }

        case JSON_VARIANT_OBJECT: {
                size_t i, n;

                n = json_variant_elements(a);
                if (n != json_variant_elements(b))
                        return false;

                /* Iterate through all keys in 'a' */
                for (i = 0; i < n; i += 2) {
                        bool found = false;
                        size_t j;

                        /* Match them against all keys in 'b' */
                        for (j = 0; j < n; j += 2) {
                                JsonVariant *key_b;

                                key_b = json_variant_by_index(b, j);

                                /* During the first iteration unmark everything */
                                if (i == 0)
                                        key_b->marked = false;
                                else if (key_b->marked) /* In later iterations if we already marked something, don't bother with it again */
                                        continue;

                                if (found)
                                        continue;

                                if (json_variant_equal(json_variant_by_index(a, i), key_b) &&
                                    json_variant_equal(json_variant_by_index(a, i+1), json_variant_by_index(b, j+1))) {
                                        /* Key and values match! */
                                        key_b->marked = found = true;

                                        /* In the first iteration we continue the inner loop since we want to mark
                                         * everything, otherwise exit the loop quickly after we found what we were
                                         * looking for. */
                                        if (i != 0)
                                                break;
                                }
                        }

                        if (!found)
                                return false;
                }

                return true;
        }

        default:
                assert_not_reached("Unknown variant type.");
        }
}

static int json_format(FILE *f, JsonVariant *v, unsigned flags, const char *prefix) {
        int r;

        assert(f);
        assert(v);

        switch (json_variant_type(v)) {

        case JSON_VARIANT_REAL: {
                locale_t loc;

                loc = newlocale(LC_NUMERIC_MASK, "C", (locale_t) 0);
                if (loc == (locale_t) 0)
                        return -errno;

                if (flags & JSON_FORMAT_COLOR)
                        fputs(ANSI_HIGHLIGHT_BLUE, f);

                fprintf(f, "%.*Le", DECIMAL_DIG, json_variant_real(v));

                if (flags & JSON_FORMAT_COLOR)
                        fputs(ANSI_NORMAL, f);

                freelocale(loc);
                break;
        }

        case JSON_VARIANT_INTEGER:
                if (flags & JSON_FORMAT_COLOR)
                        fputs(ANSI_HIGHLIGHT_BLUE, f);

                fprintf(f, "%" PRIdMAX, json_variant_integer(v));

                if (flags & JSON_FORMAT_COLOR)
                        fputs(ANSI_NORMAL, f);
                break;

        case JSON_VARIANT_BOOLEAN:

                if (flags & JSON_FORMAT_COLOR)
                        fputs(ANSI_HIGHLIGHT, f);

                if (json_variant_boolean(v))
                        fputs("true", f);
                else
                        fputs("false", f);

                if (flags & JSON_FORMAT_COLOR)
                        fputs(ANSI_NORMAL, f);

                break;

        case JSON_VARIANT_NULL:
                if (flags & JSON_FORMAT_COLOR)
                        fputs(ANSI_HIGHLIGHT, f);

                fputs("null", f);

                if (flags & JSON_FORMAT_COLOR)
                        fputs(ANSI_NORMAL, f);
                break;

        case JSON_VARIANT_STRING: {
                const char *q;

                fputc('"', f);

                if (flags & JSON_FORMAT_COLOR)
                        fputs(ANSI_GREEN, f);

                for (q = json_variant_string(v); *q; q++) {

                        switch (*q) {

                        case '"':
                                fputs("\\\"", f);
                                break;

                        case '\\':
                                fputs("\\\\", f);
                                break;

                        case '/':
                                fputs("\\/", f);
                                break;

                        case '\b':
                                fputs("\\b", f);
                                break;

                        case '\f':
                                fputs("\\f", f);
                                break;

                        case '\n':
                                fputs("\\n", f);
                                break;

                        case '\r':
                                fputs("\\r", f);
                                break;

                        case '\t':
                                fputs("\\t", f);
                                break;

                        default:
                                if (*q >= 0 && *q < ' ')
                                        fprintf(f, "\\u%04x", *q);
                                else
                                        fputc(*q, f);
                                break;
                        }
                }

                if (flags & JSON_FORMAT_COLOR)
                        fputs(ANSI_NORMAL, f);

                fputc('"', f);
                break;
        }

        case JSON_VARIANT_ARRAY: {
                size_t i, n;

                n = json_variant_elements(v);

                if (n == 0)
                        fputs("[]", f);
                else {
                        const char *prefix2;

                        if (flags & JSON_FORMAT_PRETTY) {
                                prefix2 = strjoina(strempty(prefix), "\t");
                                fputs("[\n", f);
                                fputs(prefix2, f);
                        } else {
                                prefix2 = strna(prefix);
                                fputc('[', f);
                        }

                        for (i = 0; i < n; i++) {
                                if (i > 0) {
                                        if (flags & JSON_FORMAT_PRETTY) {
                                                fputs(",\n", f);
                                                fputs(prefix2, f);
                                        } else
                                                fputc(',', f);
                                }

                                r = json_format(f, json_variant_by_index(v, i), flags, prefix2);
                                if (r < 0)
                                        return r;
                        }

                        if (flags & JSON_FORMAT_PRETTY) {
                                fputc('\n', f);
                                fputs(strempty(prefix), f);
                        }

                        fputc(']', f);
                }
                break;
        }

        case JSON_VARIANT_OBJECT: {
                size_t i, n;

                n = json_variant_elements(v);

                if (n == 0)
                        fputs("{}", f);
                else {
                        const char *prefix2;

                        if (flags & JSON_FORMAT_PRETTY) {
                                prefix2 = strjoina(strempty(prefix), "\t");
                                fputs("{\n", f);
                                fputs(prefix2, f);
                        } else {
                                prefix2 = strna(prefix);
                                fputc('{', f);
                        }

                        for (i = 0; i < n; i += 2) {

                                if (i > 0) {
                                        if (flags & JSON_FORMAT_PRETTY) {
                                                fputs(",\n", f);
                                                fputs(prefix2, f);
                                        } else
                                                fputc(',', f);
                                }

                                r = json_format(f, json_variant_by_index(v, i), flags, prefix2);
                                if (r < 0)
                                        return r;

                                fputs(flags & JSON_FORMAT_PRETTY ? " : " : ":", f);

                                r = json_format(f, json_variant_by_index(v, i+1), flags, prefix2);
                                if (r < 0)
                                        return r;
                        }

                        if (flags & JSON_FORMAT_PRETTY) {
                                fputc('\n', f);
                                fputs(strempty(prefix), f);
                        }

                        fputc('}', f);
                }
                break;
        }

        default:
                assert_not_reached("Unexpected variant type.");
        }

        return 0;
}

int json_variant_format(JsonVariant *v, unsigned flags, char **ret) {
        size_t sz;
        char *s;
        FILE *f;
        int r;

        if (!v)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        f = open_memstream(&s, &sz);
        if (!f)
                return -ENOMEM;

        (void) __fsetlocking(f, FSETLOCKING_BYCALLER);

        json_format(f, v, flags, NULL);

        if (flags & JSON_FORMAT_PRETTY)
                fputc('\n', f);

        r = fflush_and_check(f);
        if (r < 0)
                return r;

        fclose(f);
        *ret = s;

        return (int) sz;
}

void json_variant_dump(JsonVariant *v, unsigned flags, FILE *f, const char *prefix) {
        if (!v)
                return;

        if (!f)
                f = stdout;

        json_format(f, v, flags, prefix);
}

static void inc_lines(unsigned *line, const char *s, size_t n) {
        const char *p = s;

        if (!line)
                return;

        for (;;) {
                const char *f;

                f = memchr(p, '\n', n);
                if (!f)
                        return;

                n -= (f - p) + 1;
                p = f + 1;
                (*line)++;
        }
}

static int unhex_ucs2(const char *c, uint16_t *ret) {
        int aa, bb, cc, dd;
        uint16_t x;

        assert(c);
        assert(ret);

        aa = unhexchar(c[0]);
        if (aa < 0)
                return -EINVAL;

        bb = unhexchar(c[1]);
        if (bb < 0)
                return -EINVAL;

        cc = unhexchar(c[2]);
        if (cc < 0)
                return -EINVAL;

        dd = unhexchar(c[3]);
        if (dd < 0)
                return -EINVAL;

        x =     ((uint16_t) aa << 12) |
                ((uint16_t) bb << 8) |
                ((uint16_t) cc << 4) |
                ((uint16_t) dd);

        if (x <= 0)
                return -EINVAL;

        *ret = x;

        return 0;
}

static int json_parse_string(const char **p, char **ret) {
        _cleanup_free_ char *s = NULL;
        size_t n = 0, allocated = 0;
        const char *c;

        assert(p);
        assert(*p);
        assert(ret);

        c = *p;

        if (*c != '"')
                return -EINVAL;

        c++;

        for (;;) {
                int len;

                /* Check for EOF */
                if (*c == 0)
                        return -EINVAL;

                /* Check for control characters 0x00..0x1f */
                if (*c > 0 && *c < ' ')
                        return -EINVAL;

                /* Check for control character 0x7f */
                if (*c == 0x7f)
                        return -EINVAL;

                if (*c == '"') {
                        if (!s) {
                                s = strdup("");
                                if (!s)
                                        return -ENOMEM;
                        } else
                                s[n] = 0;

                        *p = c + 1;

                        *ret = s;
                        s = NULL;
                        return JSON_TOKEN_STRING;
                }

                if (*c == '\\') {
                        char ch = 0;
                        c++;

                        if (*c == 0)
                                return -EINVAL;

                        if (IN_SET(*c, '"', '\\', '/'))
                                ch = *c;
                        else if (*c == 'b')
                                ch = '\b';
                        else if (*c == 'f')
                                ch = '\f';
                        else if (*c == 'n')
                                ch = '\n';
                        else if (*c == 'r')
                                ch = '\r';
                        else if (*c == 't')
                                ch = '\t';
                        else if (*c == 'u') {
                                char16_t x;
                                int r;

                                r = unhex_ucs2(c + 1, &x);
                                if (r < 0)
                                        return r;

                                c += 5;

                                if (!GREEDY_REALLOC(s, allocated, n + 4))
                                        return -ENOMEM;

                                if (!utf16_is_surrogate(x))
                                        n += utf8_encode_unichar(s + n, (char32_t) x);
                                else if (utf16_is_trailing_surrogate(x))
                                        return -EINVAL;
                                else {
                                        char16_t y;

                                        if (c[0] != '\\' || c[1] != 'u')
                                                return -EINVAL;

                                        r = unhex_ucs2(c + 2, &y);
                                        if (r < 0)
                                                return r;

                                        c += 6;

                                        if (!utf16_is_trailing_surrogate(y))
                                                return -EINVAL;

                                        n += utf8_encode_unichar(s + n, utf16_surrogate_pair_to_unichar(x, y));
                                }

                                continue;
                        } else
                                return -EINVAL;

                        if (!GREEDY_REALLOC(s, allocated, n + 2))
                                return -ENOMEM;

                        s[n++] = ch;
                        c ++;
                        continue;
                }

                len = utf8_encoded_valid_unichar(c);
                if (len < 0)
                        return len;

                if (!GREEDY_REALLOC(s, allocated, n + len + 1))
                        return -ENOMEM;

                memcpy(s + n, c, len);
                n += len;
                c += len;
        }
}

static int json_parse_number(const char **p, JsonValue *ret) {
        bool negative = false, exponent_negative = false, is_real = false;
        long double x = 0.0, y = 0.0, exponent = 0.0, shift = 1.0;
        intmax_t i = 0;
        const char *c;

        assert(p);
        assert(*p);
        assert(ret);

        c = *p;

        if (*c == '-') {
                negative = true;
                c++;
        }

        if (*c == '0')
                c++;
        else {
                if (!strchr("123456789", *c) || *c == 0)
                        return -EINVAL;

                do {
                        if (!is_real) {
                                intmax_t t;

                                t = 10 * i + (*c - '0');
                                if (t / 10 != i) /* overflow */
                                        is_real = true;
                                else
                                        i = t;
                        }

                        x = 10.0 * x + (*c - '0');
                        c++;
                } while (strchr("0123456789", *c) && *c != 0);
        }

        if (*c == '.') {
                is_real = true;
                c++;

                if (!strchr("0123456789", *c) || *c == 0)
                        return -EINVAL;

                do {
                        y = 10.0 * y + (*c - '0');
                        shift = 10.0 * shift;
                        c++;
                } while (strchr("0123456789", *c) && *c != 0);
        }

        if (*c == 'e' || *c == 'E') {
                is_real = true;
                c++;

                if (*c == '-') {
                        exponent_negative = true;
                        c++;
                } else if (*c == '+')
                        c++;

                if (!strchr("0123456789", *c) || *c == 0)
                        return -EINVAL;

                do {
                        exponent = 10.0 * exponent + (*c - '0');
                        c++;
                } while (strchr("0123456789", *c) && *c != 0);
        }

        *p = c;

        if (is_real) {
                ret->real = ((negative ? -1.0 : 1.0) * (x + (y / shift))) * exp10l((exponent_negative ? -1.0 : 1.0) * exponent);
                return JSON_TOKEN_REAL;
        } else {
                ret->integer = negative ? -i : i;
                return JSON_TOKEN_INTEGER;
        }
}

int json_tokenize(
                const char **p,
                char **ret_string,
                JsonValue *ret_value,
                void **state,
                unsigned *line) {

        const char *c;
        int t, r;

        enum {
                STATE_NULL,
                STATE_VALUE,
                STATE_VALUE_POST,
        };

        assert(p);
        assert(*p);
        assert(ret_string);
        assert(ret_value);
        assert(state);

        t = PTR_TO_INT(*state);
        c = *p;

        if (t == STATE_NULL) {
                if (line)
                        *line = 1;
                t = STATE_VALUE;
        }

        for (;;) {
                const char *b;

                b = c + strspn(c, WHITESPACE);
                if (*b == 0)
                        return JSON_TOKEN_END;

                inc_lines(line, c, b - c);
                c = b;

                switch (t) {

                case STATE_VALUE:

                        if (*c == '{') {
                                *ret_string = NULL;
                                *ret_value = JSON_VALUE_NULL;
                                *p = c + 1;
                                *state = INT_TO_PTR(STATE_VALUE);
                                return JSON_TOKEN_OBJECT_OPEN;

                        } else if (*c == '}') {
                                *ret_string = NULL;
                                *ret_value = JSON_VALUE_NULL;
                                *p = c + 1;
                                *state = INT_TO_PTR(STATE_VALUE_POST);
                                return JSON_TOKEN_OBJECT_CLOSE;

                        } else if (*c == '[') {
                                *ret_string = NULL;
                                *ret_value = JSON_VALUE_NULL;
                                *p = c + 1;
                                *state = INT_TO_PTR(STATE_VALUE);
                                return JSON_TOKEN_ARRAY_OPEN;

                        } else if (*c == ']') {
                                *ret_string = NULL;
                                *ret_value = JSON_VALUE_NULL;
                                *p = c + 1;
                                *state = INT_TO_PTR(STATE_VALUE_POST);
                                return JSON_TOKEN_ARRAY_CLOSE;

                        } else if (*c == '"') {
                                r = json_parse_string(&c, ret_string);
                                if (r < 0)
                                        return r;

                                *ret_value = JSON_VALUE_NULL;
                                *p = c;
                                *state = INT_TO_PTR(STATE_VALUE_POST);
                                return r;

                        } else if (strchr("-0123456789", *c)) {
                                r = json_parse_number(&c, ret_value);
                                if (r < 0)
                                        return r;

                                *ret_string = NULL;
                                *p = c;
                                *state = INT_TO_PTR(STATE_VALUE_POST);
                                return r;

                        } else if (startswith(c, "true")) {
                                *ret_string = NULL;
                                ret_value->boolean = true;
                                *p = c + 4;
                                *state = INT_TO_PTR(STATE_VALUE_POST);
                                return JSON_TOKEN_BOOLEAN;

                        } else if (startswith(c, "false")) {
                                *ret_string = NULL;
                                ret_value->boolean = false;
                                *p = c + 5;
                                *state = INT_TO_PTR(STATE_VALUE_POST);
                                return JSON_TOKEN_BOOLEAN;

                        } else if (startswith(c, "null")) {
                                *ret_string = NULL;
                                *ret_value = JSON_VALUE_NULL;
                                *p = c + 4;
                                *state = INT_TO_PTR(STATE_VALUE_POST);
                                return JSON_TOKEN_NULL;

                        } else
                                return -EINVAL;

                case STATE_VALUE_POST:

                        if (*c == ':') {
                                *ret_string = NULL;
                                *ret_value = JSON_VALUE_NULL;
                                *p = c + 1;
                                *state = INT_TO_PTR(STATE_VALUE);
                                return JSON_TOKEN_COLON;
                        } else if (*c == ',') {
                                *ret_string = NULL;
                                *ret_value = JSON_VALUE_NULL;
                                *p = c + 1;
                                *state = INT_TO_PTR(STATE_VALUE);
                                return JSON_TOKEN_COMMA;
                        } else if (*c == '}') {
                                *ret_string = NULL;
                                *ret_value = JSON_VALUE_NULL;
                                *p = c + 1;
                                *state = INT_TO_PTR(STATE_VALUE_POST);
                                return JSON_TOKEN_OBJECT_CLOSE;
                        } else if (*c == ']') {
                                *ret_string = NULL;
                                *ret_value = JSON_VALUE_NULL;
                                *p = c + 1;
                                *state = INT_TO_PTR(STATE_VALUE_POST);
                                return JSON_TOKEN_ARRAY_CLOSE;
                        } else
                                return -EINVAL;
                }

        }
}

typedef enum JsonExpect {
        /* The following values are used by json_parse() */
        EXPECT_TOPLEVEL,
        EXPECT_END,
        EXPECT_OBJECT_FIRST_KEY,
        EXPECT_OBJECT_NEXT_KEY,
        EXPECT_OBJECT_COLON,
        EXPECT_OBJECT_VALUE,
        EXPECT_OBJECT_COMMA,
        EXPECT_ARRAY_FIRST_ELEMENT,
        EXPECT_ARRAY_NEXT_ELEMENT,
        EXPECT_ARRAY_COMMA,

        /* And these are used by json_build() */
        EXPECT_ARRAY_ELEMENT,
        EXPECT_OBJECT_KEY,
} JsonExpect;

typedef struct JsonStack {
        JsonExpect expect;
        JsonVariant **elements;
        size_t n_elements, n_elements_allocated;
} JsonStack;

static void json_stack_release(JsonStack *s) {
        size_t i;

        for (i = 0; i < s->n_elements; i++)
                json_variant_unref(s->elements[i]);

        free(s->elements);
}

static int json_parse_internal(const char **input, JsonVariant **ret, unsigned *ret_line, bool continue_end) {

        void *tokenizer_state = NULL;
        JsonStack *stack = NULL;
        size_t n_stack = 1, n_stack_allocated = 0, i;
        const char *p;
        int r;

        if (!input)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        p = *input;

        if (!GREEDY_REALLOC(stack, n_stack_allocated, n_stack))
                return -ENOMEM;

        stack[0] = (JsonStack) {
                .expect = EXPECT_TOPLEVEL,
        };

        for (;;) {
                _cleanup_free_ char *string = NULL;
                JsonStack *current;
                JsonValue value;
                JsonVariant *add = NULL;
                int token;

                assert(n_stack > 0);
                current = stack + n_stack - 1;

                if (continue_end && current->expect == EXPECT_END)
                        goto done;

                token = json_tokenize(&p, &string, &value, &tokenizer_state, ret_line);
                if (token < 0) {
                        r = token;
                        goto finish;
                }

                switch (token) {

                case JSON_TOKEN_END:
                        if (current->expect != EXPECT_END) {
                                r = -EINVAL;
                                goto finish;
                        }

                        assert(current->n_elements == 1);
                        assert(n_stack == 1);
                        goto done;

                case JSON_TOKEN_COLON:

                        if (current->expect != EXPECT_OBJECT_COLON) {
                                r = -EINVAL;
                                goto finish;
                        }

                        current->expect = EXPECT_OBJECT_VALUE;
                        break;

                case JSON_TOKEN_COMMA:

                        if (current->expect == EXPECT_OBJECT_COMMA)
                                current->expect = EXPECT_OBJECT_NEXT_KEY;
                        else if (current->expect == EXPECT_ARRAY_COMMA)
                                current->expect = EXPECT_ARRAY_NEXT_ELEMENT;
                        else {
                                r = -EINVAL;
                                goto finish;
                        }

                        break;

                case JSON_TOKEN_OBJECT_OPEN:

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_FIRST_ELEMENT, EXPECT_ARRAY_NEXT_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        if (!GREEDY_REALLOC(stack, n_stack_allocated, n_stack+1)) {
                                r = -ENOMEM;
                                goto finish;
                        }
                        current = stack + n_stack - 1;

                        /* Prepare the expect for when we return from the child */
                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_COMMA;
                        else {
                                assert(IN_SET(current->expect, EXPECT_ARRAY_FIRST_ELEMENT, EXPECT_ARRAY_NEXT_ELEMENT));
                                current->expect = EXPECT_ARRAY_COMMA;
                        }

                        stack[n_stack++] = (JsonStack) {
                                .expect = EXPECT_OBJECT_FIRST_KEY,
                        };

                        current = stack + n_stack - 1;
                        break;

                case JSON_TOKEN_OBJECT_CLOSE:
                        if (!IN_SET(current->expect, EXPECT_OBJECT_FIRST_KEY, EXPECT_OBJECT_COMMA)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        assert(n_stack > 1);

                        r = json_variant_new_object(&add, current->elements, current->n_elements);
                        if (r < 0)
                                goto finish;

                        json_stack_release(current);
                        n_stack--, current--;

                        break;

                case JSON_TOKEN_ARRAY_OPEN:
                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_FIRST_ELEMENT, EXPECT_ARRAY_NEXT_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        if (!GREEDY_REALLOC(stack, n_stack_allocated, n_stack+1)) {
                                r = -ENOMEM;
                                goto finish;
                        }
                        current = stack + n_stack - 1;

                        /* Prepare the expect for when we return from the child */
                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_COMMA;
                        else {
                                assert(IN_SET(current->expect, EXPECT_ARRAY_FIRST_ELEMENT, EXPECT_ARRAY_NEXT_ELEMENT));
                                current->expect = EXPECT_ARRAY_COMMA;
                        }

                        stack[n_stack++] = (JsonStack) {
                                .expect = EXPECT_ARRAY_FIRST_ELEMENT,
                        };

                        break;

                case JSON_TOKEN_ARRAY_CLOSE:
                        if (!IN_SET(current->expect, EXPECT_ARRAY_FIRST_ELEMENT, EXPECT_ARRAY_COMMA)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        assert(n_stack > 1);

                        r = json_variant_new_array(&add, current->elements, current->n_elements);
                        if (r < 0)
                                goto finish;

                        json_stack_release(current);
                        n_stack--, current--;
                        break;

                case JSON_TOKEN_STRING:
                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_FIRST_KEY, EXPECT_OBJECT_NEXT_KEY, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_FIRST_ELEMENT, EXPECT_ARRAY_NEXT_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        r = json_variant_new_string(&add, string);
                        if (r < 0)
                                goto finish;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (IN_SET(current->expect, EXPECT_OBJECT_FIRST_KEY, EXPECT_OBJECT_NEXT_KEY))
                                current->expect = EXPECT_OBJECT_COLON;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_COMMA;
                        else {
                                assert(IN_SET(current->expect, EXPECT_ARRAY_FIRST_ELEMENT, EXPECT_ARRAY_NEXT_ELEMENT));
                                current->expect = EXPECT_ARRAY_COMMA;
                        }

                        break;

                case JSON_TOKEN_REAL:
                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_FIRST_ELEMENT, EXPECT_ARRAY_NEXT_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        r = json_variant_new_real(&add, value.real);
                        if (r < 0)
                                goto finish;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_COMMA;
                        else {
                                assert(IN_SET(current->expect, EXPECT_ARRAY_FIRST_ELEMENT, EXPECT_ARRAY_NEXT_ELEMENT));
                                current->expect = EXPECT_ARRAY_COMMA;
                        }

                        break;

                case JSON_TOKEN_INTEGER:
                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_FIRST_ELEMENT, EXPECT_ARRAY_NEXT_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        r = json_variant_new_integer(&add, value.integer);
                        if (r < 0)
                                goto finish;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_COMMA;
                        else {
                                assert(IN_SET(current->expect, EXPECT_ARRAY_FIRST_ELEMENT, EXPECT_ARRAY_NEXT_ELEMENT));
                                current->expect = EXPECT_ARRAY_COMMA;
                        }

                        break;

                case JSON_TOKEN_BOOLEAN:
                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_FIRST_ELEMENT, EXPECT_ARRAY_NEXT_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        r = json_variant_new_boolean(&add, value.boolean);
                        if (r < 0)
                                goto finish;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_COMMA;
                        else {
                                assert(IN_SET(current->expect, EXPECT_ARRAY_FIRST_ELEMENT, EXPECT_ARRAY_NEXT_ELEMENT));
                                current->expect = EXPECT_ARRAY_COMMA;
                        }

                        break;

                case JSON_TOKEN_NULL:
                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_FIRST_ELEMENT, EXPECT_ARRAY_NEXT_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        r = json_variant_new_null(&add);
                        if (r < 0)
                                goto finish;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_COMMA;
                        else {
                                assert(IN_SET(current->expect, EXPECT_ARRAY_FIRST_ELEMENT, EXPECT_ARRAY_NEXT_ELEMENT));
                                current->expect = EXPECT_ARRAY_COMMA;
                        }

                        break;

                default:
                        assert_not_reached("Unexpected token");
                }

                if (add) {
                        if (!GREEDY_REALLOC(current->elements, current->n_elements_allocated, current->n_elements + 1)) {
                                r = -ENOMEM;
                                goto finish;
                        }

                        current->elements[current->n_elements++] = add;
                }
        }

done:
        assert(n_stack == 1);
        assert(stack[0].n_elements == 1);

        *ret = json_variant_ref(stack[0].elements[0]);
        *input = p;
        r = 0;

finish:
        for (i = 0; i < n_stack; i++)
                json_stack_release(stack + i);

        free(stack);

        return r;
}

int json_parse(const char *input, JsonVariant **ret, unsigned *ret_line) {
        return json_parse_internal(&input, ret, ret_line, false);
}

int json_parse_continue(const char **p, JsonVariant **ret, unsigned *ret_line) {
        return json_parse_internal(p, ret, ret_line, true);
}

int json_build_internal(JsonVariant **ret, ...) {
        JsonStack *stack = NULL;
        size_t n_stack = 1, n_stack_allocated = 0, i;
        va_list ap;
        int r;

        if (!ret)
                return -EINVAL;

        if (!GREEDY_REALLOC(stack, n_stack_allocated, n_stack))
                return -ENOMEM;

        stack[0] = (JsonStack) {
                .expect = EXPECT_TOPLEVEL,
        };

        va_start(ap, ret);

        for (;;) {
                JsonVariant *add = NULL;
                JsonStack *current;
                int command;

                assert(n_stack > 0);
                current = stack + n_stack - 1;

                command = va_arg(ap, int);

                switch (command) {

                case _JSON_BUILD_STRING: {
                        const char *p;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        p = va_arg(ap, const char *);

                        r = json_variant_new_string(&add, p);
                        if (r < 0)
                                goto finish;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;
                }

                case _JSON_BUILD_INTEGER: {
                        intmax_t j;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        j = va_arg(ap, intmax_t);

                        r = json_variant_new_integer(&add, j);
                        if (r < 0)
                                goto finish;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;
                }

                case _JSON_BUILD_REAL: {
                        long double d;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        d = va_arg(ap, long double);

                        r = json_variant_new_real(&add, d);
                        if (r < 0)
                                goto finish;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;
                }

                case _JSON_BUILD_BOOLEAN: {
                        bool b;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        b = va_arg(ap, int);

                        r = json_variant_new_boolean(&add, b);
                        if (r < 0)
                                goto finish;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;
                }

                case _JSON_BUILD_NULL:

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        r = json_variant_new_null(&add);
                        if (r < 0)
                                goto finish;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;

                case _JSON_BUILD_VARIANT:

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        add = va_arg(ap, JsonVariant*);
                        if (!add)
                                add = JSON_VARIANT_MAGIC_NULL;
                        else
                                json_variant_ref(add);

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;

                case _JSON_BUILD_LITERAL: {
                        const char *l;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        l = va_arg(ap, const char *);

                        if (!l)
                                add = JSON_VARIANT_MAGIC_NULL;
                        else {
                                r = json_parse(l, &add, NULL);
                                if (r < 0)
                                        goto finish;
                        }

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;
                }

                case _JSON_BUILD_ARRAY_BEGIN:

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        if (!GREEDY_REALLOC(stack, n_stack_allocated, n_stack+1)) {
                                r = -ENOMEM;
                                goto finish;
                        }
                        current = stack + n_stack - 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        stack[n_stack++] = (JsonStack) {
                                .expect = EXPECT_ARRAY_ELEMENT,
                        };

                        break;

                case _JSON_BUILD_ARRAY_END:
                        if (current->expect != EXPECT_ARRAY_ELEMENT) {
                                r = -EINVAL;
                                goto finish;
                        }

                        assert(n_stack > 1);

                        r = json_variant_new_array(&add, current->elements, current->n_elements);
                        if (r < 0)
                                goto finish;

                        json_stack_release(current);
                        n_stack--, current--;

                        break;

                case _JSON_BUILD_OBJECT_BEGIN:

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        if (!GREEDY_REALLOC(stack, n_stack_allocated, n_stack+1)) {
                                r = -ENOMEM;
                                goto finish;
                        }
                        current = stack + n_stack - 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        stack[n_stack++] = (JsonStack) {
                                .expect = EXPECT_OBJECT_KEY,
                        };

                        break;

                case _JSON_BUILD_OBJECT_END:

                        if (current->expect != EXPECT_OBJECT_KEY) {
                                r = -EINVAL;
                                goto finish;
                        }

                        assert(n_stack > 1);

                        r = json_variant_new_object(&add, current->elements, current->n_elements);
                        if (r < 0)
                                goto finish;

                        json_stack_release(current);
                        n_stack--, current--;

                        break;

                case _JSON_BUILD_PAIR: {
                        const char *n;

                        if (current->expect != EXPECT_OBJECT_KEY) {
                                r = -EINVAL;
                                goto finish;
                        }

                        n = va_arg(ap, const char *);

                        r = json_variant_new_string(&add, n);
                        if (r < 0)
                                goto finish;

                        current->expect = EXPECT_OBJECT_VALUE;
                        break;
                }

                case _JSON_BUILD_END:
                        if (current->expect != EXPECT_END) {
                                r = -EINVAL;
                                goto finish;
                        }

                        assert(current->n_elements == 1);
                        assert(n_stack == 1);
                        goto done;
                }

                if (add) {
                        if (!GREEDY_REALLOC(current->elements, current->n_elements_allocated, current->n_elements + 1)) {
                                r = -ENOMEM;
                                goto finish;
                        }

                        current->elements[current->n_elements++] = add;
                }
        }

done:
        assert(n_stack == 1);
        assert(stack[0].n_elements == 1);

        *ret = json_variant_ref(stack[0].elements[0]);
        r = 0;

finish:
        for (i = 0; i < n_stack; i++)
                json_stack_release(stack + i);

        free(stack);

        va_end(ap);

        return r;
}
