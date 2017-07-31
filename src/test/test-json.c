/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

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

#include <math.h>

#include "alloc-util.h"
#include "json.h"
#include "string-util.h"
#include "util.h"

static void test_tokenizer(const char *data, ...) {
        void *state = NULL;
        va_list ap;

        va_start(ap, data);

        for (;;) {
                _cleanup_free_ char *str = NULL;
                JsonValue v = JSON_VALUE_NULL;
                int t, tt;

                t = json_tokenize(&data, &str, &v, &state, NULL);
                tt = va_arg(ap, int);

                assert_se(t == tt);

                if (t == JSON_TOKEN_END || t < 0)
                        break;

                else if (t == JSON_TOKEN_STRING) {
                        const char *nn;

                        nn = va_arg(ap, const char *);
                        assert_se(streq_ptr(nn, str));

                } else if (t == JSON_TOKEN_REAL) {
                        double d;

                        d = va_arg(ap, double);
                        assert_se(fabs(d - v.real) < 0.001);

                } else if (t == JSON_TOKEN_INTEGER) {
                        intmax_t i;

                        i = va_arg(ap, intmax_t);
                        assert_se(i == v.integer);

                } else if (t == JSON_TOKEN_BOOLEAN) {
                        bool b;

                        b = va_arg(ap, int);
                        assert_se(b == v.boolean);
                }
        }

        va_end(ap);
}

typedef void (*Test)(JsonVariant *);

static void test_variant(const char *data, Test test) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL, *w = NULL;
        _cleanup_free_ char *s = NULL;
        int r;

        r = json_parse(data, &v, NULL);
        assert_se(r == 0);
        assert_se(v);
        assert_se(json_variant_type(v) == JSON_VARIANT_OBJECT);

        r = json_variant_format(v, 0, &s);
        assert_se(r >= 0);
        assert_se(s);

        log_info("formatted normally: %s\n", s);

        r = json_parse(data, &w, NULL);
        assert_se(r == 0);
        assert_se(w);
        assert_se(json_variant_type(v) == JSON_VARIANT_OBJECT);

        assert_se(json_variant_equal(v, w));

        s = mfree(s);
        w = json_variant_unref(w);

        r = json_variant_format(v, JSON_FORMAT_PRETTY, &s);
        assert_se(r >= 0);
        assert_se(s);

        log_info("formatted prettily:\n%s", s);

        r = json_parse(data, &w, NULL);
        assert_se(r == 0);
        assert_se(w);
        assert_se(json_variant_type(v) == JSON_VARIANT_OBJECT);

        assert_se(json_variant_equal(v, w));

        s = mfree(s);
        r = json_variant_format(v, JSON_FORMAT_COLOR, &s);
        assert_se(r >= 0);
        assert_se(s);
        printf("Normal with color: %s\n", s);

        s = mfree(s);
        r = json_variant_format(v, JSON_FORMAT_COLOR|JSON_FORMAT_PRETTY, &s);
        assert_se(r >= 0);
        assert_se(s);
        printf("Pretty with color:\n%s\n", s);

        if (test)
                test(v);
}

static void test_1(JsonVariant *v) {
        JsonVariant *p, *q;
        unsigned i;

        /* 3 keys + 3 values */
        assert_se(json_variant_elements(v) == 6);

        /* has k */
        p = json_variant_by_key(v, "k");
        assert_se(p && json_variant_type(p) == JSON_VARIANT_STRING);

        /* k equals v */
        assert_se(streq(json_variant_string(p), "v"));

        /* has foo */
        p = json_variant_by_key(v, "foo");
        assert_se(p && json_variant_type(p) == JSON_VARIANT_ARRAY && json_variant_elements(p) == 3);

        /* check  foo[0] = 1, foo[1] = 2, foo[2] = 3 */
        for (i = 0; i < 3; ++i) {
                q = json_variant_by_index(p, i);
                assert_se(q && json_variant_type(q) == JSON_VARIANT_INTEGER && json_variant_integer(q) == (i+1));
        }

        /* has bar */
        p = json_variant_by_key(v, "bar");
        assert_se(p && json_variant_type(p) == JSON_VARIANT_OBJECT && json_variant_elements(p) == 2);

        /* zap is null */
        q = json_variant_by_key(p, "zap");
        assert_se(q && json_variant_type(q) == JSON_VARIANT_NULL);
}

static void test_2(JsonVariant *v) {
        JsonVariant *p, *q;

        /* 2 keys + 2 values */
        assert_se(json_variant_elements(v) == 4);

        /* has mutant */
        p = json_variant_by_key(v, "mutant");
        assert_se(p && json_variant_type(p) == JSON_VARIANT_ARRAY && json_variant_elements(p) == 4);

        /* mutant[0] == 1 */
        q = json_variant_by_index(p, 0);
        assert_se(q && json_variant_type(q) == JSON_VARIANT_INTEGER && json_variant_integer(q) == 1);

        /* mutant[1] == null */
        q = json_variant_by_index(p, 1);
        assert_se(q && json_variant_type(q) == JSON_VARIANT_NULL);

        /* mutant[2] == "1" */
        q = json_variant_by_index(p, 2);
        assert_se(q && json_variant_type(q) == JSON_VARIANT_STRING && streq(json_variant_string(q), "1"));

        /* mutant[3] == JSON_VARIANT_OBJECT */
        q = json_variant_by_index(p, 3);
        assert_se(q && json_variant_type(q) == JSON_VARIANT_OBJECT && json_variant_elements(q) == 2);

        /* has 1 */
        p = json_variant_by_key(q, "1");
        assert_se(p && json_variant_type(p) == JSON_VARIANT_ARRAY && json_variant_elements(p) == 2);

        /* "1"[0] == 1 */
        q = json_variant_by_index(p, 0);
        assert_se(q && json_variant_type(q) == JSON_VARIANT_INTEGER && json_variant_integer(q) == 1);

        /* "1"[1] == "1" */
        q = json_variant_by_index(p, 1);
        assert_se(q && json_variant_type(q) == JSON_VARIANT_STRING && streq(json_variant_string(q), "1"));

        /* has blah */
        p = json_variant_by_key(v, "blah");
        assert_se(p && json_variant_type(p) == JSON_VARIANT_REAL && fabs(json_variant_real(p) - 1.27) < 0.001);
}

static void test_build(void) {
        _cleanup_(json_variant_unrefp) JsonVariant *a = NULL, *b = NULL;
        _cleanup_free_ char *s = NULL, *t = NULL;

        assert_se(json_build(&a, JSON_BUILD_STRING("hallo")) >= 0);
        assert_se(json_build(&b, JSON_BUILD_LITERAL(" \"hallo\"   ")) >= 0);
        assert_se(json_variant_equal(a, b));

        b = json_variant_unref(b);

        assert_se(json_build(&b, JSON_BUILD_VARIANT(a)) >= 0);
        assert_se(json_variant_equal(a, b));

        b = json_variant_unref(b);
        assert_se(json_build(&b, JSON_BUILD_STRING("pief")) >= 0);
        assert_se(!json_variant_equal(a, b));

        a = json_variant_unref(a);
        b = json_variant_unref(b);

        assert_se(json_build(&a, JSON_BUILD_OBJECT(JSON_BUILD_PAIR("one", JSON_BUILD_INTEGER(7)),
                                                   JSON_BUILD_PAIR("two", JSON_BUILD_REAL(2.0)),
                                                   JSON_BUILD_PAIR("three", JSON_BUILD_INTEGER(0)))) >= 0);

        assert_se(json_build(&b, JSON_BUILD_OBJECT(JSON_BUILD_PAIR("two", JSON_BUILD_INTEGER(2)),
                                                   JSON_BUILD_PAIR("three", JSON_BUILD_REAL(0)),
                                                   JSON_BUILD_PAIR("one", JSON_BUILD_REAL(7)))) >= 0);

        assert_se(json_variant_equal(a, b));

        a = json_variant_unref(a);
        b = json_variant_unref(b);

        assert_se(json_build(&a, JSON_BUILD_ARRAY(JSON_BUILD_OBJECT(JSON_BUILD_PAIR("x", JSON_BUILD_BOOLEAN(true)),
                                                                    JSON_BUILD_PAIR("y", JSON_BUILD_OBJECT(JSON_BUILD_PAIR("this", JSON_BUILD_NULL)))),
                                                  JSON_BUILD_VARIANT(NULL),
                                                  JSON_BUILD_LITERAL(NULL),
                                                  JSON_BUILD_STRING(NULL),
                                                  JSON_BUILD_NULL,
                                                  JSON_BUILD_INTEGER(77))) >= 0);

        assert_se(json_variant_format(a, 0, &s) >= 0);
        log_info("GOT: %s\n", s);
        assert_se(json_parse(s, &b, NULL) >= 0);
        assert_se(json_variant_equal(a, b));

        a = json_variant_unref(a);
        b = json_variant_unref(b);

        assert_se(json_build(&a, JSON_BUILD_REAL(M_PIl)) >= 0);

        s = mfree(s);
        assert_se(json_variant_format(a, 0, &s) >= 0);
        log_info("GOT: %s\n", s);
        assert_se(json_parse(s, &b, NULL) >= 0);
        assert_se(json_variant_format(b, 0, &t) >= 0);
        log_info("GOT: %s\n", t);

        assert_se(streq(s, t));

        a = json_variant_unref(a);
        b = json_variant_unref(b);
}

int main(int argc, char *argv[]) {

        test_tokenizer("x", -EINVAL);
        test_tokenizer("", JSON_TOKEN_END);
        test_tokenizer(" ", JSON_TOKEN_END);
        test_tokenizer("0", JSON_TOKEN_INTEGER, (intmax_t) 0, JSON_TOKEN_END);
        test_tokenizer("1234", JSON_TOKEN_INTEGER, (intmax_t) 1234, JSON_TOKEN_END);
        test_tokenizer("3.141", JSON_TOKEN_REAL, 3.141, JSON_TOKEN_END);
        test_tokenizer("0.0", JSON_TOKEN_REAL, 0.0, JSON_TOKEN_END);
        test_tokenizer("7e3", JSON_TOKEN_REAL, 7e3, JSON_TOKEN_END);
        test_tokenizer("-7e-3", JSON_TOKEN_REAL, -7e-3, JSON_TOKEN_END);
        test_tokenizer("true", JSON_TOKEN_BOOLEAN, true, JSON_TOKEN_END);
        test_tokenizer("false", JSON_TOKEN_BOOLEAN, false, JSON_TOKEN_END);
        test_tokenizer("null", JSON_TOKEN_NULL, JSON_TOKEN_END);
        test_tokenizer("{}", JSON_TOKEN_OBJECT_OPEN, JSON_TOKEN_OBJECT_CLOSE, JSON_TOKEN_END);
        test_tokenizer("\t {\n} \n", JSON_TOKEN_OBJECT_OPEN, JSON_TOKEN_OBJECT_CLOSE, JSON_TOKEN_END);
        test_tokenizer("[]", JSON_TOKEN_ARRAY_OPEN, JSON_TOKEN_ARRAY_CLOSE, JSON_TOKEN_END);
        test_tokenizer("\t [] \n\n", JSON_TOKEN_ARRAY_OPEN, JSON_TOKEN_ARRAY_CLOSE, JSON_TOKEN_END);
        test_tokenizer("\"\"", JSON_TOKEN_STRING, "", JSON_TOKEN_END);
        test_tokenizer("\"foo\"", JSON_TOKEN_STRING, "foo", JSON_TOKEN_END);
        test_tokenizer("\"foo\\nfoo\"", JSON_TOKEN_STRING, "foo\nfoo", JSON_TOKEN_END);
        test_tokenizer("{\"foo\" : \"bar\"}", JSON_TOKEN_OBJECT_OPEN, JSON_TOKEN_STRING, "foo", JSON_TOKEN_COLON, JSON_TOKEN_STRING, "bar", JSON_TOKEN_OBJECT_CLOSE, JSON_TOKEN_END);
        test_tokenizer("{\"foo\" : [true, false]}", JSON_TOKEN_OBJECT_OPEN, JSON_TOKEN_STRING, "foo", JSON_TOKEN_COLON, JSON_TOKEN_ARRAY_OPEN, JSON_TOKEN_BOOLEAN, true, JSON_TOKEN_COMMA, JSON_TOKEN_BOOLEAN, false, JSON_TOKEN_ARRAY_CLOSE, JSON_TOKEN_OBJECT_CLOSE, JSON_TOKEN_END);
        test_tokenizer("\"\xef\xbf\xbd\"", JSON_TOKEN_STRING, "\xef\xbf\xbd", JSON_TOKEN_END);
        test_tokenizer("\"\\ufffd\"", JSON_TOKEN_STRING, "\xef\xbf\xbd", JSON_TOKEN_END);
        test_tokenizer("\"\\uf\"", -EINVAL);
        test_tokenizer("\"\\ud800a\"", -EINVAL);
        test_tokenizer("\"\\udc00\\udc00\"", -EINVAL);
        test_tokenizer("\"\\ud801\\udc37\"", JSON_TOKEN_STRING, "\xf0\x90\x90\xb7", JSON_TOKEN_END);

        test_tokenizer("[1, 2]", JSON_TOKEN_ARRAY_OPEN, JSON_TOKEN_INTEGER, (intmax_t) 1, JSON_TOKEN_COMMA, JSON_TOKEN_INTEGER, (intmax_t) 2, JSON_TOKEN_ARRAY_CLOSE, JSON_TOKEN_END);

        test_variant("{\"k\": \"v\", \"foo\": [1, 2, 3], \"bar\": {\"zap\": null}}", test_1);
        test_variant("{\"mutant\": [1, null, \"1\", {\"1\": [1, \"1\"]}], \"blah\": 1.27}", test_2);

        test_build();

        return 0;
}
