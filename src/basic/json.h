#pragma once

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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "macro.h"
#include "util.h"

typedef union JsonValue JsonValue;
typedef enum JsonVariantType JsonVariantType;
typedef struct JsonVariant JsonVariant;

union JsonValue  {
        bool boolean;
        long double real;
        intmax_t integer;
};

#define JSON_VALUE_NULL ((JsonValue) {})

enum JsonVariantType {
        JSON_VARIANT_STRING,
        JSON_VARIANT_INTEGER,
        JSON_VARIANT_REAL,
        JSON_VARIANT_BOOLEAN,
        JSON_VARIANT_ARRAY,
        JSON_VARIANT_OBJECT,
        JSON_VARIANT_NULL,
        _JSON_VARIANT_MAX,
        _JSON_VARIANT_INVALID = -1
};

int json_variant_new_string(JsonVariant **ret, const char *s);
int json_variant_new_integer(JsonVariant **ret, intmax_t i);
int json_variant_new_real(JsonVariant **ret, long double d);
int json_variant_new_boolean(JsonVariant **ret, bool b);
int json_variant_new_array(JsonVariant **ret, JsonVariant **array, size_t n);
int json_variant_new_object(JsonVariant **ret, JsonVariant **array, size_t n);
int json_variant_new_null(JsonVariant **ret);

JsonVariant *json_variant_ref(JsonVariant *v);
JsonVariant *json_variant_unref(JsonVariant *v);

DEFINE_TRIVIAL_CLEANUP_FUNC(JsonVariant *, json_variant_unref);

const char *json_variant_string(JsonVariant *v);
intmax_t json_variant_integer(JsonVariant *v);
long double json_variant_real(JsonVariant *v);
bool json_variant_boolean(JsonVariant *v);

JsonVariantType json_variant_type(JsonVariant *v);
bool json_variant_has_type(JsonVariant *v, JsonVariantType type);

static inline bool json_variant_is_string(JsonVariant *v) {
        return json_variant_has_type(v, JSON_VARIANT_STRING);
}

static inline bool json_variant_is_integer(JsonVariant *v) {
        return json_variant_has_type(v, JSON_VARIANT_INTEGER);
}

static inline bool json_variant_is_real(JsonVariant *v) {
        return json_variant_has_type(v, JSON_VARIANT_REAL);
}

static inline bool json_variant_is_boolean(JsonVariant *v) {
        return json_variant_has_type(v, JSON_VARIANT_BOOLEAN);
}

static inline bool json_variant_is_array(JsonVariant *v) {
        return json_variant_has_type(v, JSON_VARIANT_ARRAY);
}

static inline bool json_variant_is_object(JsonVariant *v) {
        return json_variant_has_type(v, JSON_VARIANT_OBJECT);
}

static inline bool json_variant_is_null(JsonVariant *v) {
        return json_variant_has_type(v, JSON_VARIANT_NULL);
}

size_t json_variant_elements(JsonVariant *v);
JsonVariant *json_variant_by_index(JsonVariant *v, size_t index);
JsonVariant *json_variant_by_key(JsonVariant *v, const char *key);

bool json_variant_equal(JsonVariant *a, JsonVariant *b);

enum {
        JSON_FORMAT_PRETTY = 1,
        JSON_FORMAT_COLOR  = 2,
};

int json_variant_format(JsonVariant *v, unsigned flags, char **ret);
void json_variant_dump(JsonVariant *v, unsigned flags, FILE *f, const char *prefix);

int json_parse(const char *string, JsonVariant **ret, unsigned *ret_line);
int json_parse_continue(const char **p, JsonVariant **ret, unsigned *ret_line);

enum {
        _JSON_BUILD_STRING,
        _JSON_BUILD_INTEGER,
        _JSON_BUILD_REAL,
        _JSON_BUILD_BOOLEAN,
        _JSON_BUILD_ARRAY_BEGIN,
        _JSON_BUILD_ARRAY_END,
        _JSON_BUILD_OBJECT_BEGIN,
        _JSON_BUILD_OBJECT_END,
        _JSON_BUILD_PAIR,
        _JSON_BUILD_NULL,
        _JSON_BUILD_VARIANT,
        _JSON_BUILD_LITERAL,
        _JSON_BUILD_END,
        _JSON_BUILD_MAX,
};

#define JSON_BUILD_STRING(s) _JSON_BUILD_STRING, ({ const char *_x = s; _x; })
#define JSON_BUILD_INTEGER(i) _JSON_BUILD_INTEGER, ({ intmax_t _x = i; _x; })
#define JSON_BUILD_REAL(d) _JSON_BUILD_REAL, ({ long double _x = d; _x; })
#define JSON_BUILD_BOOLEAN(b) _JSON_BUILD_BOOLEAN, ({ bool _x = b; _x; })
#define JSON_BUILD_ARRAY(...) _JSON_BUILD_ARRAY_BEGIN, __VA_ARGS__, _JSON_BUILD_ARRAY_END
#define JSON_BUILD_OBJECT(...) _JSON_BUILD_OBJECT_BEGIN, __VA_ARGS__, _JSON_BUILD_OBJECT_END
#define JSON_BUILD_PAIR(n, ...) _JSON_BUILD_PAIR, ({ const char *_x = n; _x; }), __VA_ARGS__
#define JSON_BUILD_NULL _JSON_BUILD_NULL
#define JSON_BUILD_VARIANT(v) _JSON_BUILD_VARIANT, ({ JsonVariant *_x = v; _x; })
#define JSON_BUILD_LITERAL(l) _JSON_BUILD_LITERAL, ({ const char *_x = l; _x; })

int json_build_internal(JsonVariant **ret, ...);

#define json_build(ret, ...) json_build_internal(ret, __VA_ARGS__, _JSON_BUILD_END)

enum { /* JSON tokens */
        JSON_TOKEN_END,
        JSON_TOKEN_COLON,
        JSON_TOKEN_COMMA,
        JSON_TOKEN_OBJECT_OPEN,
        JSON_TOKEN_OBJECT_CLOSE,
        JSON_TOKEN_ARRAY_OPEN,
        JSON_TOKEN_ARRAY_CLOSE,
        JSON_TOKEN_STRING,
        JSON_TOKEN_REAL,
        JSON_TOKEN_INTEGER,
        JSON_TOKEN_BOOLEAN,
        JSON_TOKEN_NULL,
        _JSON_TOKEN_MAX,
        _JSON_TOKEN_INVALID = -1,
};

int json_tokenize(const char **p, char **ret_string, JsonValue *ret_value, void **state, unsigned *line);

/* We use fake JsonVariant objects for some special values, in order to avoid memory allocations for them. Note that
 * effectively this means that there are multiple ways to encode the some objects: via these magic values or as
 * properly allocated JsonVariant. We convert between both on-the-fly as necessary. */
#define JSON_VARIANT_MAGIC_TRUE ((JsonVariant*) 1)
#define JSON_VARIANT_MAGIC_FALSE ((JsonVariant*) 2)
#define JSON_VARIANT_MAGIC_NULL ((JsonVariant*) 3)
#define JSON_VARIANT_MAGIC_ZERO_INTEGER ((JsonVariant*) 4)
#define JSON_VARIANT_MAGIC_ZERO_REAL ((JsonVariant*) 5)
#define JSON_VARIANT_MAGIC_EMPTY_STRING ((JsonVariant*) 6)
#define JSON_VARIANT_MAGIC_EMPTY_ARRAY ((JsonVariant*) 7)
#define JSON_VARIANT_MAGIC_EMPTY_OBJECT ((JsonVariant*) 8)
