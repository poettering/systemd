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

#include "hashmap.h"
#include "parse-util.h"
#include "set.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "varlink-validate.h"

#define FIELD_NAME_MAX 256
#define INTERFACE_NAME_MAX 256
#define CONCEPT_NAME_MAX 256

typedef enum VarlinkConceptType {
        /* Types */
        VARLINK_CONCEPT_STRING,
        VARLINK_CONCEPT_INT,
        VARLINK_CONCEPT_FLOAT,
        VARLINK_CONCEPT_BOOL,
        VARLINK_CONCEPT_FOREIGN,
        VARLINK_CONCEPT_DATA,
        VARLINK_CONCEPT_OBJECT,
        VARLINK_CONCEPT_ENUM,
        VARLINK_CONCEPT_ENUM_ITEM,

        /* Metatypes, when we don't know yet */
        VARLINK_CONCEPT_ENUM_OR_OBJECT,
        VARLINK_CONCEPT_ANY_TYPE,

        /* Reference to a named type */
        VARLINK_CONCEPT_REFERENCE,

        /* Other stuff */
        VARLINK_CONCEPT_INTERFACE,
        VARLINK_CONCEPT_METHOD,
        VARLINK_CONCEPT_ERROR,
} VarlinkConceptType;

typedef enum VarlinkIsArray {
        VARLINK_ARRAY_NO = 0,
        VARLINK_ARRAY_YES = 1,
        VARLINK_ARRAY_DONT_KNOW = -1,
} VarlinkIsArray;

struct VarlinkConcept {
        VarlinkValidator *validator;

        char *name;
        char *docstring;
        VarlinkConceptType type;

        VarlinkConcept *interface;
        JsonVariant *def;

        uint64_t array_size;
        VarlinkIsArray is_array:2;

        bool named:1;

        union {
                struct {
                        OrderedHashmap *fields;
                } concept_object;
                struct {
                        OrderedHashmap *items;
                } concept_enum;
                struct {
                        OrderedHashmap *concepts;
                } concept_interface;
                struct {
                        VarlinkConcept *input;
                        VarlinkConcept *output;
                } concept_method;
                struct {
                        VarlinkConcept *parameters;
                } concept_error;
                struct {
                        char *name;
                        VarlinkConcept *reference;
                } concept_reference;
        };
};

typedef struct VarlinkValidator {
        Hashmap *concepts_by_name;
        Set *references;
        Set *with_default;
        OrderedHashmap *interfaces;
} VarlinkValidator;

static VarlinkConcept *varlink_concept_free(VarlinkConcept *c) {
        if (!c)
                return NULL;

        if (c->validator && c->name)
                (void) hashmap_remove(c->validator->concepts_by_name, c->name);

        free(c->name);
        free(c->docstring);

        json_variant_unref(c->def);

        switch (c->type) {

        case VARLINK_CONCEPT_OBJECT:
                ordered_hashmap_free(c->concept_object.fields);
                break;

        case VARLINK_CONCEPT_ENUM:
                ordered_hashmap_free(c->concept_enum.items);
                break;

        case VARLINK_CONCEPT_INTERFACE:
                ordered_hashmap_free(c->concept_interface.concepts);
                break;

        case VARLINK_CONCEPT_REFERENCE:
                free(c->concept_reference.name);
                break;

        default:
                break;
        }

        return mfree(c);
}

static int varlink_concept_new(
                VarlinkValidator *v,
                VarlinkConcept *parent,
                VarlinkConceptType type,
                const char *name,
                VarlinkConcept **ret) {

        VarlinkConcept *c;
        char *key, *id;
        int r;

        assert(v);
        assert(name);

        r = hashmap_ensure_allocated(&v->concepts_by_name, &string_hash_ops);
        if (r < 0)
                return r;

        c = new0(VarlinkConcept, 1);
        if (!c)
                return -ENOMEM;

        c->type = type;
        c->is_array = VARLINK_ARRAY_DONT_KNOW;

        if (parent) {
                if (parent->type == VARLINK_CONCEPT_INTERFACE)
                        c->interface = parent;
                else
                        c->interface = parent->interface;

                /* The fully qualified name */
                c->name = strjoin(parent->name, ".", name);
                if (!c->name)
                        return -ENOMEM;

                /* The name with the interface prefix removed */
                key = startswith(c->name, c->interface->name);
                assert(key);
                key = startswith(key, ".");
                assert(key);
                key++;

                /* The last component of the name */
                id = strrchr(key, '.');
                if (id)
                        id++;
                else
                        id = key;
        } else {
                assert(type == VARLINK_CONCEPT_INTERFACE);

                c->name = strdup(name);
                if (!c->name)
                        return -ENOMEM;

                name = c->name;
        }

        r = hashmap_put(v->concepts_by_name, c->name, c);
        if (r < 0)
                goto fail;

        c->validator = v;

        if (c->interface) {
                r = ordered_hashmap_ensure_allocated(&c->interface->concept_interface.concepts, &string_hash_ops);
                if (r < 0)
                        goto fail;

                r = ordered_hashmap_put(c->interface->concept_interface.concepts, key, c);
                if (r < 0)
                        goto fail;
        }

        if (c->type == VARLINK_CONCEPT_INTERFACE) {
                r = ordered_hashmap_ensure_allocated(&v->interfaces, &string_hash_ops);
                if (r < 0)
                        goto fail;

                r = ordered_hashmap_put(v->interfaces, c->name, c);
                if (r < 0)
                        goto fail;
        }

        if (c->type == VARLINK_CONCEPT_ENUM_ITEM) {
                assert(parent);
                assert(parent->type == VARLINK_CONCEPT_ENUM);

                r = ordered_hashmap_ensure_allocated(&parent->concept_enum.items, &string_hash_ops);
                if (r < 0)
                        goto fail;

                r = ordered_hashmap_put(parent->concept_enum.items, id, c);
                if (r < 0)
                        goto fail;
        }

        if (parent && parent->type == VARLINK_CONCEPT_OBJECT) {

                r = ordered_hashmap_ensure_allocated(&parent->concept_object.fields, &string_hash_ops);
                if (r < 0)
                        goto fail;

                r = ordered_hashmap_put(parent->concept_object.fields, id, c);
                if (r < 0)
                        goto fail;
        }

        *ret = c;
        return 0;

fail:
        varlink_concept_free(c);
        return 0;
}

static bool test_charset(char c, const char *charset) {
        /* Consider the final NUL byte of a string never be inside the charset defined */
        if (c == 0)
                return false;

        return !!strchr(charset, c);
}

typedef struct CommentContext {
        bool newline;
        char *docstring;
} CommentContext;

static int process_whitespace(const char **c, CommentContext *cc) {
        const char *p = *c;
        size_t k;

        assert(c);
        assert(*c);
        assert(cc);

        for (;;) {
                p += strspn(p, SIMPLE_WHITESPACE);

                /* An empty line? Then flush out the accumulated comments */
                if (test_charset(*p, NEWLINE)) {
                        p++;

                        cc->docstring = mfree(cc->docstring);
                        cc->newline = true;
                        continue;
                }

                /* A new comment, lasting until this lines end */
                if (*p == '#') {
                        char *e;

                        p++;

                        /* Skip one additional whitespace character after the "#" */
                        if (test_charset(*p, SIMPLE_WHITESPACE))
                                p++;

                        k = strcspn(p, NEWLINE);

                        if (cc->newline) {
                                if (cc->docstring) {
                                        size_t l;

                                        l = strlen(cc->docstring);
                                        e = realloc(cc->docstring, l + 1 + k + 1);
                                        if (!e)
                                                return -ENOMEM;

                                        e[l] = '\n';
                                        memcpy(e + l + 1, p, k);
                                        e[l+1+k] = 0;

                                        cc->docstring = e;
                                } else if (k > 0) {
                                        e = strndup(p, k);
                                        if (!e)
                                                return -ENOMEM;

                                        cc->docstring = e;
                                }
                        }

                        p += k;

                        /* Skip the delimiting newline of the comment */
                        if (test_charset(*p, NEWLINE)) {
                                p++;
                                cc->newline = true;
                        }

                        continue;
                }

                cc->newline = false;
                break;
        }

        if (p == *c)
                return 0;

        *c = p;
        return 1;
}

static int read_token(const char **c, const char *token) {
        const char *e;

        assert(c);
        assert(*c);
        assert(token);

        e = startswith(*c, token);
        if (!e)
                return 0;

        /* If the token is alphanumerical (i.e. a keyword or such), and there are more alphanumerical characters
         * coming, then the token continues, and we won't accept it here */
        if (in_charset(token, ALPHANUMERICAL) &&
            test_charset(*e, ALPHANUMERICAL))
                return 0;

        *c = e;
        return 1;
}

static int read_field_name(const char **c, char **ret) {
        const char *p;
        size_t k;
        char *m;

        assert(c);
        assert(*c);
        assert(ret);

        p = *c;

        if (!test_charset(*p, LETTERS))
                return -EINVAL;

        k = 1 + strspn(p + 1, ALPHANUMERICAL "_");

        if (k > FIELD_NAME_MAX)
                return -EINVAL;

        m = strndup(p, k);
        if (!m)
                return -ENOMEM;

        *c = p + k;
        *ret = m;

        return 0;
}

static int read_array_size(const char **c, uint64_t *ret) {
        const char *p;
        char *m;
        size_t k;
        int r;

        assert(c);
        assert(*c);
        assert(ret);

        p = *c;

        if (!test_charset(*p, "123456789"))
                return -EINVAL;

        k = 1 + strspn(p + 1, DIGITS);
        m = strndupa(p, k);

        r = safe_atou64(m, ret);
        if (r < 0)
                return r;

        *c = p + k;
        return 0;
}

static int read_interface_name(const char **c, char **ret) {
        bool numeric = true, dot = true;
        const char *p, *q;
        size_t k;
        char *m;

        assert(c);
        assert(*c);
        assert(ret);

        p = *c;

        k = strspn(p, ALPHANUMERICAL "-_.");
        if (k <= 0)
                return -EINVAL;

        if (k > INTERFACE_NAME_MAX)
                return -EINVAL;

        for (q = p; q < p + k; q++) {

                if (*q == '.') {
                        /* Don't permit two adjacent dots */
                        if (dot)
                                return -EINVAL;

                        /* Don't permit fully numeric labels */
                        if (numeric)
                                return -EINVAL;

                        dot = true;
                        numeric = true;
                } else {
                        dot = false;

                        if (!test_charset(*q, DIGITS))
                                numeric = false;
                }
        }

        if (dot || numeric)
                return -EINVAL;

        m = strndup(p, k);
        if (!m)
                return -ENOMEM;

        *c = p + k;
        *ret = m;
        return 0;
}

static int read_concept_name(const char **c, char **ret) {
        const char *p;
        size_t k;
        char *m;

        assert(c);
        assert(*c);
        assert(ret);

        p = *c;

        if (!test_charset(*p, UPPERCASE_LETTERS))
                return -EINVAL;

        k = 1 + strspn(p + 1, ALPHANUMERICAL "_");

        if (k > CONCEPT_NAME_MAX)
                return -EINVAL;

        m = strndup(p, k);
        if (!m)
                return -ENOMEM;

        *c = p + k;
        *ret = m;

        return 0;
}

static int varlink_validator_decode_json(VarlinkValidator *v, const char **c, VarlinkConcept *concept) {
        int r;

        assert(v);
        assert(c);
        assert(*c);
        assert(concept);
        assert(!concept->def);

        r = json_parse_continue(c, &concept->def, NULL);
        if (r < 0)
                return r;

        r = set_ensure_allocated(&v->with_default, NULL);
        if (r < 0)
                return r;

        r = set_put(v->with_default, concept);
        if (r < 0)
                return r;

        return 0;
}

static int varlink_validator_decode_struct(VarlinkValidator *v, const char **c, VarlinkConcept *concept, CommentContext *cc) {

        enum {
                EXPECT_START,
                EXPECT_FIELD_NAME,
                EXPECT_COLON_OR_COMMA,
                EXPECT_FIRST_FIELD_NAME,
                EXPECT_FIELD_TYPE,
                EXPECT_EQUAL,
                EXPECT_DEFAULT,
                EXPECT_COMMA,
                EXPECT_ARRAY_BRACKET_OPEN,
                EXPECT_ARRAY_SIZE,
                EXPECT_ARRAY_BRACKET_CLOSE,
        } state = EXPECT_START;

        _cleanup_free_ char *field_name = NULL, *subconcept_docstring = NULL;
        VarlinkConcept *subconcept = NULL;
        const char *p;
        int r;

        assert(v);
        assert(c);
        assert(*c);
        assert(cc);
        assert(concept);

        p = *c;

        for (;;) {
                r = process_whitespace(&p, cc);
                if (r < 0)
                        goto finish;

                switch (state) {

                case EXPECT_START: {
                        char *reference = NULL;

                        if (read_token(&p, "(")) {

                                if (concept->type == VARLINK_CONCEPT_ANY_TYPE)
                                        concept->type = VARLINK_CONCEPT_ENUM_OR_OBJECT;

                                state = EXPECT_FIRST_FIELD_NAME;
                                break;
                        }

                        if (read_token(&p, "string")) {

                                if (!IN_SET(concept->type, VARLINK_CONCEPT_STRING, VARLINK_CONCEPT_ANY_TYPE)) {
                                        r = -EINVAL;
                                        goto finish;
                                }

                                concept->type = VARLINK_CONCEPT_STRING;
                                state = EXPECT_ARRAY_BRACKET_OPEN;
                                break;
                        }

                        if (read_token(&p, "bool")) {

                                if (!IN_SET(concept->type, VARLINK_CONCEPT_BOOL, VARLINK_CONCEPT_ANY_TYPE)) {
                                        r = -EINVAL;
                                        goto finish;
                                }

                                concept->type = VARLINK_CONCEPT_BOOL;
                                state = EXPECT_ARRAY_BRACKET_OPEN;
                                break;
                        }

                        if (read_token(&p, "int")) {

                                if (!IN_SET(concept->type, VARLINK_CONCEPT_INT, VARLINK_CONCEPT_ANY_TYPE)) {
                                        r = -EINVAL;
                                        goto finish;
                                }

                                concept->type = VARLINK_CONCEPT_INT;
                                state = EXPECT_ARRAY_BRACKET_OPEN;
                                break;
                        }

                        if (read_token(&p, "float")) {

                                if (!IN_SET(concept->type, VARLINK_CONCEPT_FLOAT, VARLINK_CONCEPT_ANY_TYPE)) {
                                        r = -EINVAL;
                                        goto finish;
                                }

                                concept->type = VARLINK_CONCEPT_INT;
                                state = EXPECT_ARRAY_BRACKET_OPEN;
                                break;
                        }

                        if (read_token(&p, "object")) {

                                if (!IN_SET(concept->type, VARLINK_CONCEPT_FOREIGN, VARLINK_CONCEPT_ANY_TYPE)) {
                                        r = -EINVAL;
                                        goto finish;
                                }

                                concept->type = VARLINK_CONCEPT_FOREIGN;
                                state = EXPECT_ARRAY_BRACKET_OPEN;
                                break;
                        }

                        if (read_token(&p, "data")) {

                                if (!IN_SET(concept->type, VARLINK_CONCEPT_DATA, VARLINK_CONCEPT_ANY_TYPE)) {
                                        r = -EINVAL;
                                        goto finish;
                                }

                                concept->type = VARLINK_CONCEPT_DATA;
                                state = EXPECT_ARRAY_BRACKET_OPEN;
                                break;
                        }

                        r = read_concept_name(&p, &reference);
                        if (r < 0)
                                goto finish;

                        concept->type = VARLINK_CONCEPT_REFERENCE;
                        concept->concept_reference.name = reference;

                        r = set_ensure_allocated(&v->references, NULL);
                        if (r < 0)
                                goto finish;

                        r = set_put(v->references, concept);
                        if (r < 0)
                                goto finish;

                        state = EXPECT_ARRAY_BRACKET_OPEN;
                        break;
                }

                case EXPECT_FIRST_FIELD_NAME:

                        if (read_token(&p, ")")) {
                                if (concept->type == VARLINK_CONCEPT_ENUM_OR_OBJECT)
                                        concept->type = VARLINK_CONCEPT_OBJECT;
                                state = EXPECT_ARRAY_BRACKET_OPEN;
                                break;
                        }

                        /* fall through */

                case EXPECT_FIELD_NAME:

                        assert(!field_name);

                        r = read_field_name(&p, &field_name);
                        if (r < 0)
                                goto finish;

                        free_and_replace(subconcept_docstring, cc->docstring);

                        state = EXPECT_COLON_OR_COMMA;
                        break;

                case EXPECT_COLON_OR_COMMA:

                        if (read_token(&p, ":")) {

                                if (!IN_SET(concept->type, VARLINK_CONCEPT_OBJECT, VARLINK_CONCEPT_ENUM_OR_OBJECT)) {
                                        r = -EINVAL;
                                        goto finish;
                                }

                                concept->type = VARLINK_CONCEPT_OBJECT;
                                state = EXPECT_FIELD_TYPE;
                                break;
                        }

                        if (read_token(&p, ",")) {
                                if (!IN_SET(concept->type, VARLINK_CONCEPT_ENUM, VARLINK_CONCEPT_ENUM_OR_OBJECT)) {
                                        r = -EINVAL;
                                        goto finish;
                                }

                                assert(field_name);

                                concept->type = VARLINK_CONCEPT_ENUM;

                                r = varlink_concept_new(v, concept, VARLINK_CONCEPT_ENUM_ITEM, field_name, &subconcept);
                                if (r < 0)
                                        goto finish;

                                free_and_replace(subconcept->docstring, subconcept_docstring);

                                field_name = mfree(field_name);
                                state = EXPECT_FIELD_NAME;
                                break;
                        }

                        if (read_token(&p, ")")) {

                                if (!IN_SET(concept->type, VARLINK_CONCEPT_ENUM, VARLINK_CONCEPT_ENUM_OR_OBJECT)) {
                                        r = -EINVAL;
                                        goto finish;
                                }

                                assert(field_name);

                                concept->type = VARLINK_CONCEPT_ENUM;

                                r = varlink_concept_new(v, concept, VARLINK_CONCEPT_ENUM_ITEM, field_name, &subconcept);
                                if (r < 0)
                                        goto finish;

                                free_and_replace(subconcept->docstring, subconcept_docstring);

                                field_name = mfree(field_name);

                                state = EXPECT_ARRAY_BRACKET_OPEN;
                                break;
                        }

                        r = -EINVAL;
                        goto finish;

                case EXPECT_FIELD_TYPE: {
                        assert(concept->type == VARLINK_CONCEPT_OBJECT);

                        r = varlink_concept_new(v, concept, VARLINK_CONCEPT_ANY_TYPE, field_name, &subconcept);
                        if (r < 0)
                                goto finish;

                        free_and_replace(subconcept->docstring, subconcept_docstring);

                        r = varlink_validator_decode_struct(v, &p, subconcept, cc);
                        if (r < 0)
                                goto finish;

                        state = EXPECT_EQUAL;
                        break;
                }

                case EXPECT_EQUAL:
                        assert(concept->type == VARLINK_CONCEPT_OBJECT);
                        assert(subconcept);

                        if (read_token(&p, "=")) {
                                state = EXPECT_DEFAULT;
                                break;
                        }

                        if (read_token(&p, ",")) {
                                field_name = mfree(field_name);
                                subconcept = NULL;

                                state = EXPECT_FIELD_NAME;
                                break;
                        }

                        if (read_token(&p, ")")) {
                                field_name = mfree(field_name);
                                subconcept = NULL;

                                state = EXPECT_ARRAY_BRACKET_OPEN;
                                break;
                        }

                        r = -EINVAL;
                        goto finish;

                case EXPECT_DEFAULT:
                        assert(concept->type == VARLINK_CONCEPT_OBJECT);
                        assert(subconcept);

                        r = varlink_validator_decode_json(v, &p, subconcept);
                        if (r < 0)
                                goto finish;

                        field_name = mfree(field_name);
                        subconcept = NULL;

                        state = EXPECT_COMMA;
                        break;

                case EXPECT_COMMA:
                        assert(concept->type == VARLINK_CONCEPT_OBJECT);

                        if (read_token(&p, ",")) {
                                state = EXPECT_FIELD_NAME;
                                break;
                        }

                        if (read_token(&p, ")")) {
                                state = EXPECT_ARRAY_BRACKET_OPEN;
                                break;
                        }

                        break;

                case EXPECT_ARRAY_BRACKET_OPEN:

                        if (concept->is_array == VARLINK_ARRAY_NO) {
                                r = 0;
                                goto finish;
                        }

                        if (read_token(&p, "[")) {
                                concept->is_array = VARLINK_ARRAY_YES;
                                state = EXPECT_ARRAY_SIZE;
                                break;
                        }

                        if (concept->is_array == VARLINK_ARRAY_YES) {
                                r = -EINVAL;
                                goto finish;
                        }

                        concept->is_array = VARLINK_ARRAY_NO;
                        r = 0;
                        goto finish;

                case EXPECT_ARRAY_SIZE:

                        if (read_token(&p, "]")) {
                                concept->array_size = (size_t) -1;
                                state = EXPECT_ARRAY_BRACKET_CLOSE;
                                break;
                        }

                        r = read_array_size(&p, &concept->array_size);
                        if (r < 0)
                                goto finish;

                        state = EXPECT_ARRAY_BRACKET_CLOSE;
                        break;

                case EXPECT_ARRAY_BRACKET_CLOSE:

                        if (read_token(&p, "]")) {
                                r = 0;
                                goto finish;
                        }

                        r = -EINVAL;
                        goto finish;
                }
        }

finish:
        if (r >= 0)
                *c = p;

        return r;
}

static int varlink_validator_decode_interface(VarlinkValidator *v, const char **c) {

        enum {
                EXPECT_INTERFACE,
                EXPECT_INTERFACE_NAME,

                EXPECT_CONCEPT,

                EXPECT_TYPE_NAME,
                EXPECT_TYPE_DEFINITION,

                EXPECT_METHOD_NAME,
                EXPECT_METHOD_INPUT,
                EXPECT_METHOD_ARROW,
                EXPECT_METHOD_OUTPUT,

                EXPECT_ERROR_NAME,
                EXPECT_ERROR_PARAMETERS,

        } state = EXPECT_INTERFACE;

        VarlinkConcept *interface = NULL, *concept = NULL;
        _cleanup_free_ char *docstring = NULL;
        CommentContext cc = { .newline = true };
        const char *p;
        int r;


        assert(v);
        assert(c);
        assert(*c);

        p = *c;

        for (;;) {
                r = process_whitespace(&p, &cc);
                if (r < 0)
                        goto finish;

                switch (state) {

                case EXPECT_INTERFACE:
                        r = read_token(&p, "interface");
                        if (r < 0)
                                goto finish;
                        if (r > 0) {
                                free_and_replace(docstring, cc.docstring);
                                state = EXPECT_INTERFACE_NAME;
                                break;
                        }

                        r = -EINVAL;
                        goto finish;

                case EXPECT_INTERFACE_NAME: {
                        _cleanup_free_ char *name = NULL;

                        r = read_interface_name(&p, &name);
                        if (r < 0)
                                goto finish;

                        assert(!interface);

                        r = varlink_concept_new(v, NULL, VARLINK_CONCEPT_INTERFACE, name, &interface);
                        if (r < 0)
                                goto finish;

                        free_and_replace(interface->docstring, docstring);
                        interface->named = true;

                        state = EXPECT_CONCEPT;
                        break;
                }

                case EXPECT_CONCEPT:
                        if (*p == 0) {
                                r = 0;
                                goto finish;
                        }

                        r = read_token(&p, "type");
                        if (r < 0)
                                goto finish;
                        if (r > 0) {
                                free_and_replace(docstring, cc.docstring);
                                state = EXPECT_TYPE_NAME;
                                break;
                        }

                        r = read_token(&p, "method");
                        if (r < 0)
                                goto finish;
                        if (r > 0) {
                                free_and_replace(docstring, cc.docstring);
                                state = EXPECT_METHOD_NAME;
                                break;
                        }

                        r = read_token(&p, "error");
                        if (r < 0)
                                goto finish;
                        if (r > 0) {
                                free_and_replace(docstring, cc.docstring);
                                state = EXPECT_ERROR_NAME;
                                break;
                        }

                        r = -EINVAL;
                        goto finish;

                case EXPECT_TYPE_NAME: {
                        _cleanup_free_ char *name = NULL;

                        r = read_concept_name(&p, &name);
                        if (r < 0)
                                goto finish;

                        assert(!concept);
                        assert(interface);

                        r = varlink_concept_new(v, interface, VARLINK_CONCEPT_ENUM_OR_OBJECT, name, &concept);
                        if (r < 0)
                                goto finish;

                        concept->is_array = VARLINK_ARRAY_NO;
                        concept->named = true;
                        free_and_replace(concept->docstring, docstring);

                        state = EXPECT_TYPE_DEFINITION;
                        break;
                }

                case EXPECT_TYPE_DEFINITION:
                        r = varlink_validator_decode_struct(v, &p, concept, &cc);
                        if (r < 0)
                                goto finish;

                        state = EXPECT_CONCEPT;
                        concept = NULL;
                        break;

                case EXPECT_METHOD_NAME: {
                        _cleanup_free_ char *name = NULL;

                        r = read_concept_name(&p, &name);
                        if (r < 0)
                                goto finish;

                        assert(!concept);
                        assert(interface);

                        r = varlink_concept_new(v, interface, VARLINK_CONCEPT_METHOD, name, &concept);
                        if (r < 0)
                                goto finish;

                        concept->named = true;
                        free_and_replace(concept->docstring, docstring);

                        state = EXPECT_METHOD_INPUT;
                        break;
                }

                case EXPECT_METHOD_INPUT:
                        assert(concept);
                        assert(!concept->concept_method.input);
                        assert(!concept->concept_method.output);

                        r = varlink_concept_new(v, concept, VARLINK_CONCEPT_OBJECT, "input", &concept->concept_method.input);
                        if (r < 0)
                                goto finish;

                        concept->is_array = VARLINK_ARRAY_NO;

                        r = varlink_validator_decode_struct(v, &p, concept->concept_method.input, &cc);
                        if (r < 0)
                                goto finish;

                        state = EXPECT_METHOD_ARROW;
                        break;

                case EXPECT_METHOD_ARROW:

                        r = read_token(&p, "->");
                        if (r < 0)
                                goto finish;
                        if (r > 0) {
                                state = EXPECT_METHOD_OUTPUT;
                                break;
                        }

                        r = -EINVAL;
                        goto finish;

                case EXPECT_METHOD_OUTPUT:
                        assert(concept);
                        assert(concept->concept_method.input);
                        assert(!concept->concept_method.output);

                        r = varlink_concept_new(v, concept, VARLINK_CONCEPT_OBJECT, "output", &concept->concept_method.output);
                        if (r < 0)
                                goto finish;

                        concept->is_array = VARLINK_ARRAY_NO;

                        r = varlink_validator_decode_struct(v, &p, concept->concept_method.output, &cc);
                        if (r < 0)
                                goto finish;

                        state = EXPECT_CONCEPT;
                        concept = NULL;
                        break;

                case EXPECT_ERROR_NAME: {
                        _cleanup_free_ char *name = NULL;

                        r = read_concept_name(&p, &name);
                        if (r < 0)
                                goto finish;

                        assert(!concept);
                        assert(interface);

                        r = varlink_concept_new(v, interface, VARLINK_CONCEPT_ERROR, name, &concept);
                        if (r < 0)
                                goto finish;

                        concept->named = true;
                        free_and_replace(concept->docstring, docstring);

                        state = EXPECT_ERROR_PARAMETERS;
                        break;
                }

                case EXPECT_ERROR_PARAMETERS:
                        assert(concept);
                        assert(!concept->concept_error.parameters);

                        r = varlink_concept_new(v, concept, VARLINK_CONCEPT_OBJECT, "parameters", &concept->concept_error.parameters);
                        if (r < 0)
                                goto finish;

                        concept->is_array = VARLINK_ARRAY_NO;

                        r = varlink_validator_decode_struct(v, &p, concept->concept_error.parameters, &cc);
                        if (r < 0)
                                goto finish;

                        state = EXPECT_CONCEPT;
                        concept = NULL;
                        break;
                }
        }

finish:
        free(cc.docstring);

        if (r >= 0)
                *c = p;

        return r;
}

static int varlink_qualify_name(const char *name, const char *interface, char **ret) {
        char *q;

        assert(name);
        assert(interface);
        assert(ret);

        if (strchr(name, '.'))
                q = strdup(name);
        else
                q = strjoin(interface, ".", name);
        if (!q)
                return -ENOMEM;

        *ret = q;
        return 0;
}

static int varlink_validator_resolve(VarlinkValidator *v) {
        VarlinkConcept *c;
        Iterator i;
        int r;

        assert(v);

        SET_FOREACH(c, v->references, i) {
                _cleanup_free_ char *qualified = NULL;
                VarlinkConcept *q;

                assert(c->type == VARLINK_CONCEPT_REFERENCE);
                assert(c->concept_reference.name);
                assert(!c->concept_reference.reference);

                r = varlink_qualify_name(c->concept_reference.name, c->interface->name, &qualified);
                if (r < 0)
                        return r;

                q = varlink_validator_find(v, qualified);
                if (!q)
                        return -ENXIO;

                if (!IN_SET(q->type, VARLINK_CONCEPT_OBJECT, VARLINK_CONCEPT_ENUM))
                        return -ENOTTY;

                if (!q->named)
                        return -EADDRNOTAVAIL;

                c->concept_reference.reference = q;
        }

        return 0;
}

static int varlink_validator_check_defaults(VarlinkValidator *v) {
        VarlinkConcept *c;
        Iterator i;
        int r;

        SET_FOREACH(c, v->with_default, i) {

                assert(c->def);

                r = varlink_validate(c, c->def, NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

int varlink_validator_parse(VarlinkValidator **ret, char **texts) {
        _cleanup_(varlink_validator_unrefp) VarlinkValidator *v = NULL;
        char **t;
        int r;

        assert_return(ret, -EINVAL);

        v = new0(VarlinkValidator, 1);
        if (!v)
                return -ENOMEM;

        STRV_FOREACH(t, texts) {
                const char *p;

                p = *t;
                r = varlink_validator_decode_interface(v, &p);
                if (r < 0)
                        return r;
        }

        r = varlink_validator_resolve(v);
        if (r < 0)
                return r;

        r = varlink_validator_check_defaults(v);
        if (r < 0)
                return r;

        *ret = v;
        v = NULL;

        return 0;
}

VarlinkValidator *varlink_validator_unref(VarlinkValidator *validator) {
        VarlinkConcept *c;

        if (!validator)
                return NULL;

        while ((c = hashmap_first(validator->concepts_by_name)))
                varlink_concept_free(c);

        hashmap_free(validator->concepts_by_name);
        set_free(validator->references);
        set_free(validator->with_default);

        return mfree(validator);
}

VarlinkConcept *varlink_validator_find(VarlinkValidator *validator, const char *name) {
        assert(validator);

        return hashmap_get(validator->concepts_by_name, name);
}

static void varlink_docstring_dump(const char *docstring, FILE *f, const char *prefix, unsigned flags) {
        const char *p;
        size_t k;

        assert(f);

        if (!docstring)
                return;

        prefix = strempty(prefix);

        p = docstring;
        for (;;) {
                k = strcspn(p, NEWLINE);

                fputs(prefix, f);
                fputs("# ", f);
                fwrite(p, 1, k, f);
                fputc('\n', f);

                p += k;

                if (*p == 0)
                        break;

                p++;
        }
}

static const char *varlink_unqualify_name(const char *name) {
        const char *p;

        assert(name);

        p = strrchr(name, '.');
        if (p)
                return p + 1;

        return name;
}

static const char *varlink_strip_interface(const char *name, const char *interface) {
        const char *p;

        assert(name);
        assert(interface);

        p = startswith(name, interface);
        if (p && *p == '.')
                return p + 1;

        return name;
}

static void varlink_struct_dump(VarlinkConcept *c, FILE *f, const char *prefix, unsigned flags) {
        const char *prefix2;

        prefix = strempty(prefix);
        prefix2 = strjoina(prefix, "\t");

        switch (c->type) {

        case VARLINK_CONCEPT_OBJECT: {
                bool separator = false;
                VarlinkConcept *field;
                Iterator i;

                if (ordered_hashmap_isempty(c->concept_object.fields)) {
                        fputs("()", f);
                        break;
                }

                fputs("(\n", f);

                ORDERED_HASHMAP_FOREACH(field, c->concept_object.fields, i) {

                        if (separator)
                                fputs(",\n", f);

                        varlink_docstring_dump(field->docstring, f, prefix2, flags);
                        fputs(prefix2, f);
                        if (flags & VARLINK_DUMP_COLOR)
                                fputs(ANSI_GREEN, f);
                        fputs(varlink_unqualify_name(field->name), f);
                        if (flags & VARLINK_DUMP_COLOR)
                                fputs(ANSI_NORMAL, f);
                        fputs(" : ", f);

                        varlink_struct_dump(field, f, prefix2, flags);
                        separator = true;
                }

                fputc('\n', f);
                fputs(prefix, f);
                fputc(')', f);

                break;
        }

        case VARLINK_CONCEPT_ENUM: {
                bool separator = false;
                VarlinkConcept *item;
                Iterator i;

                fputs("(\n", f);

                ORDERED_HASHMAP_FOREACH(item, c->concept_enum.items, i) {

                        if (separator)
                                fputs(",\n", f);

                        varlink_docstring_dump(item->docstring, f, prefix2, flags);
                        fputs(prefix2, f);
                        if (flags & VARLINK_DUMP_COLOR)
                                fputs(ANSI_GREEN, f);
                        fputs(varlink_unqualify_name(item->name), f);
                        if (flags & VARLINK_DUMP_COLOR)
                                fputs(ANSI_NORMAL, f);
                        separator = true;
                }

                fputc('\n', f);
                fputs(prefix, f);
                fputc(')', f);
                break;
        }

        case VARLINK_CONCEPT_STRING:
                if (flags & VARLINK_DUMP_COLOR)
                        fputs(ANSI_HIGHLIGHT, f);
                fputs("string", f);
                if (flags & VARLINK_DUMP_COLOR)
                        fputs(ANSI_NORMAL, f);
                break;

        case VARLINK_CONCEPT_INT:
                if (flags & VARLINK_DUMP_COLOR)
                        fputs(ANSI_HIGHLIGHT, f);
                fputs("int", f);
                if (flags & VARLINK_DUMP_COLOR)
                        fputs(ANSI_NORMAL, f);
                break;

        case VARLINK_CONCEPT_BOOL:
                if (flags & VARLINK_DUMP_COLOR)
                        fputs(ANSI_HIGHLIGHT, f);
                fputs("bool", f);
                if (flags & VARLINK_DUMP_COLOR)
                        fputs(ANSI_NORMAL, f);
                break;

        case VARLINK_CONCEPT_FLOAT:
                if (flags & VARLINK_DUMP_COLOR)
                        fputs(ANSI_HIGHLIGHT, f);
                fputs("float", f);
                if (flags & VARLINK_DUMP_COLOR)
                        fputs(ANSI_NORMAL, f);
                break;

        case VARLINK_CONCEPT_FOREIGN:
                if (flags & VARLINK_DUMP_COLOR)
                        fputs(ANSI_HIGHLIGHT, f);
                fputs("object", f);
                if (flags & VARLINK_DUMP_COLOR)
                        fputs(ANSI_NORMAL, f);
                break;

        case VARLINK_CONCEPT_DATA:
                if (flags & VARLINK_DUMP_COLOR)
                        fputs(ANSI_HIGHLIGHT, f);
                fputs("data", f);
                if (flags & VARLINK_DUMP_COLOR)
                        fputs(ANSI_NORMAL, f);
                break;

        case VARLINK_CONCEPT_REFERENCE:
                if (flags & VARLINK_DUMP_COLOR)
                        fputs(ANSI_HIGHLIGHT_BLUE, f);
                fputs(varlink_strip_interface(c->concept_reference.reference->name,
                                              c->interface->name), f);
                if (flags & VARLINK_DUMP_COLOR)
                        fputs(ANSI_NORMAL, f);
                break;

        default:
                assert_not_reached("Unexpected concept");
        }

        if (c->is_array == VARLINK_ARRAY_YES) {
                fputc('[', f);

                if (c->array_size != UINT64_MAX)
                        fprintf(f, "%" PRIu64, c->array_size);

                fputc(']', f);
        }

        if (c->def) {
                fputs(" = ", f);

                json_variant_dump(c->def, JSON_FORMAT_PRETTY|(flags & VARLINK_DUMP_COLOR ? JSON_FORMAT_COLOR : 0), f, prefix2);
        }
}

static void varlink_type_dump(VarlinkConcept *c, FILE *f, unsigned flags) {
        assert(c);
        assert(f);
        assert(IN_SET(c->type, VARLINK_CONCEPT_OBJECT, VARLINK_CONCEPT_ENUM));

        fputc('\n', f);
        varlink_docstring_dump(c->docstring, f, NULL, flags);
        if (flags & VARLINK_DUMP_COLOR)
                fputs(ANSI_HIGHLIGHT, f);
        fputs("type", f);
        if (flags & VARLINK_DUMP_COLOR)
                fputs(ANSI_NORMAL, f);
        fputc(' ', f);
        if (flags & VARLINK_DUMP_COLOR)
                fputs(ANSI_HIGHLIGHT_BLUE, f);
        fputs(varlink_unqualify_name(c->name), f);
        if (flags & VARLINK_DUMP_COLOR)
                fputs(ANSI_NORMAL, f);
        varlink_struct_dump(c, f, NULL, flags);
        fputc('\n', f);
}

static void varlink_method_dump(VarlinkConcept *c, FILE *f, unsigned flags) {
        assert(c);
        assert(f);
        assert(c->type == VARLINK_CONCEPT_METHOD);

        fputc('\n', f);
        varlink_docstring_dump(c->docstring, f, NULL, flags);
        if (flags & VARLINK_DUMP_COLOR)
                fputs(ANSI_HIGHLIGHT, f);
        fputs("method", f);
        if (flags & VARLINK_DUMP_COLOR)
                fputs(ANSI_NORMAL, f);
        fputc(' ', f);
        if (flags & VARLINK_DUMP_COLOR)
                fputs(ANSI_HIGHLIGHT_BLUE, f);
        fputs(varlink_unqualify_name(c->name), f);
        if (flags & VARLINK_DUMP_COLOR)
                fputs(ANSI_NORMAL, f);
        varlink_struct_dump(c->concept_method.input, f, NULL, flags);
        fputs(" -> ", f);
        varlink_struct_dump(c->concept_method.output, f, NULL, flags);
        fputc('\n', f);
}

static void varlink_error_dump(VarlinkConcept *c, FILE *f, unsigned flags) {
        assert(c);
        assert(f);
        assert(c->type == VARLINK_CONCEPT_ERROR);

        fputc('\n', f);
        varlink_docstring_dump(c->docstring, f, NULL, flags);
        if (flags & VARLINK_DUMP_COLOR)
                fputs(ANSI_HIGHLIGHT, f);
        fputs("error", f);
        if (flags & VARLINK_DUMP_COLOR)
                fputs(ANSI_NORMAL, f);
        fputc(' ', f);
        if (flags & VARLINK_DUMP_COLOR)
                fputs(ANSI_HIGHLIGHT_BLUE, f);
        fputs(varlink_unqualify_name(c->name), f);
        if (flags & VARLINK_DUMP_COLOR)
                fputs(ANSI_NORMAL, f);
        varlink_struct_dump(c->concept_error.parameters, f, NULL, flags);
        fputc('\n', f);
}

static void varlink_interface_dump(VarlinkConcept *interface, FILE *f, unsigned flags) {
        VarlinkConcept *c;
        Iterator i;

        assert(interface);
        assert(f);
        assert(interface->type == VARLINK_CONCEPT_INTERFACE);

        varlink_docstring_dump(interface->docstring, f, NULL, flags);
        if (flags & VARLINK_DUMP_COLOR)
                fputs(ANSI_HIGHLIGHT, f);
        fputs("interface", f);
        if (flags & VARLINK_DUMP_COLOR)
                fputs(ANSI_NORMAL, f);
        fputc(' ', f);
        if (flags & VARLINK_DUMP_COLOR)
                fputs(ANSI_HIGHLIGHT_BLUE, f);
        fputs(interface->name, f);
        if (flags & VARLINK_DUMP_COLOR)
                fputs(ANSI_NORMAL, f);
        fputc('\n', f);

        ORDERED_HASHMAP_FOREACH(c, interface->concept_interface.concepts, i) {

                if (!c->named)
                        continue;

                switch (c->type) {

                case VARLINK_CONCEPT_OBJECT:
                case VARLINK_CONCEPT_ENUM:
                        varlink_type_dump(c, f, flags);
                        break;

                case VARLINK_CONCEPT_METHOD:
                        varlink_method_dump(c, f, flags);
                        break;

                case VARLINK_CONCEPT_ERROR:
                        varlink_error_dump(c, f, flags);
                        break;

                default:
                        assert_not_reached("unexpected concept");
                }
        }
}

void varlink_validator_dump(VarlinkValidator *validator, FILE *f, unsigned flags) {
        VarlinkConcept *c;
        Iterator i;

        assert(validator);

        if (!f)
                f = stdout;

        ORDERED_HASHMAP_FOREACH(c, validator->interfaces, i)
                varlink_interface_dump(c, f, flags);
}

int varlink_validator_find_method(VarlinkValidator *v, const char *method, VarlinkConcept **ret) {
        VarlinkConcept *m;

        assert(v);
        assert(method);

        m = varlink_validator_find(v, method);
        if (!m)
                return -ENXIO;

        if (!IN_SET(m->type, VARLINK_CONCEPT_METHOD))
                return -ENOTTY;

        if (!m->named)
                return -EADDRNOTAVAIL;

        if (ret)
                *ret = m;
        return 0;
}

int varlink_validator_find_error(VarlinkValidator *v, const char *id, VarlinkConcept **ret) {
        VarlinkConcept *e;

        assert(v);
        assert(id);

        e = varlink_validator_find(v, id);
        if (!e)
                return -ENXIO;

        if (!IN_SET(e->type, VARLINK_CONCEPT_ERROR))
                return -ENOTTY;

        if (!e->named)
                return -EADDRNOTAVAIL;

        if (ret)
                *ret = e;
        return 0;
}

static int varlink_validate_object(VarlinkConcept *concept, JsonVariant *parameters, JsonVariant **ret) {
        JsonVariant **new_fields = NULL;
        VarlinkConcept *field;
        const char *field_name;
        Iterator i;
        size_t n = 0, j;
        int r;

        assert(concept);
        assert(parameters);
        assert(concept->type == VARLINK_CONCEPT_OBJECT);

        if (!json_variant_is_object(parameters))
                return -ENOEXEC;

        if (ret)
                new_fields = newa(JsonVariant*,
                                  2 * ordered_hashmap_size(concept->concept_object.fields) +
                                  json_variant_elements(parameters));

        ORDERED_HASHMAP_FOREACH_KEY(field, field_name, concept->concept_object.fields, i) {
                JsonVariant *b;

                r = varlink_validate(field, json_variant_by_key(parameters, field_name), ret ? &b : NULL);
                if (r < 0)
                        goto finish;

                if (ret) {
                        JsonVariant *k;

                        r = json_variant_new_string(&k, field_name);
                        if (r < 0) {
                                json_variant_unref(b);
                                goto finish;
                        }

                        new_fields[n++] = k;
                        new_fields[n++] = b;
                }
        }

        if (ret) {
                for (j = 0; j < json_variant_elements(parameters); j += 2) {
                        JsonVariant *k, *v;

                        k = json_variant_by_index(parameters, j);
                        assert(k);

                        if (ordered_hashmap_contains(concept->concept_object.fields, json_variant_string(k)))
                                continue;

                        v = json_variant_by_index(parameters, j+1);
                        assert(v);

                        new_fields[n++] = json_variant_ref(k);
                        new_fields[n++] = json_variant_ref(v);
                }

                r = json_variant_new_object(ret, new_fields, n);
        } else
                r = 0;

finish:
        for (j = 0; j < n; j++)
                json_variant_unref(new_fields[j]);

        return r;
}

static int varlink_validate_enum(VarlinkConcept *concept, JsonVariant *parameters, JsonVariant **ret) {
        const char *item_name;
        VarlinkConcept *item;
        Iterator i;
        bool good = false;

        assert(concept);
        assert(parameters);
        assert(concept->type == VARLINK_CONCEPT_ENUM);

        if (!json_variant_is_string(parameters))
                return -ENOEXEC;

        ORDERED_HASHMAP_FOREACH_KEY(item, item_name, concept->concept_enum.items, i) {

                if (streq_ptr(json_variant_string(parameters), item_name)) {
                        good = true;
                        break;
                }
        }

        if (!good)
                return -ENOEXEC;

        if (ret)
                *ret = json_variant_ref(parameters);

        return 0;
}

int varlink_validate(VarlinkConcept *concept, JsonVariant *parameters, JsonVariant **ret) {
        assert(concept);

        /* Fill in unset fields */
        if (!parameters) {

                /* If there's no default value defined, we insist on the field being around. Also, if we are called
                 * with ret = NULL we check that all fields mentioned exist, and in that also generate an error. This
                 * is used when checking the default values themselves. */

                if (!ret || !concept->def)
                        return -ENOMEDIUM;

                *ret = json_variant_ref(concept->def);
                return 0;
        }

        /* All fields are nullable */
        if (json_variant_is_null(parameters)) {

                if (ret)
                        *ret = json_variant_ref(parameters);

                return 0;
        }

        switch (concept->type) {

        case VARLINK_CONCEPT_DATA: /* FIXME */
        case VARLINK_CONCEPT_STRING:
                if (!json_variant_is_string(parameters))
                        return -ENOEXEC;

                break;

        case VARLINK_CONCEPT_INT:
                if (!json_variant_is_integer(parameters))
                        return -ENOEXEC;

                break;

        case VARLINK_CONCEPT_FLOAT:
                if (!json_variant_is_real(parameters))
                        return -ENOEXEC;

                break;

        case VARLINK_CONCEPT_BOOL:
                if (!json_variant_is_boolean(parameters))
                        return -ENOEXEC;

                break;

        case VARLINK_CONCEPT_FOREIGN:
                break;

        case VARLINK_CONCEPT_OBJECT:
                return varlink_validate_object(concept, parameters, ret);

        case VARLINK_CONCEPT_ENUM:
                return varlink_validate_enum(concept, parameters, ret);

        case VARLINK_CONCEPT_REFERENCE:
                return varlink_validate(concept->concept_reference.reference, parameters, ret);

        default:
                assert_not_reached("Unexpected concept");
        }

        if (ret)
                *ret = json_variant_ref(parameters);

        return 0;
}

int varlink_validate_method(VarlinkConcept *concept, JsonVariant *parameters, JsonVariant **ret) {
        assert(concept);
        assert(parameters);

        assert(concept->type == VARLINK_CONCEPT_METHOD);

        return varlink_validate(concept->concept_method.input, parameters, ret);
}

int varlink_validate_reply(VarlinkConcept *concept, JsonVariant *parameters, JsonVariant **ret) {
        assert(concept);
        assert(parameters);

        assert(concept->type == VARLINK_CONCEPT_METHOD);

        return varlink_validate(concept->concept_method.output, parameters, ret);
}

int varlink_validate_error(VarlinkConcept *concept, JsonVariant *parameters, JsonVariant **ret) {
        assert(concept);
        assert(parameters);

        assert(concept->type == VARLINK_CONCEPT_ERROR);

        return varlink_validate(concept->concept_error.parameters, parameters, ret);
}
