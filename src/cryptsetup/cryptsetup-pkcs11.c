/* SPDX-License-Identifier: LGPL-2.1+ */

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include <p11-kit/p11-kit.h>
#include <p11-kit/uri.h>

#include "alloc-util.h"
#include "ask-password-api.h"
#include "cryptsetup-pkcs11.h"
#include "escape.h"
#include "fd-util.h"
#include "macro.h"
#include "memory-util.h"
#include "stat-util.h"
#include "strv.h"

DEFINE_TRIVIAL_CLEANUP_FUNC(P11KitUri*, p11_kit_uri_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(CK_FUNCTION_LIST**, p11_kit_modules_finalize_and_release);

static int token_login(
                const char *friendly_name,
                CK_FUNCTION_LIST *m,
                CK_SESSION_HANDLE session,
                CK_SLOT_ID slotid,
                const CK_TOKEN_INFO *token_info,
                const char *token_uri_string,
                const char *token_label,
                usec_t until) {

        _cleanup_free_ char *token_uri_escaped = NULL, *id = NULL;
        CK_TOKEN_INFO updated_token_info;
        CK_RV rv;
        int r;

        assert(friendly_name);
        assert(m);
        assert(token_info);
        assert(token_uri_string);
        assert(token_label);

        if (FLAGS_SET(token_info->flags, CKF_PROTECTED_AUTHENTICATION_PATH)) {
                rv = m->C_Login(session, CKU_USER, NULL, 0);
                if (rv != CKR_OK)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to log into security token '%s': %s", token_label, p11_kit_strerror(rv));

                log_info("Successully logged into security token '%s' via protected authentication path.", token_label);
                return 0;
        }

        if (!FLAGS_SET(token_info->flags, CKF_LOGIN_REQUIRED)) {
                log_info("No login into security token '%s' required.", token_label);
                return 0;
        }

        token_uri_escaped = cescape(token_uri_string);
        if (!token_uri_escaped)
                return log_oom();

        id = strjoin("pkcs11:", token_uri_escaped);
        if (!id)
                return log_oom();

        for (unsigned tries = 0; tries < 3; tries++) {
                _cleanup_strv_free_erase_ char **passwords = NULL;
                _cleanup_free_ char *text = NULL;
                char **i;

                if (FLAGS_SET(token_info->flags, CKF_USER_PIN_FINAL_TRY))
                        r = asprintf(&text, "Please enter correct PIN for security token '%s' in order to unlock disk %s (final try):", token_label, friendly_name);
                if (FLAGS_SET(token_info->flags, CKF_USER_PIN_COUNT_LOW))
                        r = asprintf(&text, "PIN has been entered incorrectly previously, please enter correct PIN for security token '%s' in order to unlock disk %s:", token_label, friendly_name);
                else if (tries == 0)
                        r = asprintf(&text, "Please enter PIN for security token '%s' in order to unlock disk %s:", token_label, friendly_name);
                else
                        r = asprintf(&text, "Please enter PIN for security token '%s' in order to unlock disk %s (try #%u):", token_label, friendly_name, tries+1);
                if (r < 0)
                        return log_oom();

                /* We never cache PINs, simply because it's fatal if we use wrong PINs, since usually there are only 3 tries */
                r = ask_password_auto(text, "drive-harddisk", id, "pkcs11-pin", until, 0, &passwords);
                if (r < 0)
                        return log_error_errno(r, "Failed to query PIN for security token '%s': %m", token_label);

                STRV_FOREACH(i, passwords) {
                        rv = m->C_Login(session, CKU_USER, (CK_UTF8CHAR*) *i, strlen(*i));
                        if (rv == CKR_OK)  {
                                log_info("Successfully logged into security token '%s'.", token_label);
                                return 0;
                        }
                        if (rv == CKR_PIN_LOCKED)
                                return log_error_errno(SYNTHETIC_ERRNO(EPERM), "PIN has been locked, please reset PIN of security token '%s'.", token_label);
                        if (!IN_SET(rv, CKR_PIN_INCORRECT, CKR_PIN_LEN_RANGE))
                                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to log into security token '%s': %s", token_label, p11_kit_strerror(rv));

                        /* Referesh the token info, so that we can prompt knowing the new flags if they changed. */
                        rv = m->C_GetTokenInfo(slotid, &updated_token_info);
                        if (rv != CKR_OK)
                                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to acquire updated security token information for slot %lu: %s", slotid, p11_kit_strerror(rv));

                        token_info = &updated_token_info;
                        log_notice("PIN for token '%s' is incorrect, please try again.", token_label);
                }
        }

        return log_error_errno(SYNTHETIC_ERRNO(EPERM), "Too many attempts to log into token '%s'.", token_label);
}

static int token_find_private_key(
                CK_FUNCTION_LIST *m,
                CK_SESSION_HANDLE session,
                P11KitUri *search_uri,
                CK_OBJECT_HANDLE *ret_object) {

        bool found_decrypt = false, found_class = false, found_key_type = false;
        _cleanup_free_ CK_ATTRIBUTE *attributes_buffer = NULL;
        CK_ULONG n_attributes, a, n_objects;
        CK_ATTRIBUTE *attributes = NULL;
        CK_OBJECT_HANDLE objects[2];
        CK_RV rv, rv2;

        assert(m);
        assert(search_uri);
        assert(ret_object);

        attributes = p11_kit_uri_get_attributes(search_uri, &n_attributes);
        for (a = 0; a < n_attributes; a++) {

                /* We use the URI's included match attributes, but make them more strict. This allows users
                 * to specify a token URL instead of an object URL and the right thing should happen if
                 * there's only one suitable key on the token. */

                switch (attributes[a].type) {

                case CKA_CLASS: {
                        CK_OBJECT_CLASS c;

                        if (attributes[a].ulValueLen != sizeof(c))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid PKCS#11 CKA_CLASS attribute size.");

                        memcpy(&c, attributes[a].pValue, sizeof(c));
                        if (c != CKO_PRIVATE_KEY)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Selected PKCS#11 object is not a private key, refusing.");

                        found_class = true;
                        break;
                }

                case CKA_DECRYPT: {
                        CK_BBOOL b;

                        if (attributes[a].ulValueLen != sizeof(b))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid PKCS#11 CKA_DECRYPT attribute size.");

                        memcpy(&b, attributes[a].pValue, sizeof(b));
                        if (!b)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Selected PKCS#11 object is not suitable for decryption, refusing.");

                        found_decrypt = true;
                        break;
                }

                case CKA_KEY_TYPE: {
                        CK_KEY_TYPE t;

                        if (attributes[a].ulValueLen != sizeof(t))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid PKCS#11 CKA_KEY_TYPE attribute size.");

                        memcpy(&t, attributes[a].pValue, sizeof(t));
                        if (t != CKK_RSA)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Selected PKCS#11 object is not an RSA key, refusing.");

                        found_key_type = true;
                        break;
                }}
        }

        if (!found_decrypt || !found_class || !found_key_type) {
                /* Hmm, let's slightly extend the attribute list we search for */

                attributes_buffer = new(CK_ATTRIBUTE, n_attributes + !found_decrypt + !found_class + !found_key_type);
                if (!attributes_buffer)
                        return log_oom();

                memcpy(attributes_buffer, attributes, sizeof(CK_ATTRIBUTE) * n_attributes);

                if (!found_decrypt) {
                        static const CK_BBOOL yes = true;

                        attributes_buffer[n_attributes++] = (CK_ATTRIBUTE) {
                                .type = CKA_DECRYPT,
                                .pValue = (CK_BBOOL*) &yes,
                                .ulValueLen = sizeof(yes),
                        };
                }

                if (!found_class) {
                        static const CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;

                        attributes_buffer[n_attributes++] = (CK_ATTRIBUTE) {
                                .type = CKA_CLASS,
                                .pValue = (CK_OBJECT_CLASS*) &class,
                                .ulValueLen = sizeof(class),
                        };
                }

                if (!found_key_type) {
                        static const CK_KEY_TYPE type = CKK_RSA;

                        attributes_buffer[n_attributes++] = (CK_ATTRIBUTE) {
                                .type = CKA_KEY_TYPE,
                                .pValue = (CK_KEY_TYPE*) &type,
                                .ulValueLen = sizeof(type),
                        };
                }

                attributes = attributes_buffer;
        }

        rv = m->C_FindObjectsInit(session, attributes, n_attributes);
        if (rv != CKR_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to initialize object find call: %s", p11_kit_strerror(rv));

        rv = m->C_FindObjects(session, objects, ELEMENTSOF(objects), &n_objects);
        rv2 = m->C_FindObjectsFinal(session);
        if (rv != CKR_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to search objects: %s", p11_kit_strerror(rv));
        if (rv2 != CKR_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to finalize object find call: %s", p11_kit_strerror(rv));
        if (n_objects == 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "Failed to find selected private key suitable for decryption on token.");
        if (n_objects > 1)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTUNIQ), "Configured private key URI matches multiple keys, refusing.");

        *ret_object = objects[0];
        return 0;
}

static int token_decrypt_our_key(
                CK_FUNCTION_LIST *m,
                CK_SESSION_HANDLE session,
                CK_OBJECT_HANDLE object,
                const char *token_label,
                const void *encrypted_key,
                size_t encrypted_key_size,
                void **ret_decrypted_key,
                size_t *ret_decrypted_key_size) {

        static const CK_MECHANISM mechanism = {
                 .mechanism = CKM_RSA_PKCS
        };
        _cleanup_(erase_and_freep) CK_BYTE *dbuffer = NULL;
        CK_ULONG dbuffer_size = 0;
        CK_RV rv;

        assert(m);
        assert(encrypted_key);
        assert(encrypted_key_size > 0);
        assert(ret_decrypted_key);
        assert(ret_decrypted_key_size);

        rv = m->C_DecryptInit(session, (CK_MECHANISM*) &mechanism, object);
        if (rv != CKR_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to initialize decryption on security token '%s': %s", token_label, p11_kit_strerror(rv));

        dbuffer_size = encrypted_key_size; /* Start with something reasonable */
        dbuffer = malloc(dbuffer_size);
        if (!dbuffer)
                return log_oom();

        rv = m->C_Decrypt(session, (CK_BYTE*) encrypted_key, encrypted_key_size, dbuffer, &dbuffer_size);
        if (rv == CKR_BUFFER_TOO_SMALL) {
                erase_and_free(dbuffer);

                dbuffer = malloc(dbuffer_size);
                if (!dbuffer)
                        return log_oom();

                rv = m->C_Decrypt(session, (CK_BYTE*) encrypted_key, encrypted_key_size, dbuffer, &dbuffer_size);
        }
        if (rv != CKR_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to decrypt key on security token '%s': %s", token_label, p11_kit_strerror(rv));

        log_info("Successfully decrypted key with security token '%s'.", token_label);

        *ret_decrypted_key = TAKE_PTR(dbuffer);
        *ret_decrypted_key_size = dbuffer_size;
        return 0;
}

static int token_process(
                const char *friendly_name,
                CK_FUNCTION_LIST *m,
                CK_SLOT_ID slotid,
                const CK_TOKEN_INFO *token_info,
                const char *token_uri_string,
                P11KitUri *search_uri,
                const void *encrypted_key,
                size_t encrypted_key_size,
                usec_t until,
                void **ret_decrypted_key,
                size_t *ret_decrypted_key_size) {

        _cleanup_free_ char *token_label = NULL;
        CK_SESSION_HANDLE session;
        CK_OBJECT_HANDLE object;
        CK_RV rv;
        int r;

        assert(friendly_name);
        assert(m);
        assert(token_info);
        assert(token_uri_string);
        assert(search_uri);
        assert(encrypted_key);
        assert(encrypted_key_size > 0);
        assert(ret_decrypted_key);
        assert(ret_decrypted_key_size);

        /* The label is not NUL terminated and likely padded with spaces, let's make a copy here, so that we can strip that. */
        token_label = strndup((char*) token_info->label, sizeof(token_info->label));
        if (!token_label)
                return log_oom();

        strstrip(token_label);

        rv = m->C_OpenSession(slotid, CKF_SERIAL_SESSION, NULL, NULL, &session);
        if (rv != CKR_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to create session for security token '%s': %s", token_label, p11_kit_strerror(rv));

        r = token_login(friendly_name, m, session, slotid, token_info, token_uri_string, token_label, until);
        if (r < 0)
                goto finish;

        r = token_find_private_key(m, session, search_uri, &object);
        if (r < 0)
                goto finish;

        r = token_decrypt_our_key(m, session, object, token_label, encrypted_key, encrypted_key_size, ret_decrypted_key, ret_decrypted_key_size);
        if (r < 0)
                goto finish;

        r = 1;

finish:
        rv = m->C_CloseSession(session);
        if (rv != CKR_OK)
                log_warning_errno(SYNTHETIC_ERRNO(rv), "Failed to close session on PKCS#11 token, ignoring: %s", p11_kit_strerror(rv));

        return r;
}

static int uri_from_string(const char *p, P11KitUri **ret) {
        _cleanup_(p11_kit_uri_freep) P11KitUri *uri = NULL;

        assert(p);
        assert(ret);

        uri = p11_kit_uri_new();
        if (!uri)
                return -ENOMEM;

        if (p11_kit_uri_parse(p, P11_KIT_URI_FOR_ANY, uri) != P11_KIT_URI_OK)
                return -EINVAL;

        *ret = TAKE_PTR(uri);
        return 0;
}

static P11KitUri *uri_from_module_info(const CK_INFO *info) {
        P11KitUri *uri;

        assert(info);

        uri = p11_kit_uri_new();
        if (!uri)
                return NULL;

        *p11_kit_uri_get_module_info(uri) = *info;
        return uri;
}

static P11KitUri *uri_from_slot_info(const CK_SLOT_INFO *slot_info) {
        P11KitUri *uri;

        assert(slot_info);

        uri = p11_kit_uri_new();
        if (!uri)
                return NULL;

        *p11_kit_uri_get_slot_info(uri) = *slot_info;
        return uri;
}

static P11KitUri *uri_from_token_info(const CK_TOKEN_INFO *token_info) {
        P11KitUri *uri;

        assert(token_info);

        uri = p11_kit_uri_new();
        if (!uri)
                return NULL;

        *p11_kit_uri_get_token_info(uri) = *token_info;
        return uri;
}

static int slot_process(
                const char *friendly_name,
                CK_FUNCTION_LIST *m,
                CK_SLOT_ID slotid,
                P11KitUri *search_uri,
                const void *encrypted_key,
                size_t encrypted_key_size,
                usec_t until,
                void **ret_decrypted_key,
                size_t *ret_decrypted_key_size) {

        _cleanup_(p11_kit_uri_freep) P11KitUri* slot_uri = NULL, *token_uri = NULL;
        _cleanup_free_ char *token_uri_string = NULL;
        CK_TOKEN_INFO token_info;
        CK_SLOT_INFO slot_info;
        int uri_result;
        CK_RV rv;

        assert(friendly_name);
        assert(m);
        assert(search_uri);
        assert(encrypted_key);
        assert(encrypted_key_size > 0);
        assert(ret_decrypted_key);
        assert(ret_decrypted_key_size);

        /* We return -EAGAIN for all failures we can attribute to a specific slot in some way, so that the
         * caller might try other slots before giving up. */

        rv = m->C_GetSlotInfo(slotid, &slot_info);
        if (rv != CKR_OK) {
                log_warning("Failed to acquire slot info for slot %lu, ignoring slot: %s", slotid, p11_kit_strerror(rv));
                return -EAGAIN;
        }

        slot_uri = uri_from_slot_info(&slot_info);
        if (!slot_uri)
                return log_oom();

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *slot_uri_string = NULL;

                uri_result = p11_kit_uri_format(slot_uri, P11_KIT_URI_FOR_ANY, &slot_uri_string);
                if (uri_result != P11_KIT_URI_OK) {
                        log_warning("Failed to format slot URI, ignoring slot: %s", p11_kit_uri_message(uri_result));
                        return -EAGAIN;
                }

                log_debug("Found slot with URI %s", slot_uri_string);
        }

        rv = m->C_GetTokenInfo(slotid, &token_info);
        if (rv == CKR_TOKEN_NOT_PRESENT) {
                log_debug("Token not present in slot, ignoring.");
                return -EAGAIN;
        } else if (rv != CKR_OK) {
                log_warning("Failed to acquire token info for slot %lu, ignoring slot: %s", slotid, p11_kit_strerror(rv));
                return -EAGAIN;
        }

        token_uri = uri_from_token_info(&token_info);
        if (!token_uri)
                return log_oom();

        uri_result = p11_kit_uri_format(token_uri, P11_KIT_URI_FOR_ANY, &token_uri_string);
        if (uri_result != P11_KIT_URI_OK) {
                log_warning("Failed to format slot URI: %s", p11_kit_uri_message(uri_result));
                return -EAGAIN;
        }

        if (!p11_kit_uri_match_token_info(search_uri, &token_info)) {
                log_debug("Found non-matching token with URI %s.", token_uri_string);
                return -EAGAIN;
        }

        log_debug("Found matching token with URI %s.", token_uri_string);

        return token_process(
                        friendly_name,
                        m,
                        slotid,
                        &token_info,
                        token_uri_string,
                        search_uri,
                        encrypted_key, encrypted_key_size,
                        until,
                        ret_decrypted_key, ret_decrypted_key_size);
}

static int module_process(
                const char *friendly_name,
                CK_FUNCTION_LIST *m,
                P11KitUri *search_uri,
                const void *encrypted_key,
                size_t encrypted_key_size,
                usec_t until,
                void **ret_decrypted_key,
                size_t *ret_decrypted_key_size) {

        _cleanup_free_ char *name = NULL, *module_uri_string = NULL;
        _cleanup_(p11_kit_uri_freep) P11KitUri* module_uri = NULL;
        _cleanup_free_ CK_SLOT_ID *slotids = NULL;
        CK_ULONG n_slotids = 0;
        int uri_result;
        CK_INFO info;
        size_t k;
        CK_RV rv;
        int r;

        /* We ignore most errors from modules here, in order to skip over faulty modules: one faulty module
         * should not have the effect that we don't try the others anymore. We indicate such per-module
         * failures with -EAGAIN, which let's the caller try the next module. */

        name = p11_kit_module_get_name(m);
        if (!name)
                return log_oom();

        log_debug("Trying PKCS#11 module %s.", name);

        rv = m->C_GetInfo(&info);
        if (rv != CKR_OK) {
                log_warning("Failed to get info on PKCS#11 module, ignoring module: %s", p11_kit_strerror(rv));
                return -EAGAIN;
        }

        module_uri = uri_from_module_info(&info);
        if (!module_uri)
                return log_oom();

        uri_result = p11_kit_uri_format(module_uri, P11_KIT_URI_FOR_ANY, &module_uri_string);
        if (uri_result != P11_KIT_URI_OK) {
                log_warning("Failed to format module URI, ignoring module: %s", p11_kit_uri_message(uri_result));
                return -EAGAIN;
        }

        log_debug("Found module with URI %s", module_uri_string);

        for (unsigned tries = 0; tries < 16; tries++) {
                slotids = mfree(slotids);
                n_slotids = 0;

                rv = m->C_GetSlotList(0, NULL, &n_slotids);
                if (rv != CKR_OK) {
                        log_warning("Failed to get slot list size, ignoring module: %s", p11_kit_strerror(rv));
                        n_slotids = 0;
                        break;
                }
                if (n_slotids == 0) {
                        log_debug("This module has no slots? Ignoring module.");
                        break;
                }

                slotids = new(CK_SLOT_ID, n_slotids);
                if (!slotids)
                        return log_oom();

                rv = m->C_GetSlotList(0, slotids, &n_slotids);
                if (rv == CKR_OK)
                        break;
                n_slotids = 0;
                if (rv != CKR_BUFFER_TOO_SMALL) {
                        log_warning("Failed to acquire slot list, ignoring module: %s", p11_kit_strerror(rv));
                        break;
                }

                /* Hu? Maybe somebody plugged something in and things changed? Let's try again */
        }

        if (n_slotids == 0)
                return -EAGAIN;

        for (k = 0; k < n_slotids; k++) {
                r = slot_process(
                                friendly_name,
                                m,
                                slotids[k],
                                search_uri,
                                encrypted_key, encrypted_key_size,
                                until,
                                ret_decrypted_key, ret_decrypted_key_size);
                if (r != -EAGAIN)
                        return r;
        }

        return -EAGAIN;
}

static int load_key_file(
                const char *key_file,
                size_t key_file_size,
                uint64_t key_file_offset,
                void **ret_encrypted_key,
                size_t *ret_encrypted_key_size) {

        _cleanup_(erase_and_freep) char *buffer = NULL;
        _cleanup_close_ int fd = -1;
        ssize_t n;
        int r;

        assert(key_file);
        assert(ret_encrypted_key);
        assert(ret_encrypted_key_size);

        fd = open(key_file, O_RDONLY|O_CLOEXEC);
        if (fd < 0)
                return log_error_errno(errno, "Failed to load encrypted PKCS#11 key: %m");

        if (key_file_size == 0) {
                struct stat st;

                if (fstat(fd, &st) < 0)
                        return log_error_errno(errno, "Failed to stat key file: %m");

                r = stat_verify_regular(&st);
                if (r < 0)
                        return log_error_errno(r, "Key file is not a regular file: %m");

                if (st.st_size == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Key file is empty, refusing.");
                if ((uint64_t) st.st_size > SIZE_MAX)
                        return log_error_errno(SYNTHETIC_ERRNO(ERANGE), "Key file too large, refsing.");

                if (key_file_offset >= (uint64_t) st.st_size)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Key file offset too large for file, refusing.");

                key_file_size = st.st_size - key_file_offset;
        }

        buffer = malloc(key_file_size);
        if (!buffer)
                return log_oom();

        if (key_file_offset > 0)
                n = pread(fd, buffer, key_file_size, key_file_offset);
        else
                n = read(fd, buffer, key_file_size);
        if (n < 0)
                return log_error_errno(errno, "Failed to read PKCS#11 key file: %m");
        if (n == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Empty encrypted key found, refusing.");

        *ret_encrypted_key = TAKE_PTR(buffer);
        *ret_encrypted_key_size = (size_t) n;

        return 0;
}

int acquire_pkcs11_key(
                const char *friendly_name,
                const char *pkcs11_uri,
                const char *key_file,
                size_t key_file_size,
                uint64_t key_file_offset,
                usec_t until,
                void **ret_decrypted_key,
                size_t *ret_decrypted_key_size) {

        _cleanup_(p11_kit_modules_finalize_and_releasep) CK_FUNCTION_LIST **modules = NULL;
        _cleanup_(p11_kit_uri_freep) P11KitUri *search_uri = NULL;
        _cleanup_(erase_and_freep) void *encrypted_key = NULL;
        size_t encrypted_key_size;
        int r;

        assert(friendly_name);
        assert(pkcs11_uri);
        assert(key_file);
        assert(ret_decrypted_key);
        assert(ret_decrypted_key_size);

        r = load_key_file(key_file, key_file_size, key_file_offset, &encrypted_key, &encrypted_key_size);
        if (r < 0)
                return r;

        r = uri_from_string(pkcs11_uri, &search_uri);
        if (r < 0)
                return log_error_errno(r, "Failed to parse PKCS#11 URI '%s': %m", pkcs11_uri);

        modules = p11_kit_modules_load_and_initialize(0);
        if (!modules)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to initialize pkcs11 modules");

        for (CK_FUNCTION_LIST **i = modules; *i; i++) {
                r = module_process(
                                friendly_name,
                                *i,
                                search_uri,
                                encrypted_key,
                                encrypted_key_size,
                                until,
                                ret_decrypted_key,
                                ret_decrypted_key_size);
                if (r != -EAGAIN)
                        return r;
        }

        return -EAGAIN;
}
