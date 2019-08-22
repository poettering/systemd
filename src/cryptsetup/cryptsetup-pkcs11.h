/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <sys/types.h>

#include "time-util.h"

#if HAVE_P11KIT

int acquire_pkcs11_key(
                const char *friendly_name,
                const char *pkcs11_uri,
                const char *key_file,
                size_t key_file_size,
                uint64_t key_file_offset,
                usec_t until,
                void **ret_decrypted_key,
                size_t *ret_decrypted_key_size);

#else

static inline int acquire_pkcs11_key(
                const char *friendly_name,
                const char *pkcs11_uri,
                const char *key_file,
                size_t key_file_size,
                uint64_t key_file_offset,
                usec_t until,
                void **ret_decrypted_key,
                size_t *ret_decrypted_key_size) {

        return -EOPNOTSUPP;
}

#endif
