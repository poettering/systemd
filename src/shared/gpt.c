/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "gpt.h"
#include "string-util.h"
#include "utf8.h"

const GptPartitionType gpt_partition_type_table[] = {
        { GPT_ROOT_X86,              "root-x86",              GPT_FLAG_READ_ONLY|GPT_FLAG_NO_AUTO },
        { GPT_ROOT_X86_VERITY,       "root-x86-verity",       GPT_FLAG_READ_ONLY|GPT_FLAG_NO_AUTO },
        { GPT_ROOT_X86_64,           "root-x86-64",           GPT_FLAG_READ_ONLY|GPT_FLAG_NO_AUTO },
        { GPT_ROOT_X86_64_VERITY,    "root-x86-64-verity",    GPT_FLAG_READ_ONLY|GPT_FLAG_NO_AUTO },
        { GPT_ROOT_ARM,              "root-arm",              GPT_FLAG_READ_ONLY|GPT_FLAG_NO_AUTO },
        { GPT_ROOT_ARM_VERITY,       "root-arm-verity",       GPT_FLAG_READ_ONLY|GPT_FLAG_NO_AUTO },
        { GPT_ROOT_ARM_64,           "root-arm64",            GPT_FLAG_READ_ONLY|GPT_FLAG_NO_AUTO },
        { GPT_ROOT_ARM_64_VERITY,    "root-arm64-verity",     GPT_FLAG_READ_ONLY|GPT_FLAG_NO_AUTO },
        { GPT_ROOT_IA64,             "root-ia64",             GPT_FLAG_READ_ONLY|GPT_FLAG_NO_AUTO },
        { GPT_ROOT_IA64_VERITY,      "root-ia64-verity",      GPT_FLAG_READ_ONLY|GPT_FLAG_NO_AUTO },
        { GPT_ROOT_RISCV32,          "root-riscv32",          GPT_FLAG_READ_ONLY|GPT_FLAG_NO_AUTO },
        { GPT_ROOT_RISCV32_VERITY,   "root-riscv32-verity",   GPT_FLAG_READ_ONLY|GPT_FLAG_NO_AUTO },
        { GPT_ROOT_RISCV64,          "root-riscv64",          GPT_FLAG_READ_ONLY|GPT_FLAG_NO_AUTO },
        { GPT_ROOT_RISCV64_VERITY,   "root-riscv64-verity",   GPT_FLAG_READ_ONLY|GPT_FLAG_NO_AUTO },
#ifdef GPT_ROOT_NATIVE
        { GPT_ROOT_NATIVE,           "root",                  GPT_FLAG_READ_ONLY|GPT_FLAG_NO_AUTO },
        { GPT_ROOT_NATIVE_VERITY,    "root-verity",           GPT_FLAG_READ_ONLY|GPT_FLAG_NO_AUTO },
#endif
#ifdef GPT_ROOT_SECONDARY
        { GPT_ROOT_SECONDARY,        "root-secondary",        GPT_FLAG_READ_ONLY|GPT_FLAG_NO_AUTO },
        { GPT_ROOT_SECONDARY_VERITY, "root-secondary-verity", GPT_FLAG_READ_ONLY|GPT_FLAG_NO_AUTO },
#endif
        { GPT_USR_X86,               "usr-x86",               GPT_FLAG_READ_ONLY|GPT_FLAG_NO_AUTO },
        { GPT_USR_X86_VERITY,        "usr-x86-verity",        GPT_FLAG_READ_ONLY|GPT_FLAG_NO_AUTO },
        { GPT_USR_X86_64,            "usr-x86-64",            GPT_FLAG_READ_ONLY|GPT_FLAG_NO_AUTO },
        { GPT_USR_X86_64_VERITY,     "usr-x86-64-verity",     GPT_FLAG_READ_ONLY|GPT_FLAG_NO_AUTO },
        { GPT_USR_ARM,               "usr-arm",               GPT_FLAG_READ_ONLY|GPT_FLAG_NO_AUTO },
        { GPT_USR_ARM_VERITY,        "usr-arm-verity",        GPT_FLAG_READ_ONLY|GPT_FLAG_NO_AUTO },
        { GPT_USR_ARM_64,            "usr-arm64",             GPT_FLAG_READ_ONLY|GPT_FLAG_NO_AUTO },
        { GPT_USR_ARM_64_VERITY,     "usr-arm64-verity",      GPT_FLAG_READ_ONLY|GPT_FLAG_NO_AUTO },
        { GPT_USR_IA64,              "usr-ia64",              GPT_FLAG_READ_ONLY|GPT_FLAG_NO_AUTO },
        { GPT_USR_IA64_VERITY,       "usr-ia64-verity",       GPT_FLAG_READ_ONLY|GPT_FLAG_NO_AUTO },
        { GPT_USR_RISCV32,           "usr-riscv32",           GPT_FLAG_READ_ONLY|GPT_FLAG_NO_AUTO },
        { GPT_USR_RISCV32_VERITY,    "usr-riscv32-verity",    GPT_FLAG_READ_ONLY|GPT_FLAG_NO_AUTO },
        { GPT_USR_RISCV64,           "usr-riscv64",           GPT_FLAG_READ_ONLY|GPT_FLAG_NO_AUTO },
        { GPT_USR_RISCV64_VERITY,    "usr-riscv64-verity",    GPT_FLAG_READ_ONLY|GPT_FLAG_NO_AUTO },
#ifdef GPT_USR_NATIVE
        { GPT_USR_NATIVE,            "usr",                   GPT_FLAG_READ_ONLY|GPT_FLAG_NO_AUTO },
        { GPT_USR_NATIVE_VERITY,     "usr-verity",            GPT_FLAG_READ_ONLY|GPT_FLAG_NO_AUTO },
#endif
#ifdef GPT_USR_SECONDARY
        { GPT_USR_SECONDARY,         "usr-secondary",         GPT_FLAG_READ_ONLY|GPT_FLAG_NO_AUTO },
        { GPT_USR_SECONDARY_VERITY,  "usr-secondary-verity",  GPT_FLAG_READ_ONLY|GPT_FLAG_NO_AUTO },
#endif
        { GPT_ESP,                   "esp",                   0                                   },
        { GPT_XBOOTLDR,              "xbootldr",              GPT_FLAG_READ_ONLY|GPT_FLAG_NO_AUTO },
        { GPT_SWAP,                  "swap",                  GPT_FLAG_READ_ONLY|GPT_FLAG_NO_AUTO },
        { GPT_HOME,                  "home",                  GPT_FLAG_READ_ONLY|GPT_FLAG_NO_AUTO },
        { GPT_SRV,                   "srv",                   GPT_FLAG_READ_ONLY|GPT_FLAG_NO_AUTO },
        { GPT_VAR,                   "var",                   GPT_FLAG_READ_ONLY|GPT_FLAG_NO_AUTO },
        { GPT_TMP,                   "tmp",                   GPT_FLAG_READ_ONLY|GPT_FLAG_NO_AUTO },
        { GPT_USER_HOME,             "user-home",             0                                   },
        { GPT_LINUX_GENERIC,         "linux-generic",         0                                   },
        {} /* we export this table, hence keep a marker at the end, since ELEMENTSOF() won't work outside of this file */
};

const char *gpt_partition_type_uuid_to_string(sd_id128_t id) {
        for (size_t i = 0; i < ELEMENTSOF(gpt_partition_type_table) - 1; i++)
                if (sd_id128_equal(id, gpt_partition_type_table[i].uuid))
                        return gpt_partition_type_table[i].name;

        return NULL;
}

uint64_t gpt_partition_type_uuid_to_supported_flags(sd_id128_t id) {
        for (size_t i = 0; i < ELEMENTSOF(gpt_partition_type_table) - 1; i++)
                if (sd_id128_equal(id, gpt_partition_type_table[i].uuid))
                        return gpt_partition_type_table[i].supported_flags;

        return 0;
}

const char *gpt_partition_type_uuid_to_string_harder(
                sd_id128_t id,
                char buffer[static ID128_UUID_STRING_MAX]) {

        const char *s;

        assert(buffer);

        s = gpt_partition_type_uuid_to_string(id);
        if (s)
                return s;

        return id128_to_uuid_string(id, buffer);
}

int gpt_partition_type_uuid_from_string(const char *s, sd_id128_t *ret) {
        assert(s);
        assert(ret);

        for (size_t i = 0; i < ELEMENTSOF(gpt_partition_type_table) - 1; i++)
                if (streq(s, gpt_partition_type_table[i].name)) {
                        *ret = gpt_partition_type_table[i].uuid;
                        return 0;
                }

        return sd_id128_from_string(s, ret);
}

int gpt_partition_label_valid(const char *s) {
        _cleanup_free_ char16_t *recoded = NULL;

        recoded = utf8_to_utf16(s, strlen(s));
        if (!recoded)
                return -ENOMEM;

        return char16_strlen(recoded) <= 36;
}
