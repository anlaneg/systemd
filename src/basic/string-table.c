/* SPDX-License-Identifier: LGPL-2.1+ */

#include "string-table.h"
#include "string-util.h"

//给出表table,其长度为len,在其中查找key,找到后，返回对应的array的下标
ssize_t string_table_lookup(const char * const *table, size_t len, const char *key) {
        size_t i;

        if (!key)
                return -1;

        for (i = 0; i < len; ++i)
                if (streq_ptr(table[i], key))
                        return (ssize_t) i;

        return -1;
}
