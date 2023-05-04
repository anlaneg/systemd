/* SPDX-License-Identifier: LGPL-2.1+ */

#include <stdint.h>
#include <string.h>

#include "alloc-util.h"
#include "macro.h"
#include "util.h"

void* memdup(const void *p, size_t l) {
        void *ret;

        assert(l == 0 || p);

        ret = malloc(l ?: 1);
        if (!ret)
                return NULL;

        memcpy(ret, p, l);
        return ret;
}

void* memdup_suffix0(const void *p, size_t l) {
        void *ret;

        assert(l == 0 || p);

        /* The same as memdup() but place a safety NUL byte after the allocated memory */

        ret = malloc(l + 1);
        if (!ret)
                return NULL;

        *((uint8_t*) mempcpy(ret, p, l)) = 0;
        return ret;
}

void* greedy_realloc(void **p/*待realloc的指针*/, size_t *allocated/*当前内存长度*/, size_t need/*需要的长度*/, size_t size/*每个元素占内存大小*/) {
        size_t a, newalloc;
        void *q;

        assert(p);
        assert(allocated);

        if (*allocated >= need)
        	/*已有的超过需要的，直接返回旧的*/
                return *p;

        /*返回优化后的申请大小*/
        newalloc = MAX(need * 2, 64u / size);
        a = newalloc * size;

        /* check for overflows */
        if (a < size * need)
                return NULL;

        q = realloc(*p, a);
        if (!q)
                return NULL;

        *p = q;
        *allocated = newalloc;
        return q;
}

void* greedy_realloc0(void **p, size_t *allocated, size_t need, size_t size) {
        size_t prev;
        uint8_t *q;

        assert(p);
        assert(allocated);

        prev = *allocated;

        q = greedy_realloc(p, allocated, need, size);
        if (!q)
                return NULL;

        if (*allocated > prev)
                memzero(q + prev * size, (*allocated - prev) * size);

        return q;
}
