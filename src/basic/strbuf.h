/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "macro.h"

struct strbuf {
        char *buf;/*字符串起始位置*/
        size_t len;/*占用的字符串长度*/
        struct strbuf_node *root;/*根节点，在此树上会以字符串反序进行挂接，支持字符串复用*/

        size_t nodes_count;/*挂接在root上的strbuf_node数量*/
        size_t in_count;
        size_t in_len;
        size_t dedup_len;/*复用的字符串长度*/
        size_t dedup_count;/*复用的字符串数目*/
};

struct strbuf_node {
        size_t value_off;
        size_t value_len;

        struct strbuf_child_entry *children;/*按c成员排序的strbuf_child_entry数组*/
        uint8_t children_count;/*children数组大小*/
};

struct strbuf_child_entry {
        uint8_t c;
        struct strbuf_node *child;
};

struct strbuf* strbuf_new(void);
ssize_t strbuf_add_string_full(struct strbuf *str, const char *s, size_t len);
static inline ssize_t strbuf_add_string(struct strbuf *str, const char *s) {
        return strbuf_add_string_full(str, s, SIZE_MAX);
}
void strbuf_complete(struct strbuf *str);
struct strbuf* strbuf_free(struct strbuf *str);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct strbuf*, strbuf_free);
