/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "alloc-util.h"
#include "strbuf.h"
#include "util.h"

/*
 * Strbuf stores given strings in a single continuous allocated memory
 * area. Identical strings are de-duplicated and return the same offset
 * as the first string stored. If the tail of a string already exists
 * in the buffer, the tail is returned.
 *
 * A trie (http://en.wikipedia.org/wiki/Trie) is used to maintain the
 * information about the stored strings.
 *
 * Example of udev rules:
 *   $ ./udevadm test .
 *   ...
 *   read rules file: /usr/lib/udev/rules.d/99-systemd.rules
 *   rules contain 196608 bytes tokens (16384 * 12 bytes), 39742 bytes strings
 *   23939 strings (207859 bytes), 20404 de-duplicated (171653 bytes), 3536 trie nodes used
 *   ...
 */

struct strbuf *strbuf_new(void) {
        struct strbuf *str;

        str = new(struct strbuf, 1);
        if (!str)
                return NULL;
        /*初始化strbuf*/
        *str = (struct strbuf) {
                .buf = new0(char, 1),
                .root = new0(struct strbuf_node, 1),/*所有成员初始化为0*/
                .len = 1,
                .nodes_count = 1,
        };
        if (!str->buf || !str->root) {
                free(str->buf);
                free(str->root);
                return mfree(str);
        }

        return str;
}

static struct strbuf_node* strbuf_node_cleanup(struct strbuf_node *node) {
        size_t i;

        for (i = 0; i < node->children_count; i++)
                strbuf_node_cleanup(node->children[i].child);
        free(node->children);
        return mfree(node);
}

/* clean up trie data, leave only the string buffer */
void strbuf_complete(struct strbuf *str) {
        if (!str)
                return;
        if (str->root)
                str->root = strbuf_node_cleanup(str->root);
}

/* clean up everything */
void strbuf_cleanup(struct strbuf *str) {
        if (!str)
                return;

        strbuf_complete(str);
        free(str->buf);
        free(str);
}

static int strbuf_children_cmp(const struct strbuf_child_entry *n1,
                               const struct strbuf_child_entry *n2) {
        return n1->c - n2->c;
}

/*通过c进行查询，构造strbuf_child_entry，并将其加入到node->children内*/
static void bubbleinsert(struct strbuf_node *node,
                         uint8_t c,
                         struct strbuf_node *node_child) {

        struct strbuf_child_entry new = {
                .c = c,
                .child = node_child,
        };
        int left = 0, right = node->children_count;

        /*二分法在node->children数组间查找new->c的位置*/
        while (right > left) {
                int middle = (right + left) / 2 ;
                if (strbuf_children_cmp(&node->children[middle], &new) <= 0)
                        left = middle + 1;
                else
                        right = middle;
        }

        /*找到插入点left,先将left位置及其之后的元素移动到后面，空出此格*/
        memmove(node->children + left + 1, node->children + left,
                sizeof(struct strbuf_child_entry) * (node->children_count - left));
        node->children[left] = new;/*存入n*/

        node->children_count++;
}

/* add string, return the index/offset into the buffer */
ssize_t strbuf_add_string(struct strbuf *str, const char *s/*字符串*/, size_t len/*字符串长度*/) {
        uint8_t c;
        struct strbuf_node *node;
        size_t depth;
        char *buf_new;
        struct strbuf_child_entry *child;
        struct strbuf_node *node_child;
        ssize_t off;

        if (!str->root)
            /*root不得为空*/
                return -EINVAL;

        /* search string; start from last character to find possibly matching tails */

        str->in_count++;
        if (len == 0) {
                str->dedup_count++;
                return 0;
        }
        str->in_len += len;

        node = str->root;
        for (depth = 0; depth <= len; depth++) {
                struct strbuf_child_entry search;

                /* match against current node */
                off = node->value_off + node->value_len - len;
                if (depth == len /*最后一个字符*/|| (node->value_len >= len/*此node字符串大于要加入的*/ && memcmp(str->buf + off, s, len) == 0)) {
                        str->dedup_len += len;
                        str->dedup_count++;
                        return off;
                }

                c = s[len - 1 - depth];/*逆序取s的元素*/

                /* lookup child node */
                search.c = c;
                child = typesafe_bsearch(&search, node->children, node->children_count, strbuf_children_cmp);
                if (!child)
                    /*c不在node->children中存在，跳出*/
                        break;
                /*在查找到的子节点中继续查询*/
                node = child->child;
        }

        /* add new string */
        buf_new = realloc(str->buf, str->len + len+1);/*增加要添加的字符串*/
        if (!buf_new)
                return -ENOMEM;
        str->buf = buf_new;
        off = str->len;
        memcpy(str->buf + off, s, len);/*在off位置，写入要填加的字符串*/
        str->len += len;
        str->buf[str->len++] = '\0';/*填字符串终止符*/

        /* new node */
        node_child = new(struct strbuf_node, 1);/*增加一个node*/
        if (!node_child)
                return -ENOMEM;
        *node_child = (struct strbuf_node) {
                .value_off = off,/*记录此字符串在buffer的起始位置*/
                .value_len = len,/*记录此字符串长度*/
        };

        /*扩充node->children数组*/
        /* extend array, add new entry, sort for bisection */
        child = reallocarray(node->children, node->children_count + 1, sizeof(struct strbuf_child_entry));
        if (!child) {
                free(node_child);
                return -ENOMEM;
        }

        str->nodes_count++;

        node->children = child;
        bubbleinsert(node, c, node_child);

        return off;
}
