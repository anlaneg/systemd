/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "alloc-util.h"
#include "glob-util.h"
#include "hexdecoct.h"
#include "path-util.h"
#include "special.h"
#include "string-util.h"
#include "strv.h"
#include "unit-name.h"

/* Characters valid in a unit name. */
#define VALID_CHARS                             \
        DIGITS                                  \
        LETTERS                                 \
        ":-_.\\"

/* The same, but also permits the single @ character that may appear */
#define VALID_CHARS_WITH_AT                     \
        "@"                                     \
        VALID_CHARS

/* All chars valid in a unit name glob */
#define VALID_CHARS_GLOB                        \
        VALID_CHARS_WITH_AT                     \
        "[]!-*?"

/*检查unit名称是否有效*/
bool unit_name_is_valid(const char *n, UnitNameFlags flags) {
        const char *e, *i, *at;

        assert((flags & ~(UNIT_NAME_PLAIN|UNIT_NAME_INSTANCE|UNIT_NAME_TEMPLATE)) == 0);

        if (_unlikely_(flags == 0))
        	/*如果flags为0，则直接返回无效*/
                return false;

        //名称为空，返回无效
        if (isempty(n))
                return false;

        //名称长度过长
        if (strlen(n) >= UNIT_NAME_MAX)
                return false;

        //名称必须包含'.',但不得以'.'开头
        e = strrchr(n, '.');
        if (!e || e == n)
                return false;

        //名称中包含的后缀必须是合法的unit后缀
        if (unit_type_from_string(e + 1) < 0)
                return false;

        //校验unit名称，必须为约定的合法字符
        for (i = n, at = NULL; i < e/*'.'所在的位置*/; i++) {

                if (*i == '@' && !at)
                        at = i;//at首次出现，记录其出现的位置

                //字符只能在VALID_CHARS及'@'集合中,否则无效
                if (!strchr("@" VALID_CHARS, *i))
                        return false;
        }

        //'@'符不能是第一个
        if (at == n)
                return false;

        //如果有UNIT_NAME_PLAIN标记，则不容许包含@符号
        if (flags & UNIT_NAME_PLAIN)
                if (!at)
                        return true;

        //如果UNIT_NAME_INSTANCE标记，则＠必须存在，且必须不能位于'.'号之前
        if (flags & UNIT_NAME_INSTANCE)
                if (at && e > at + 1)
                        return true;

        //如果有unit_name_template标记，则@必须在'.'号之前
        if (flags & UNIT_NAME_TEMPLATE)
                if (at && e == at + 1)
                        return true;

        /*其它情况均无效*/
        return false;
}

bool unit_prefix_is_valid(const char *p) {

        /* We don't allow additional @ in the prefix string */

        if (isempty(p))
                return false;

        return in_charset(p, VALID_CHARS);
}

bool unit_instance_is_valid(const char *i) {

        /* The max length depends on the length of the string, so we
         * don't really check this here. */

        if (isempty(i))
                return false;

        /* We allow additional @ in the instance string, we do not
         * allow them in the prefix! */

        //检查字符串i是否合首valid_chars约束
        return in_charset(i, "@" VALID_CHARS);
}

bool unit_suffix_is_valid(const char *s) {
        if (isempty(s))
                return false;

        if (s[0] != '.')
        	/*首字符必须为'.'*/
                return false;

        if (unit_type_from_string(s + 1) < 0)
        	/*unit后缀不匹配，返回false*/
                return false;

        return true;
}

int unit_name_to_prefix(const char *n, char **ret) {
        const char *p;
        char *s;

        assert(n);
        assert(ret);

        if (!unit_name_is_valid(n, UNIT_NAME_ANY))
                return -EINVAL;

        p = strchr(n, '@');
        if (!p)
                p = strrchr(n, '.');

        assert_se(p);

        s = strndup(n, p - n);
        if (!s)
                return -ENOMEM;

        *ret = s;
        return 0;
}

//取实例名称（unit名称中@号之后，‘.'号之前的内容）
int unit_name_to_instance(const char *n, char **instance) {
        const char *p, *d;
        char *i;

        assert(n);
        assert(instance);

        if (!unit_name_is_valid(n, UNIT_NAME_ANY))
                return -EINVAL;

        /* Everything past the first @ and before the last . is the instance */
        p = strchr(n, '@');//找到'@'
        if (!p) {
                *instance = NULL;
                return 0;
        }

        p++;

        d = strrchr(p, '.');//找到'.'
        if (!d)
                return -EINVAL;

        //复制p,d之间的字符串返回
        i = strndup(p, d-p);
        if (!i)
                return -ENOMEM;

        *instance = i;
        return 1;
}

int unit_name_to_prefix_and_instance(const char *n, char **ret) {
        const char *d;
        char *s;

        assert(n);
        assert(ret);

        if (!unit_name_is_valid(n, UNIT_NAME_ANY))
                return -EINVAL;

        d = strrchr(n, '.');
        if (!d)
                return -EINVAL;

        s = strndup(n, d - n);
        if (!s)
                return -ENOMEM;

        *ret = s;
        return 0;
}

//取unit对应的类型，通过名称后缀获取，例如service
UnitType unit_name_to_type(const char *n) {
        const char *e;

        assert(n);

        if (!unit_name_is_valid(n, UNIT_NAME_ANY))
                return _UNIT_TYPE_INVALID;

        //必须要有'.'
        assert_se(e = strrchr(n, '.'));

        //返回unit对应的类型
        return unit_type_from_string(e + 1);
}

int unit_name_change_suffix(const char *n, const char *suffix, char **ret) {
        char *e, *s;
        size_t a, b;

        assert(n);
        assert(suffix);
        assert(ret);

        if (!unit_name_is_valid(n, UNIT_NAME_ANY))
                return -EINVAL;

        if (!unit_suffix_is_valid(suffix))
                return -EINVAL;

        assert_se(e = strrchr(n, '.'));

        a = e - n;
        b = strlen(suffix);

        s = new(char, a + b + 1);
        if (!s)
                return -ENOMEM;

        strcpy(mempcpy(s, n, a), suffix);
        *ret = s;

        return 0;
}

int unit_name_build(const char *prefix, const char *instance, const char *suffix, char **ret) {
        UnitType type;

        assert(prefix);
        assert(suffix);
        assert(ret);

        if (suffix[0] != '.')
                return -EINVAL;

        type = unit_type_from_string(suffix + 1);
        if (type < 0)
                return -EINVAL;

        return unit_name_build_from_type(prefix, instance, type, ret);
}

int unit_name_build_from_type(const char *prefix, const char *instance, UnitType type, char **ret) {
        const char *ut;
        char *s;

        assert(prefix);
        assert(type >= 0);
        assert(type < _UNIT_TYPE_MAX);
        assert(ret);

        if (!unit_prefix_is_valid(prefix))
                return -EINVAL;

        if (instance && !unit_instance_is_valid(instance))
                return -EINVAL;

        ut = unit_type_to_string(type);

        if (!instance)
                s = strjoin(prefix, ".", ut);
        else
                s = strjoin(prefix, "@", instance, ".", ut);
        if (!s)
                return -ENOMEM;

        *ret = s;
        return 0;
}

static char *do_escape_char(char c, char *t) {
        assert(t);

        *(t++) = '\\';
        *(t++) = 'x';
        *(t++) = hexchar(c >> 4);
        *(t++) = hexchar(c);

        return t;
}

static char *do_escape(const char *f, char *t) {
        assert(f);
        assert(t);

        /* do not create units with a leading '.', like for "/.dotdir" mount points */
        if (*f == '.') {
                t = do_escape_char(*f, t);
                f++;
        }

        for (; *f; f++) {
                if (*f == '/')
                        *(t++) = '-';
                else if (IN_SET(*f, '-', '\\') || !strchr(VALID_CHARS, *f))
                        t = do_escape_char(*f, t);
                else
                        *(t++) = *f;
        }

        return t;
}

char *unit_name_escape(const char *f) {
        char *r, *t;

        assert(f);

        r = new(char, strlen(f)*4+1);
        if (!r)
                return NULL;

        t = do_escape(f, r);
        *t = 0;

        return r;
}

int unit_name_unescape(const char *f, char **ret) {
        _cleanup_free_ char *r = NULL;
        char *t;

        assert(f);

        r = strdup(f);
        if (!r)
                return -ENOMEM;

        for (t = r; *f; f++) {
                if (*f == '-')
                        *(t++) = '/';
                else if (*f == '\\') {
                        int a, b;

                        if (f[1] != 'x')
                                return -EINVAL;

                        a = unhexchar(f[2]);
                        if (a < 0)
                                return -EINVAL;

                        b = unhexchar(f[3]);
                        if (b < 0)
                                return -EINVAL;

                        *(t++) = (char) (((uint8_t) a << 4U) | (uint8_t) b);
                        f += 3;
                } else
                        *(t++) = *f;
        }

        *t = 0;

        *ret = TAKE_PTR(r);

        return 0;
}

int unit_name_path_escape(const char *f, char **ret) {
        char *p, *s;

        assert(f);
        assert(ret);

        /*复制字符串，且内存采用alloc*/
        p = strdupa(f);
        if (!p)
                return -ENOMEM;

        path_simplify(p, false);

        if (empty_or_root(p))
        	/*路径为root或为空*/
                s = strdup("-");
        else {
                if (!path_is_normalized(p))
                        return -EINVAL;

                /* Truncate trailing slashes */
                delete_trailing_chars(p, "/");

                /* Truncate leading slashes */
                p = skip_leading_chars(p, "/");

                s = unit_name_escape(p);
        }
        if (!s)
                return -ENOMEM;

        *ret = s;
        return 0;
}

int unit_name_path_unescape(const char *f, char **ret) {
        char *s;
        int r;

        assert(f);

        if (isempty(f))
                return -EINVAL;

        if (streq(f, "-")) {
                s = strdup("/");
                if (!s)
                        return -ENOMEM;
        } else {
                char *w;

                r = unit_name_unescape(f, &w);
                if (r < 0)
                        return r;

                /* Don't accept trailing or leading slashes */
                if (startswith(w, "/") || endswith(w, "/")) {
                        free(w);
                        return -EINVAL;
                }

                /* Prefix a slash again */
                s = strappend("/", w);
                free(w);
                if (!s)
                        return -ENOMEM;

                if (!path_is_normalized(s)) {
                        free(s);
                        return -EINVAL;
                }
        }

        if (ret)
                *ret = s;
        else
                free(s);

        return 0;
}

int unit_name_replace_instance(const char *f, const char *i, char **ret) {
        const char *p, *e;
        char *s;
        size_t a, b;

        assert(f);
        assert(i);
        assert(ret);

        //f必须为有效的实例名或者模板名
        if (!unit_name_is_valid(f, UNIT_NAME_INSTANCE|UNIT_NAME_TEMPLATE))
                return -EINVAL;

        //f必须为有效的名称
        if (!unit_instance_is_valid(i))
                return -EINVAL;

        //一定包含'@',一定包含'.'
        assert_se(p = strchr(f, '@'));
        assert_se(e = strrchr(f, '.'));

        a = p - f;//到'@‘号的偏移量
        b = strlen(i);//实例名长度

        //对于字符串"XXXX@XX.XXX"，在@后添加i，申请必要的长度(含'\0')
        s = new(char, a + 1 + b + strlen(e) + 1);
        if (!s)
                return -ENOMEM;

        //1.先copy头部f,p+1范围,存入s,返回s;2.再copy　i字符串到s,返回s;3.再copy e到s
        //这个实现看起来是错的。
        strcpy(mempcpy(mempcpy(s, f, a + 1), i, b), e);

        *ret = s;
        return 0;
}

int unit_name_template(const char *f, char **ret) {
        const char *p, *e;
        char *s;
        size_t a;

        assert(f);
        assert(ret);

        if (!unit_name_is_valid(f, UNIT_NAME_INSTANCE|UNIT_NAME_TEMPLATE))
                return -EINVAL;

        assert_se(p = strchr(f, '@'));
        assert_se(e = strrchr(f, '.'));

        a = p - f;

        s = new(char, a + 1 + strlen(e) + 1);
        if (!s)
                return -ENOMEM;

        strcpy(mempcpy(s, f, a + 1), e);

        *ret = s;
        return 0;
}

int unit_name_from_path(const char *path, const char *suffix, char **ret) {
        _cleanup_free_ char *p = NULL;
        char *s = NULL;
        int r;

        assert(path);
        assert(suffix);
        assert(ret);

        if (!unit_suffix_is_valid(suffix))
                return -EINVAL;

        r = unit_name_path_escape(path, &p);
        if (r < 0)
                return r;

        /*unit名称添加后缀，并返回*/
        s = strappend(p, suffix);
        if (!s)
                return -ENOMEM;

        *ret = s;
        return 0;
}

int unit_name_from_path_instance(const char *prefix, const char *path, const char *suffix, char **ret) {
        _cleanup_free_ char *p = NULL;
        char *s;
        int r;

        assert(prefix);
        assert(path);
        assert(suffix);
        assert(ret);

        if (!unit_prefix_is_valid(prefix))
                return -EINVAL;

        if (!unit_suffix_is_valid(suffix))
                return -EINVAL;

        r = unit_name_path_escape(path, &p);
        if (r < 0)
                return r;

        s = strjoin(prefix, "@", p, suffix);
        if (!s)
                return -ENOMEM;

        *ret = s;
        return 0;
}

int unit_name_to_path(const char *name, char **ret) {
        _cleanup_free_ char *prefix = NULL;
        int r;

        assert(name);

        r = unit_name_to_prefix(name, &prefix);
        if (r < 0)
                return r;

        return unit_name_path_unescape(prefix, ret);
}

static bool do_escape_mangle(const char *f, bool allow_globs, char *t) {
        const char *valid_chars;
        bool mangled = false;

        assert(f);
        assert(t);

        /* We'll only escape the obvious characters here, to play safe.
         *
         * Returns true if any characters were mangled, false otherwise.
         */

        valid_chars = allow_globs ? VALID_CHARS_GLOB : VALID_CHARS_WITH_AT;

        for (; *f; f++)
                if (*f == '/') {
                        *(t++) = '-';
                        mangled = true;
                } else if (!strchr(valid_chars, *f)) {
                        t = do_escape_char(*f, t);
                        mangled = true;
                } else
                        *(t++) = *f;
        *t = 0;

        return mangled;
}

/**
 *  Convert a string to a unit name. /dev/blah is converted to dev-blah.device,
 *  /blah/blah is converted to blah-blah.mount, anything else is left alone,
 *  except that @suffix is appended if a valid unit suffix is not present.
 *
 *  If @allow_globs, globs characters are preserved. Otherwise, they are escaped.
 */
int unit_name_mangle_with_suffix(const char *name, UnitNameMangle flags, const char *suffix, char **ret) {
        char *s;
        int r;
        bool mangled;

        assert(name);
        assert(suffix);
        assert(ret);

        if (isempty(name)) /* We cannot mangle empty unit names to become valid, sorry. */
                return -EINVAL;

        if (!unit_suffix_is_valid(suffix))
                return -EINVAL;

        /* Already a fully valid unit name? If so, no mangling is necessary... */
        if (unit_name_is_valid(name, UNIT_NAME_ANY))
                goto good;

        /* Already a fully valid globbing expression? If so, no mangling is necessary either... */
        if ((flags & UNIT_NAME_MANGLE_GLOB) &&
            string_is_glob(name) &&
            in_charset(name, VALID_CHARS_GLOB))
                goto good;

        if (is_device_path(name)) {
                r = unit_name_from_path(name, ".device", ret);
                if (r >= 0)
                        return 1;
                if (r != -EINVAL)
                        return r;
        }

        if (path_is_absolute(name)) {
                r = unit_name_from_path(name, ".mount", ret);
                if (r >= 0)
                        return 1;
                if (r != -EINVAL)
                        return r;
        }

        s = new(char, strlen(name) * 4 + strlen(suffix) + 1);
        if (!s)
                return -ENOMEM;

        mangled = do_escape_mangle(name, flags & UNIT_NAME_MANGLE_GLOB, s);
        if (mangled)
                log_full(flags & UNIT_NAME_MANGLE_WARN ? LOG_NOTICE : LOG_DEBUG,
                         "Invalid unit name \"%s\" was escaped as \"%s\" (maybe you should use systemd-escape?)",
                         name, s);

        /* Append a suffix if it doesn't have any, but only if this is not a glob, so that we can allow "foo.*" as a
         * valid glob. */
        if ((!(flags & UNIT_NAME_MANGLE_GLOB) || !string_is_glob(s)) && unit_name_to_type(s) < 0)
                strcat(s, suffix);

        *ret = s;
        return 1;

good:
        s = strdup(name);
        if (!s)
                return -ENOMEM;

        *ret = s;
        return 0;
}

int slice_build_parent_slice(const char *slice, char **ret) {
        char *s, *dash;
        int r;

        assert(slice);
        assert(ret);

        if (!slice_name_is_valid(slice))
                return -EINVAL;

        if (streq(slice, SPECIAL_ROOT_SLICE)) {
                *ret = NULL;
                return 0;
        }

        s = strdup(slice);
        if (!s)
                return -ENOMEM;

        dash = strrchr(s, '-');
        if (dash)
                strcpy(dash, ".slice");
        else {
                r = free_and_strdup(&s, SPECIAL_ROOT_SLICE);
                if (r < 0) {
                        free(s);
                        return r;
                }
        }

        *ret = s;
        return 1;
}

int slice_build_subslice(const char *slice, const char *name, char **ret) {
        char *subslice;

        assert(slice);
        assert(name);
        assert(ret);

        if (!slice_name_is_valid(slice))
                return -EINVAL;

        if (!unit_prefix_is_valid(name))
                return -EINVAL;

        if (streq(slice, SPECIAL_ROOT_SLICE))
                subslice = strappend(name, ".slice");
        else {
                char *e;

                assert_se(e = endswith(slice, ".slice"));

                subslice = new(char, (e - slice) + 1 + strlen(name) + 6 + 1);
                if (!subslice)
                        return -ENOMEM;

                stpcpy(stpcpy(stpcpy(mempcpy(subslice, slice, e - slice), "-"), name), ".slice");
        }

        *ret = subslice;
        return 0;
}

bool slice_name_is_valid(const char *name) {
        const char *p, *e;
        bool dash = false;

        if (!unit_name_is_valid(name, UNIT_NAME_PLAIN))
                return false;

        if (streq(name, SPECIAL_ROOT_SLICE))
                return true;

        e = endswith(name, ".slice");
        if (!e)
                return false;

        for (p = name; p < e; p++) {

                if (*p == '-') {

                        /* Don't allow initial dash */
                        if (p == name)
                                return false;

                        /* Don't allow multiple dashes */
                        if (dash)
                                return false;

                        dash = true;
                } else
                        dash = false;
        }

        /* Don't allow trailing hash */
        if (dash)
                return false;

        return true;
}
