/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "sd-id128.h"

#include "alloc-util.h"
#include "glob-util.h"
#include "hexdecoct.h"
#include "memory-util.h"
#include "path-util.h"
#include "random-util.h"
#include "sparse-endian.h"
#include "special.h"
#include "stdio-util.h"
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

#define LONG_UNIT_NAME_HASH_KEY SD_ID128_MAKE(ec,f2,37,fb,58,32,4a,32,84,9f,06,9b,0d,21,eb,9a)
#define UNIT_NAME_HASH_LENGTH_CHARS 16

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
                if (!strchr(VALID_CHARS_WITH_AT, *i))
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
UnitNameFlags unit_name_to_instance(const char *n, char **ret) {
        const char *p, *d;

        assert(n);

        if (!unit_name_is_valid(n, UNIT_NAME_ANY))
                return -EINVAL;

        /* Everything past the first @ and before the last . is the instance */
        p = strchr(n, '@');//找到'@'
        if (!p) {
                if (ret)
                        *ret = NULL;
                return UNIT_NAME_PLAIN;
        }

        p++;

        d = strrchr(p, '.');//找到'.'
        if (!d)
                return -EINVAL;

        //复制p,d之间的字符串返回
        if (ret) {
                char *i = strndup(p, d-p);
                if (!i)
                        return -ENOMEM;

                *ret = i;
        }
        return d > p ? UNIT_NAME_INSTANCE : UNIT_NAME_TEMPLATE;
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
        _cleanup_free_ char *s = NULL;
        size_t a, b;
        char *e;

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

        /* Make sure the name is still valid (i.e. didn't grow too large due to longer suffix) */
        if (!unit_name_is_valid(s, UNIT_NAME_ANY))
                return -EINVAL;

        *ret = TAKE_PTR(s);
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
                return type;

        return unit_name_build_from_type(prefix, instance, type, ret);
}

int unit_name_build_from_type(const char *prefix, const char *instance, UnitType type, char **ret) {
        _cleanup_free_ char *s = NULL;
        const char *ut;

        assert(prefix);
        assert(type >= 0);
        assert(type < _UNIT_TYPE_MAX);
        assert(ret);

        if (!unit_prefix_is_valid(prefix))
                return -EINVAL;

        ut = unit_type_to_string(type);

        if (instance) {
                if (!unit_instance_is_valid(instance))
                        return -EINVAL;

                s = strjoin(prefix, "@", instance, ".", ut);
        } else
                s = strjoin(prefix, ".", ut);
        if (!s)
                return -ENOMEM;

        /* Verify that this didn't grow too large (or otherwise is invalid) */
        if (!unit_name_is_valid(s, instance ? UNIT_NAME_INSTANCE : UNIT_NAME_PLAIN))
                return -EINVAL;

        *ret = TAKE_PTR(s);
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

char* unit_name_escape(const char *f) {
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
        _cleanup_free_ char *p = NULL;
        char *s;
        int r;

        assert(f);
        assert(ret);

        /*复制字符串，且内存采用alloc*/
        r = path_simplify_alloc(f, &p);
        if (r < 0)
                return r;

        if (empty_or_root(p))
        	/*路径为root或为空*/
                s = strdup("-");
        else {
                if (!path_is_normalized(p))
                        return -EINVAL;

                /* Truncate trailing slashes and skip leading slashes */
                delete_trailing_chars(p, "/");
                s = unit_name_escape(skip_leading_chars(p, "/"));
        }
        if (!s)
                return -ENOMEM;

        *ret = s;
        return 0;
}

int unit_name_path_unescape(const char *f, char **ret) {
        _cleanup_free_ char *s = NULL;
        int r;

        assert(f);

        if (isempty(f))
                return -EINVAL;

        if (streq(f, "-")) {
                s = strdup("/");
                if (!s)
                        return -ENOMEM;
        } else {
                _cleanup_free_ char *w = NULL;

                r = unit_name_unescape(f, &w);
                if (r < 0)
                        return r;

                /* Don't accept trailing or leading slashes */
                if (startswith(w, "/") || endswith(w, "/"))
                        return -EINVAL;

                /* Prefix a slash again */
                s = strjoin("/", w);
                if (!s)
                        return -ENOMEM;

                if (!path_is_normalized(s))
                        return -EINVAL;
        }

        if (ret)
                *ret = TAKE_PTR(s);

        return 0;
}

int unit_name_replace_instance_full(
                const char *original,
                const char *instance,
                bool accept_glob,
                char **ret) {

        _cleanup_free_ char *s = NULL;
        const char *prefix, *suffix;
        size_t pl;

        assert(original);
        assert(instance);
        assert(ret);

        //f必须为有效的实例名或者模板名
        if (!unit_name_is_valid(original, UNIT_NAME_INSTANCE|UNIT_NAME_TEMPLATE))
                return -EINVAL;
        //f必须为有效的名称
        if (!unit_instance_is_valid(instance) && !(accept_glob && in_charset(instance, VALID_CHARS_GLOB)))
                return -EINVAL;

        //一定包含'@',一定包含'.'
        prefix = ASSERT_PTR(strchr(original, '@'));
        suffix = ASSERT_PTR(strrchr(original, '.'));
        assert(prefix < suffix);

        pl = prefix - original + 1; /* include '@' */

        //对于字符串"XXXX@XX.XXX"，在@后添加i，申请必要的长度(含'\0')
        s = new(char, pl + strlen(instance) + strlen(suffix) + 1);
        if (!s)
                return -ENOMEM;

        //1.先copy头部f,p+1范围,存入s,返回s;2.再copy　i字符串到s,返回s;3.再copy e到s
        //这个实现看起来是错的。
#if HAS_FEATURE_MEMORY_SANITIZER
        /* MSan doesn't like stpncpy... See also https://github.com/google/sanitizers/issues/926 */
        memzero(s, pl + strlen(instance) + strlen(suffix) + 1);
#endif

        strcpy(stpcpy(stpncpy(s, original, pl), instance), suffix);

        /* Make sure the resulting name still is valid, i.e. didn't grow too large. Globs will be expanded
         * by clients when used, so the check is pointless. */
        if (!accept_glob && !unit_name_is_valid(s, UNIT_NAME_INSTANCE))
                return -EINVAL;

        *ret = TAKE_PTR(s);
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

bool unit_name_is_hashed(const char *name) {
        char *s;

        if (!unit_name_is_valid(name, UNIT_NAME_PLAIN))
                return false;

        assert_se(s = strrchr(name, '.'));

        if (s - name < UNIT_NAME_HASH_LENGTH_CHARS + 1)
                return false;

        s -= UNIT_NAME_HASH_LENGTH_CHARS;
        if (s[-1] != '_')
                return false;

        for (size_t i = 0; i < UNIT_NAME_HASH_LENGTH_CHARS; i++)
                if (!strchr(LOWERCASE_HEXDIGITS, s[i]))
                        return false;

        return true;
}

int unit_name_hash_long(const char *name, char **ret) {
        _cleanup_free_ char *n = NULL, *hash = NULL;
        char *suffix;
        le64_t h;
        size_t len;

        if (strlen(name) < UNIT_NAME_MAX)
                return -EMSGSIZE;

        suffix = strrchr(name, '.');
        if (!suffix)
                return -EINVAL;

        if (unit_type_from_string(suffix+1) < 0)
                return -EINVAL;

        h = htole64(siphash24_string(name, LONG_UNIT_NAME_HASH_KEY.bytes));

        hash = hexmem(&h, sizeof(h));
        if (!hash)
                return -ENOMEM;

        assert_se(strlen(hash) == UNIT_NAME_HASH_LENGTH_CHARS);

        len = UNIT_NAME_MAX - 1 - strlen(suffix+1) - UNIT_NAME_HASH_LENGTH_CHARS - 2;
        assert(len > 0 && len < UNIT_NAME_MAX);

        n = strndup(name, len);
        if (!n)
                return -ENOMEM;

        if (!strextend(&n, "_", hash, suffix))
                return -ENOMEM;
        assert_se(unit_name_is_valid(n, UNIT_NAME_PLAIN));

        *ret = TAKE_PTR(n);

        return 0;
}

int unit_name_from_path(const char *path, const char *suffix, char **ret) {
        _cleanup_free_ char *p = NULL, *s = NULL;
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
        s = strjoin(p, suffix);
        if (!s)
                return -ENOMEM;

        if (strlen(s) >= UNIT_NAME_MAX) {
                _cleanup_free_ char *n = NULL;

                log_debug("Unit name \"%s\" too long, falling back to hashed unit name.", s);

                r = unit_name_hash_long(s, &n);
                if (r < 0)
                        return r;

                free_and_replace(s, n);
        }

        /* Refuse if this for some other reason didn't result in a valid name */
        if (!unit_name_is_valid(s, UNIT_NAME_PLAIN))
                return -EINVAL;

        *ret = TAKE_PTR(s);
        return 0;
}

int unit_name_from_path_instance(const char *prefix, const char *path, const char *suffix, char **ret) {
        _cleanup_free_ char *p = NULL, *s = NULL;
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

        if (strlen(s) >= UNIT_NAME_MAX) /* Return a slightly more descriptive error for this specific condition */
                return -ENAMETOOLONG;

        /* Refuse if this for some other reason didn't result in a valid name */
        if (!unit_name_is_valid(s, UNIT_NAME_INSTANCE))
                return -EINVAL;

        *ret = TAKE_PTR(s);
        return 0;
}

int unit_name_to_path(const char *name, char **ret) {
        _cleanup_free_ char *prefix = NULL;
        int r;

        assert(name);

        r = unit_name_to_prefix(name, &prefix);
        if (r < 0)
                return r;

        if (unit_name_is_hashed(name))
                return -ENAMETOOLONG;

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
int unit_name_mangle_with_suffix(
                const char *name,
                const char *operation,
                UnitNameMangle flags,
                const char *suffix,
                char **ret) {

        _cleanup_free_ char *s = NULL;
        bool mangled, suggest_escape = true, warn = flags & UNIT_NAME_MANGLE_WARN;
        int r;

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
        if (string_is_glob(name) && in_charset(name, VALID_CHARS_GLOB)) {
                if (flags & UNIT_NAME_MANGLE_GLOB)
                        goto good;
                log_full(warn ? LOG_NOTICE : LOG_DEBUG,
                         "Glob pattern passed%s%s, but globs are not supported for this.",
                         operation ? " " : "", strempty(operation));
                suggest_escape = false;
        }

        if (path_is_absolute(name)) {
                _cleanup_free_ char *n = NULL;

                r = path_simplify_alloc(name, &n);
                if (r < 0)
                        return r;

                if (is_device_path(n)) {
                        r = unit_name_from_path(n, ".device", ret);
                        if (r >= 0)
                                return 1;
                        if (r != -EINVAL)
                                return r;
                }

                r = unit_name_from_path(n, ".mount", ret);
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
                log_full(warn ? LOG_NOTICE : LOG_DEBUG,
                         "Invalid unit name \"%s\" escaped as \"%s\"%s.",
                         name, s,
                         suggest_escape ? " (maybe you should use systemd-escape?)" : "");

        /* Append a suffix if it doesn't have any, but only if this is not a glob, so that we can allow
         * "foo.*" as a valid glob. */
        if ((!(flags & UNIT_NAME_MANGLE_GLOB) || !string_is_glob(s)) && unit_name_to_type(s) < 0)
                strcat(s, suffix);

        /* Make sure mangling didn't grow this too large (but don't do this check if globbing is allowed,
         * since globs generally do not qualify as valid unit names) */
        if (!FLAGS_SET(flags, UNIT_NAME_MANGLE_GLOB) && !unit_name_is_valid(s, UNIT_NAME_ANY))
                return -EINVAL;

        *ret = TAKE_PTR(s);
        return 1;

good:
        return strdup_to(ret, name);
}

int slice_build_parent_slice(const char *slice, char **ret) {
        assert(slice);
        assert(ret);

        if (!slice_name_is_valid(slice))
                return -EINVAL;

        if (streq(slice, SPECIAL_ROOT_SLICE)) {
                *ret = NULL;
                return 0;
        }

        _cleanup_free_ char *s = strdup(slice);
        if (!s)
                return -ENOMEM;

        char *dash = strrchr(s, '-');
        if (!dash)
                return strdup_to_full(ret, SPECIAL_ROOT_SLICE);

        /* We know that s ended with .slice before truncation, so we have enough space. */
        strcpy(dash, ".slice");

        *ret = TAKE_PTR(s);
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
                subslice = strjoin(name, ".slice");
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

bool unit_name_prefix_equal(const char *a, const char *b) {
        const char *p, *q;

        assert(a);
        assert(b);

        if (!unit_name_is_valid(a, UNIT_NAME_ANY) || !unit_name_is_valid(b, UNIT_NAME_ANY))
                return false;

        p = strchr(a, '@');
        if (!p)
                p = strrchr(a, '.');

        q = strchr(b, '@');
        if (!q)
                q = strrchr(b, '.');

        assert(p);
        assert(q);

        return memcmp_nn(a, p - a, b, q - b) == 0;
}
