/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <stdio.h>

#include "device-private.h"
#include "device-util.h"
#include "string-util.h"
#include "strv.h"
#include "udev-builtin.h"

static bool initialized;

static const UdevBuiltin *const builtins[_UDEV_BUILTIN_MAX] = {
#if HAVE_BLKID
        [UDEV_BUILTIN_BLKID] = &udev_builtin_blkid,
#endif
        [UDEV_BUILTIN_BTRFS] = &udev_builtin_btrfs,
        [UDEV_BUILTIN_HWDB] = &udev_builtin_hwdb,
        [UDEV_BUILTIN_INPUT_ID] = &udev_builtin_input_id,
        [UDEV_BUILTIN_KEYBOARD] = &udev_builtin_keyboard,
#if HAVE_KMOD
        [UDEV_BUILTIN_KMOD] = &udev_builtin_kmod,
#endif
        [UDEV_BUILTIN_NET_DRIVER] = &udev_builtin_net_driver,
        [UDEV_BUILTIN_NET_ID] = &udev_builtin_net_id,
        [UDEV_BUILTIN_NET_LINK] = &udev_builtin_net_setup_link,
        [UDEV_BUILTIN_PATH_ID] = &udev_builtin_path_id,
        [UDEV_BUILTIN_USB_ID] = &udev_builtin_usb_id,
#if HAVE_ACL
        [UDEV_BUILTIN_UACCESS] = &udev_builtin_uaccess,
#endif
};

void udev_builtin_init(void) {
        if (initialized)
                return;

        /*初始化所有内置命令*/
        for (UdevBuiltinCommand i = 0; i < _UDEV_BUILTIN_MAX; i++)
                if (builtins[i] && builtins[i]->init)
                        builtins[i]->init();

        initialized = true;
}

void udev_builtin_exit(void) {
        if (!initialized)
                return;

        /*针对所有内置命令调用exit*/
        for (UdevBuiltinCommand i = 0; i < _UDEV_BUILTIN_MAX; i++)
                if (builtins[i] && builtins[i]->exit)
                        builtins[i]->exit();

        initialized = false;
}

bool udev_builtin_should_reload(void) {
        for (UdevBuiltinCommand i = 0; i < _UDEV_BUILTIN_MAX; i++)
                if (builtins[i] && builtins[i]->should_reload && builtins[i]->should_reload())
                        return true;
        return false;
}

void udev_builtin_list(void) {
        /*针对所有内置命令显示命令及帮助信息*/
        for (UdevBuiltinCommand i = 0; i < _UDEV_BUILTIN_MAX; i++)
                if (builtins[i])
                        fprintf(stderr, "  %-14s  %s\n", builtins[i]->name, builtins[i]->help);
}

/*返回指定内置命令的名称*/
const char* udev_builtin_name(UdevBuiltinCommand cmd) {
        assert(cmd >= 0 && cmd < _UDEV_BUILTIN_MAX);

        if (!builtins[cmd])
                return NULL;

        return builtins[cmd]->name;
}

/*检查给定cmd是否仅需要运行一次*/
bool udev_builtin_run_once(UdevBuiltinCommand cmd) {
        assert(cmd >= 0 && cmd < _UDEV_BUILTIN_MAX);

        if (!builtins[cmd])
                return false;

        return builtins[cmd]->run_once;
}

/*查询命令对应的内建命令index*/
UdevBuiltinCommand udev_builtin_lookup(const char *command) {
        size_t n;

        assert(command);

        command += strspn(command, WHITESPACE);
        n = strcspn(command, WHITESPACE);
        for (UdevBuiltinCommand i = 0; i < _UDEV_BUILTIN_MAX; i++)
                if (builtins[i] && strneq(builtins[i]->name, command, n))
                        return i;

        return _UDEV_BUILTIN_INVALID;
}

/*执行内建命令*/
int udev_builtin_run(UdevEvent *event, UdevBuiltinCommand cmd/*内建的命令index*/, const char *command) {
        _cleanup_strv_free_ char **argv = NULL;
        int r;

        assert(event);
        assert(event->dev);
        assert(cmd >= 0 && cmd < _UDEV_BUILTIN_MAX);
        assert(command);

        if (!builtins[cmd])
                return -EOPNOTSUPP;

        r = strv_split_full(&argv, command, NULL, EXTRACT_UNQUOTE | EXTRACT_RELAX | EXTRACT_RETAIN_ESCAPE);
        if (r < 0)
                return r;

        /* we need '0' here to reset the internal state */
        optind = 0;
        /*按命令index找到相应命令，执行命令处理*/
        return builtins[cmd]->cmd(event, strv_length(argv), argv);
}

int udev_builtin_add_property(sd_device *dev, EventMode mode, const char *key, const char *val) {
        int r;

        assert(dev);
        assert(key);

        r = device_add_property(dev, key, val);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to add property '%s%s%s'",
                                              key, val ? "=" : "", strempty(val));

        if (mode == EVENT_UDEVADM_TEST_BUILTIN)
                printf("%s=%s\n", key, strempty(val));

        return 0;
}

int udev_builtin_add_propertyf(sd_device *dev, EventMode mode, const char *key, const char *valf, ...) {
        _cleanup_free_ char *val = NULL;
        va_list ap;
        int r;

        assert(dev);
        assert(key);
        assert(valf);

        va_start(ap, valf);
        r = vasprintf(&val, valf, ap);
        va_end(ap);
        if (r < 0)
                return log_oom_debug();

        return udev_builtin_add_property(dev, mode, key, val);
}

int udev_builtin_import_property(sd_device *dev, sd_device *src, EventMode mode, const char *key) {
        const char *val;
        int r;

        assert(dev);
        assert(key);

        if (!src)
                return 0;

        r = sd_device_get_property_value(src, key, &val);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_device_debug_errno(src, r, "Failed to get property \"%s\", ignoring: %m", key);

        r = udev_builtin_add_property(dev, mode, key, val);
        if (r < 0)
                return r;

        return 1;
}
