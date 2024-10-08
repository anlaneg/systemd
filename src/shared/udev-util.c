/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <string.h>

#include "alloc-util.h"
#include "env-file.h"
#include "log.h"
#include "parse-util.h"
#include "string-table.h"
#include "string-util.h"
#include "udev-util.h"
#include "udev.h"

static const char* const resolve_name_timing_table[_RESOLVE_NAME_TIMING_MAX] = {
        [RESOLVE_NAME_NEVER] = "never",
        [RESOLVE_NAME_LATE] = "late",
        [RESOLVE_NAME_EARLY] = "early",
};

DEFINE_STRING_TABLE_LOOKUP(resolve_name_timing, ResolveNameTiming);

int udev_parse_config_full(
                unsigned *ret_children_max,
                usec_t *ret_exec_delay_usec,
                usec_t *ret_event_timeout_usec,
                ResolveNameTiming *ret_resolve_name_timing) {

        _cleanup_free_ char *log_val = NULL, *children_max = NULL, *exec_delay = NULL, *event_timeout = NULL, *resolve_names = NULL;
        int r;

        //解析udev配置文件，将指定的key取值填充到其对应的变量中
        r = parse_env_file(NULL, "/etc/udev/udev.conf",
                           "udev_log", &log_val,
                           "children_max", &children_max,
                           "exec_delay", &exec_delay,
                           "event_timeout", &event_timeout,
                           "resolve_names", &resolve_names);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return r;

        if (log_val) {
                const char *log;
                size_t n;

                /* unquote */
                n = strlen(log_val);
                if (n >= 2 &&
                    ((log_val[0] == '"' && log_val[n-1] == '"') ||
                     (log_val[0] == '\'' && log_val[n-1] == '\''))) {
                		/*以字符串形式指明log级别的，移除前导及后继的字符*/
                        log_val[n - 1] = '\0';
                        log = log_val + 1;
                } else
                        log = log_val;

                /* we set the udev log level here explicitly, this is supposed
                 * to regulate the code in libudev/ and udev/. */
                r = log_set_max_level_from_string_realm(LOG_REALM_UDEV, log);
                if (r < 0)
                        log_debug_errno(r, "/etc/udev/udev.conf: failed to set udev log level '%s', ignoring: %m", log);
        }

        if (ret_children_max && children_max) {
        	/*解析children_max配置并通过children_max出参带出函数*/
                r = safe_atou(children_max, ret_children_max);
                if (r < 0)
                        log_notice_errno(r, "/etc/udev/udev.conf: failed to set parse children_max=%s, ignoring: %m", children_max);
        }

        if (ret_exec_delay_usec && exec_delay) {
                r = parse_sec(exec_delay, ret_exec_delay_usec);
                if (r < 0)
                        log_notice_errno(r, "/etc/udev/udev.conf: failed to set parse exec_delay=%s, ignoring: %m", exec_delay);
        }

        if (ret_event_timeout_usec && event_timeout) {
                r = parse_sec(event_timeout, ret_event_timeout_usec);
                if (r < 0)
                        log_notice_errno(r, "/etc/udev/udev.conf: failed to set parse event_timeout=%s, ignoring: %m", event_timeout);
        }

        if (ret_resolve_name_timing && resolve_names) {
                ResolveNameTiming t;

                t = resolve_name_timing_from_string(resolve_names);
                if (t < 0)
                        log_notice("/etc/udev/udev.conf: failed to set parse resolve_names=%s, ignoring.", resolve_names);
                else
                        *ret_resolve_name_timing = t;
        }

        return 0;
}

struct DeviceMonitorData {
        const char *sysname;
        sd_device *device;
};

static int device_monitor_handler(sd_device_monitor *monitor, sd_device *device, void *userdata) {
        struct DeviceMonitorData *data = userdata;
        const char *sysname;

        assert(device);
        assert(data);
        assert(data->sysname);
        assert(!data->device);

        if (sd_device_get_sysname(device, &sysname) >= 0 && streq(sysname, data->sysname)) {
                data->device = sd_device_ref(device);
                return sd_event_exit(sd_device_monitor_get_event(monitor), 0);
        }

        return 0;
}

int device_wait_for_initialization(sd_device *device, const char *subsystem, sd_device **ret) {
        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *monitor = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        struct DeviceMonitorData data = {};
        int r;

        assert(device);
        assert(subsystem);

        if (sd_device_get_is_initialized(device) > 0) {
                if (ret)
                        *ret = sd_device_ref(device);
                return 0;
        }

        assert_se(sd_device_get_sysname(device, &data.sysname) >= 0);

        /* Wait until the device is initialized, so that we can get access to the ID_PATH property */

        r = sd_event_default(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to get default event: %m");

        r = sd_device_monitor_new(&monitor);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire monitor: %m");

        r = sd_device_monitor_filter_add_match_subsystem_devtype(monitor, subsystem, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to add %s subsystem match to monitor: %m", subsystem);

        r = sd_device_monitor_attach_event(monitor, event);
        if (r < 0)
                return log_error_errno(r, "Failed to attach event to device monitor: %m");

        r = sd_device_monitor_start(monitor, device_monitor_handler, &data);
        if (r < 0)
                return log_error_errno(r, "Failed to start device monitor: %m");

        /* Check again, maybe things changed. Udev will re-read the db if the device wasn't initialized
         * yet. */
        if (sd_device_get_is_initialized(device) > 0) {
                if (ret)
                        *ret = sd_device_ref(device);
                return 0;
        }

        r = sd_event_loop(event);
        if (r < 0)
                return log_error_errno(r, "Event loop failed: %m");

        if (ret)
                *ret = TAKE_PTR(data.device);
        return 0;
}
