/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>

#include "module-util.h"

int module_load_and_warn(struct kmod_ctx *ctx, const char *module/*要加载的模块名*/, bool verbose) {
        const int probe_flags = KMOD_PROBE_APPLY_BLACKLIST;
        struct kmod_list *itr;
        _cleanup_(kmod_module_unref_listp) struct kmod_list *modlist = NULL;
        int r = 0;

        /* verbose==true means we should log at non-debug level if we
         * fail to find or load the module. */

        log_debug("Loading module: %s", module);

        r = kmod_module_new_from_lookup(ctx, module, &modlist);
        if (r < 0)
                return log_full_errno(verbose ? LOG_ERR : LOG_DEBUG, r,
                                      "Failed to lookup module alias '%s': %m", module);

        if (!modlist) {
            /*没有查找到配置的module*/
                log_full_errno(verbose ? LOG_ERR : LOG_DEBUG, r,
                               "Failed to find module '%s'", module);
                return -ENOENT;
        }

        /*遍历查找到的所有module*/
        kmod_list_foreach(itr, modlist) {
                _cleanup_(kmod_module_unrefp) struct kmod_module *mod = NULL;
                int state, err;

                mod = kmod_module_get_module(itr);
                /*取此module当前状态*/
                state = kmod_module_get_initstate(mod);

                switch (state) {
                case KMOD_MODULE_BUILTIN:
                    /*已内建*/
                        log_full(verbose ? LOG_INFO : LOG_DEBUG,
                                 "Module '%s' is builtin", kmod_module_get_name(mod));
                        break;

                case KMOD_MODULE_LIVE:
                    /*已加载*/
                        log_debug("Module '%s' is already loaded", kmod_module_get_name(mod));
                        break;

                default:
                        /*实现module插入*/
                        err = kmod_module_probe_insert_module(mod, probe_flags,
                                                              NULL, NULL, NULL, NULL);
                        if (err == 0)
                                log_full(verbose ? LOG_INFO : LOG_DEBUG,
                                         "Inserted module '%s'", kmod_module_get_name(mod));
                        else if (err == KMOD_PROBE_APPLY_BLACKLIST)
                                log_full(verbose ? LOG_INFO : LOG_DEBUG,
                                         "Module '%s' is blacklisted", kmod_module_get_name(mod));
                        else {
                                assert(err < 0);

                                log_full_errno(!verbose ? LOG_DEBUG :
                                               err == -ENODEV ? LOG_NOTICE :
                                               err == -ENOENT ? LOG_WARNING :
                                                                LOG_ERR,
                                               err,
                                               "Failed to insert module '%s': %m",
                                               kmod_module_get_name(mod));
                                if (!IN_SET(err, -ENODEV, -ENOENT))
                                        r = err;
                        }
                }
        }

        return r;
}
