/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "env-util.h"
#include "log.h"
#include "macro.h"
#include "process-util.h"
#include "string-util.h"
#include "verbs.h"
#include "virt.h"

/* Wraps running_in_chroot() which is used in various places, but also adds an environment variable check so external
 * processes can reliably force this on.
 */
bool running_in_chroot_or_offline(void) {
        int r;

        /* Added to support use cases like rpm-ostree, where from %post scripts we only want to execute "preset", but
         * not "start"/"restart" for example.
         *
         * See docs/ENVIRONMENT.md for docs.
         */
        r = getenv_bool("SYSTEMD_OFFLINE");
        if (r < 0 && r != -ENXIO)
                log_debug_errno(r, "Failed to parse $SYSTEMD_OFFLINE: %m");
        else if (r >= 0)
                return r > 0;

        /* We've had this condition check for a long time which basically checks for legacy chroot case like Fedora's
         * "mock", which is used for package builds.  We don't want to try to start systemd services there, since
         * without --new-chroot we don't even have systemd running, and even if we did, adding a concept of background
         * daemons to builds would be an enormous change, requiring considering things like how the journal output is
         * handled, etc.  And there's really not a use case today for a build talking to a service.
         *
         * Note this call itself also looks for a different variable SYSTEMD_IGNORE_CHROOT=1.
         */
        r = running_in_chroot();
        if (r < 0)
                log_debug_errno(r, "running_in_chroot(): %m");

        return r > 0;
}

int dispatch_verb(int argc, char *argv[], const Verb verbs[]/*各命令指行函数*/, void *userdata) {
        const Verb *verb;
        const char *name;
        unsigned i;
        int left, r;

        assert(verbs);
        assert(verbs[0].dispatch);
        assert(argc >= 0);
        assert(argv);
        assert(argc >= optind);

        left = argc - optind;
        argv += optind;
        optind = 0;
        name = argv[0];

        for (i = 0;; i++) {
                bool found;

                /* At the end of the list? */
                if (!verbs[i].dispatch) {
                        if (name)
                                log_error("Unknown operation %s.", name);
                        else
                                log_error("Requires operation parameter.");
                        return -EINVAL;
                }

                if (name)
                    /*提供了参数，检查参数是否区配*/
                        found = streq(name, verbs[i].verb);
                else
                    /*命令有default标记，没有提供参数，使用默认命令*/
                        found = verbs[i].flags & VERB_DEFAULT;

                if (found) {
                    /*命中*/
                        verb = &verbs[i];
                        break;
                }
        }

        assert(verb);

        if (!name)
                left = 1;

        /*子命令参数校验*/
        if (verb->min_args != VERB_ANY &&
            (unsigned) left < verb->min_args)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Too few arguments.");

        if (verb->max_args != VERB_ANY &&
            (unsigned) left > verb->max_args)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Too many arguments.");

        if ((verb->flags & VERB_ONLINE_ONLY) && running_in_chroot_or_offline()) {
                if (name)
                        log_info("Running in chroot, ignoring request: %s", name);
                else
                        log_info("Running in chroot, ignoring request.");
                return 0;
        }

        if (verb->flags & VERB_MUST_BE_ROOT) {
                r = must_be_root();
                if (r < 0)
                        return r;
        }

        /*执行选中的子命令*/
        if (name)
                return verb->dispatch(left, argv, userdata);
        else {
                char* fake[2] = {
                        (char*) verb->verb,
                        NULL
                };

                return verb->dispatch(1, fake, userdata);
        }
}
