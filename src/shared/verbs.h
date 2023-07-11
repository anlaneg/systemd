/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdbool.h>

#define VERB_ANY ((unsigned) -1)

typedef enum VerbFlags {
		/*标记默认动作*/
        VERB_DEFAULT      = 1 << 0,
		/*标记此动作仅在chroot中运行*/
        VERB_ONLINE_ONLY  = 1 << 1,
		/*标记此动作必须以root运行*/
        VERB_MUST_BE_ROOT = 1 << 2,
} VerbFlags;

typedef struct {
        const char *verb;
        unsigned min_args, max_args;
        VerbFlags flags;
        int (* const dispatch)(int argc, char *argv[], void *userdata);
} Verb;

bool running_in_chroot_or_offline(void);

int dispatch_verb(int argc, char *argv[], const Verb verbs[], void *userdata);
