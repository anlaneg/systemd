/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "unit.h"

typedef struct Target Target;

//Target类型的Unit,继续自unit
struct Target {
        Unit meta;

        TargetState state, deserialized_state;
};

extern const UnitVTable target_vtable;

DEFINE_CAST(TARGET, Target);
