/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdbool.h>
#include <stdio.h>

#include "list.h"
#include "macro.h"

typedef enum ConditionType {
        CONDITION_ARCHITECTURE,
        CONDITION_VIRTUALIZATION,
        CONDITION_HOST,
        CONDITION_KERNEL_COMMAND_LINE,
        CONDITION_KERNEL_VERSION,
        CONDITION_SECURITY,
        CONDITION_CAPABILITY,
        CONDITION_AC_POWER,

        CONDITION_NEEDS_UPDATE,
        CONDITION_FIRST_BOOT,

        CONDITION_PATH_EXISTS,
        CONDITION_PATH_EXISTS_GLOB,
        CONDITION_PATH_IS_DIRECTORY,
        CONDITION_PATH_IS_SYMBOLIC_LINK,
        CONDITION_PATH_IS_MOUNT_POINT,
        CONDITION_PATH_IS_READ_WRITE,
        CONDITION_DIRECTORY_NOT_EMPTY,
        CONDITION_FILE_NOT_EMPTY,
        CONDITION_FILE_IS_EXECUTABLE,

        CONDITION_NULL,

        CONDITION_USER,
        CONDITION_GROUP,

        CONDITION_CONTROL_GROUP_CONTROLLER,

        _CONDITION_TYPE_MAX,
        _CONDITION_TYPE_INVALID = -1
} ConditionType;

typedef enum ConditionResult {
        CONDITION_UNTESTED,/*未执行判定*/
        CONDITION_SUCCEEDED,/*判定为真*/
        CONDITION_FAILED,/*判定为假*/
        CONDITION_ERROR,/*判定时出错*/
        _CONDITION_RESULT_MAX,
        _CONDITION_RESULT_INVALID = -1
} ConditionResult;

typedef struct Condition {
        ConditionType type:8;

        bool trigger:1;
        bool negate:1;/*对判定结果是否取反*/

        ConditionResult result:6;

        char *parameter;

        LIST_FIELDS(struct Condition, conditions);
} Condition;

Condition* condition_new(ConditionType type, const char *parameter, bool trigger, bool negate);
void condition_free(Condition *c);
Condition* condition_free_list(Condition *c);

int condition_test(Condition *c);

void condition_dump(Condition *c, FILE *f, const char *prefix, const char *(*to_string)(ConditionType t));
void condition_dump_list(Condition *c, FILE *f, const char *prefix, const char *(*to_string)(ConditionType t));

const char* condition_type_to_string(ConditionType t) _const_;
ConditionType condition_type_from_string(const char *s) _pure_;

const char* assert_type_to_string(ConditionType t) _const_;
ConditionType assert_type_from_string(const char *s) _pure_;

const char* condition_result_to_string(ConditionResult r) _const_;
ConditionResult condition_result_from_string(const char *s) _pure_;

static inline bool condition_takes_path(ConditionType t) {
        return IN_SET(t,
                      CONDITION_PATH_EXISTS,
                      CONDITION_PATH_EXISTS_GLOB,
                      CONDITION_PATH_IS_DIRECTORY,
                      CONDITION_PATH_IS_SYMBOLIC_LINK,
                      CONDITION_PATH_IS_MOUNT_POINT,
                      CONDITION_PATH_IS_READ_WRITE,
                      CONDITION_DIRECTORY_NOT_EMPTY,
                      CONDITION_FILE_NOT_EMPTY,
                      CONDITION_FILE_IS_EXECUTABLE,
                      CONDITION_NEEDS_UPDATE);
}
