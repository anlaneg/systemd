/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <sys/stat.h>

#include "build.h"
#include "conf-files.h"
#include "constants.h"
#include "fd-util.h"
#include "fileio.h"
#include "log.h"
#include "main-func.h"
#include "module-util.h"
#include "pretty-print.h"
#include "proc-cmdline.h"
#include "string-util.h"
#include "strv.h"

static char **arg_proc_cmdline_modules = NULL;
/*modules-load配置文件可能的目录列表*/
static const char conf_file_dirs[] = CONF_PATHS_NULSTR("modules-load.d");

STATIC_DESTRUCTOR_REGISTER(arg_proc_cmdline_modules, strv_freep);

static int parse_proc_cmdline_item(const char *key, const char *value, void *data) {
        int r;

        /*取命令行中modules_load参数，解析要加载的module*/
        if (proc_cmdline_key_streq(key, "modules_load")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = strv_split_and_extend(&arg_proc_cmdline_modules, value, ",", /* filter_duplicates = */ true);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse modules_load= kernel command line option: %m");
        }

        return 0;
}

static int apply_file(struct kmod_ctx *ctx, const char *path/*要加载的模块path*/, bool ignore_enoent) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *pp = NULL;
        int r;

        assert(ctx);
        assert(path);

        r = search_and_fopen_nulstr(path, "re", NULL, conf_file_dirs, &f, &pp);
        if (r < 0) {
            /*没有找到文件，退出*/
                if (ignore_enoent && r == -ENOENT)
                        return 0;

                return log_error_errno(r, "Failed to open %s: %m", path);
        }

        log_debug("apply: %s", pp);
        for (;;) {
                _cleanup_free_ char *line = NULL;
                int k;

                /*自此文件中读取一行*/
                k = read_stripped_line(f, LONG_LINE_MAX, &line);
                if (k < 0)
                        return log_error_errno(k, "Failed to read file '%s': %m", pp);
                if (k == 0)
                        break;

                if (isempty(line))
                        continue;
                if (strchr(COMMENTS, *line))
                    /*跳过注释行*/
                        continue;

                k = module_load_and_warn(ctx, line/*要加载的模块名*/, true);
                if (k == -ENOENT)
                        continue;
                RET_GATHER(r, k);
        }

        return r;
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-modules-load.service", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] [CONFIGURATION FILE...]\n\n"
               "Loads statically configured kernel modules.\n\n"
               "  -h --help             Show this help\n"
               "     --version          Show package version\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, 'h'           },
                { "version",   no_argument,       NULL, ARG_VERSION   },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)
                switch (c) {

                case 'h':
                	/*显示帮助*/
                        return help();

                case ARG_VERSION:
                	/*显示版本*/
                        return version();

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        return 1;
}

static int run(int argc, char *argv[]) {
        _cleanup_(sym_kmod_unrefp) struct kmod_ctx *ctx = NULL;
        int r, k;

        /*解析参数*/
        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        log_setup();

        umask(0022);

        r = proc_cmdline_parse(parse_proc_cmdline_item, NULL, PROC_CMDLINE_STRIP_RD_PREFIX);
        if (r < 0)
                log_warning_errno(r, "Failed to parse kernel command line, ignoring: %m");

        /*初始化kmod_ctx*/
        r = module_setup_context(&ctx);
        if (r < 0)
                return log_error_errno(r, "Failed to initialize libkmod context: %m");

        r = 0;

        if (argc > optind) {
                /*按参数指定的文件名进行模块加载*/
                for (int i = optind; i < argc; i++)
                        RET_GATHER(r, apply_file(ctx, argv[i], false));

        } else {
                _cleanup_strv_free_ char **files = NULL;

                STRV_FOREACH(i, arg_proc_cmdline_modules) {
                        k = module_load_and_warn(ctx, *i, true);
                        if (k == -ENOENT)
                                continue;
                        RET_GATHER(r, k);
                }

                /*查找modules-load.d目录下，所以.conf后缀的文件*/
                k = conf_files_list_nulstr(&files, ".conf", NULL, 0, conf_file_dirs);
                if (k < 0)
                        return log_error_errno(k, "Failed to enumerate modules-load.d files: %m");

                /*逐个加载这些文件指定的module*/
                STRV_FOREACH(fn, files)
                        RET_GATHER(r, apply_file(ctx, *fn, true));
        }

        return r;
}

/*systemd-modules-load进程main函数定义*/
DEFINE_MAIN_FUNCTION(run);
