/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <fcntl.h>
#include <linux/loop.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "loop-util.h"
#include "stat-util.h"

/*利用fd创建后端文件*/
int loop_device_make(int fd, int open_flags, LoopDevice **ret) {
        const struct loop_info64 info = {
                .lo_flags = LO_FLAGS_AUTOCLEAR|LO_FLAGS_PARTSCAN|(open_flags == O_RDONLY ? LO_FLAGS_READ_ONLY : 0),
        };

        _cleanup_close_ int control = -1, loop = -1;
        _cleanup_free_ char *loopdev = NULL;
        struct stat st;
        LoopDevice *d;
        int nr, r;

        assert(fd >= 0);
        assert(ret);
        assert(IN_SET(open_flags, O_RDWR, O_RDONLY));

        if (fstat(fd, &st) < 0)
                return -errno;

        if (S_ISBLK(st.st_mode)) {
                int copy;

                /* If this is already a block device, store a copy of the fd as it is */

                copy = fcntl(fd, F_DUPFD_CLOEXEC, 3);
                if (copy < 0)
                        return -errno;

                d = new0(LoopDevice, 1);
                if (!d)
                        return -ENOMEM;

                *d = (LoopDevice) {
                        .fd = copy,
                        .nr = -1,
                        .relinquished = true, /* It's not allocated by us, don't destroy it when this object is freed */
                };

                *ret = d;
                return d->fd;
        }

        r = stat_verify_regular(&st);
        if (r < 0)
                return r;

        /*获取空闲的loop设备idx*/
        control = open("/dev/loop-control", O_RDWR|O_CLOEXEC|O_NOCTTY|O_NONBLOCK);
        if (control < 0)
                return -errno;

        nr = ioctl(control, LOOP_CTL_GET_FREE);/*返回空闲的loop设备idx*/
        if (nr < 0)
                return -errno;

        /*构造设备名称*/
        if (asprintf(&loopdev, "/dev/loop%i", nr) < 0)
                return -ENOMEM;

        /*打开给定的loop设备*/
        loop = open(loopdev, O_CLOEXEC|O_NONBLOCK|O_NOCTTY|open_flags);
        if (loop < 0)
                return -errno;

        /*传入loop设备后端文件fd*/
        if (ioctl(loop, LOOP_SET_FD, fd/*后端文件*/) < 0)
                return -errno;

        if (ioctl(loop, LOOP_SET_STATUS64, &info) < 0)
                return -errno;

        d = new(LoopDevice, 1);
        if (!d)
                return -ENOMEM;

        *d = (LoopDevice) {
                .fd = TAKE_FD(loop),
                .node = TAKE_PTR(loopdev),
                .nr = nr,
        };

        *ret = d;
        return d->fd;/*返回loop设备idx*/
}

/*创建loop设备，并将其后端设置为path*/
int loop_device_make_by_path(const char *path, int open_flags, LoopDevice **ret) {
        _cleanup_close_ int fd = -1;

        assert(path);
        assert(ret);
        assert(IN_SET(open_flags, O_RDWR, O_RDONLY));

        fd = open(path, O_CLOEXEC|O_NONBLOCK|O_NOCTTY|open_flags);
        if (fd < 0)
                return -errno;

        return loop_device_make(fd, open_flags, ret);
}

LoopDevice* loop_device_unref(LoopDevice *d) {
        if (!d)
                return NULL;

        if (d->fd >= 0) {

                if (d->nr >= 0 && !d->relinquished) {
                        if (ioctl(d->fd, LOOP_CLR_FD) < 0)
                                log_debug_errno(errno, "Failed to clear loop device: %m");

                }

                safe_close(d->fd);
        }

        if (d->nr >= 0 && !d->relinquished) {
                _cleanup_close_ int control = -1;

                control = open("/dev/loop-control", O_RDWR|O_CLOEXEC|O_NOCTTY|O_NONBLOCK);
                if (control < 0)
                        log_debug_errno(errno, "Failed to open loop control device: %m");
                else {
                        if (ioctl(control, LOOP_CTL_REMOVE, d->nr) < 0)
                                log_debug_errno(errno, "Failed to remove loop device: %m");
                }
        }

        free(d->node);
        return mfree(d);
}

void loop_device_relinquish(LoopDevice *d) {
        assert(d);

        /* Don't attempt to clean up the loop device anymore from this point on. Leave the clean-ing up to the kernel
         * itself, using the loop device "auto-clear" logic we already turned on when creating the device. */

        d->relinquished = true;
}
