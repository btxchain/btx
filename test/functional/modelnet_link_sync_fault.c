// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int run_sync(int fd, const char *symbol)
{
    int (*real_sync)(int) = dlsym(RTLD_NEXT, symbol);
    if (!real_sync) _exit(97);
    const char *root = getenv("BTX_TEST_FLUSH_ROOT");
    if (!root) return real_sync(fd);
    const int saved_errno = errno;
    char proc_path[64], path[PATH_MAX], record[PATH_MAX + 120], arm[PATH_MAX], trace[PATH_MAX];
    snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);
    ssize_t length = readlink(proc_path, path, sizeof(path) - 1);
    const size_t root_length = strlen(root);
    if (length <= 0) goto passthrough;
    path[length] = 0;
    if (strcmp(path, root) == 0) {
        snprintf(trace, sizeof(trace), "%s/trace", root);
        const int log = open(trace, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
        const char event[] = "directory\n";
        if (log < 0 || write(log, event, sizeof(event) - 1) != sizeof(event) - 1 || close(log)) _exit(99);
        goto passthrough;
    }
    if ((size_t)length <= root_length + 17) goto passthrough;
    if (strncmp(path, root, root_length) || strncmp(path + root_length, "/.btx-export-", 13)
        || strcmp(path + length - 4, ".tmp")) goto passthrough;
    struct stat opened, named;
    if (fstat(fd, &opened) || stat(path, &named) ||
        opened.st_dev != named.st_dev || opened.st_ino != named.st_ino) _exit(98);
    snprintf(arm, sizeof(arm), "%s/arm", root);
    snprintf(trace, sizeof(trace), "%s/trace", root);
    int armed = access(arm, F_OK) == 0;
    if (armed) {
        char snapshot[PATH_MAX], bytes[4096];
        snprintf(snapshot, sizeof(snapshot), "%s/staged-bytes", root);
        int input = open(path, O_RDONLY | O_CLOEXEC);
        int output = open(snapshot, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (input < 0 || output < 0) _exit(99);
        ssize_t count;
        while ((count = read(input, bytes, sizeof(bytes))) > 0) {
            if (write(output, bytes, (size_t)count) != count) _exit(99);
        }
        if (count || close(input) || close(output)) _exit(99);
    }
    int size = snprintf(record, sizeof(record), "%s %d %lld\n", symbol, armed, (long long)opened.st_size);
    int log = open(trace, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (log < 0 || write(log, record, (size_t)size) != size || close(log)) _exit(99);
    if (armed) {
        errno = EIO;
        return -1;
    }
passthrough:
    errno = saved_errno;
    return real_sync(fd);
}

int fsync(int fd) { return run_sync(fd, "fsync"); }
int fdatasync(int fd) { return run_sync(fd, "fdatasync"); }
