// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

// Arm the kernel's file size limit after the payload has synced. The next
// regular file write is the sidecar, including when libc flushes on fclose.
int fsync(int fd)
{
    int (*next_fsync)(int) = dlsym(RTLD_NEXT, "fsync");
    const int result = next_fsync(fd);
    const char* gate = getenv("BTX_TEST_GENERATION_GATE");
    const char* prefix = getenv("BTX_TEST_GENERATION_STORE");
    if (result != 0 || !gate || !prefix || access(gate, F_OK) != 0) return result;

    char descriptor[64], target[PATH_MAX];
    snprintf(descriptor, sizeof(descriptor), "/proc/self/fd/%d", fd);
    const ssize_t length = readlink(descriptor, target, sizeof(target) - 1);
    const char suffix[] = ".st";
    if (length < (ssize_t)sizeof(suffix)) return result;
    target[length] = '\0';
    if (strncmp(target, prefix, strlen(prefix)) != 0 ||
        strcmp(target + length - sizeof(suffix) + 1, suffix) != 0) return result;

    struct rlimit limit;
    if (getrlimit(RLIMIT_FSIZE, &limit) != 0 || limit.rlim_cur <= 8) abort();
    limit.rlim_cur = 8;
    if (signal(SIGXFSZ, SIG_IGN) == SIG_ERR || setrlimit(RLIMIT_FSIZE, &limit) != 0) abort();
    // Remove the gate only once the kernel has installed the fault.
    if (unlink(gate) != 0) abort();
    return result;
}
