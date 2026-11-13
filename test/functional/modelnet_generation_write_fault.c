// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Inject a short write followed by EIO when the staged stream flushes on close.
ssize_t write(int fd, const void* buffer, size_t size)
{
    ssize_t (*write_next)(int, const void*, size_t) = dlsym(RTLD_NEXT, "write");
    const char* gate = getenv("BTX_TEST_GENERATION_GATE");
    const char* prefix = getenv("BTX_TEST_GENERATION_STORE");
    if (gate && prefix && access(gate, F_OK) == 0) {
        char fd_path[64], target[PATH_MAX];
        snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
        const ssize_t length = readlink(fd_path, target, sizeof(target) - 1);
        const char suffix[] = ".gen";
        if (length >= (ssize_t)sizeof(suffix)) {
            target[length] = '\0';
            if (strncmp(target, prefix, strlen(prefix)) == 0 &&
                strcmp(target + length - sizeof(suffix) + 1, suffix) == 0) {
                if (size > 8) return write_next(fd, buffer, 8);
                const char event[] = "generation fixture: EIO\n";
                write_next(STDERR_FILENO, event, sizeof(event) - 1);
                errno = EIO;
                return -1;
            }
        }
    }
    return write_next(fd, buffer, size);
}
