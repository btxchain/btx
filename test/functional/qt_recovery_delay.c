// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
/* Test-only delay for an actual read of an owned regtest block file. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Avoid delaying shielded rehydration, which precedes the scan dialog. */
static int scanner_started(void)
{
    const char *log = getenv("BTX_RECOVERY_SCAN_LOG");
    const char *marker = getenv("BTX_RECOVERY_SCAN_MARKER");
    if (!log || !marker) return 0;
    int fd = open(log, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    off_t end = lseek(fd, 0, SEEK_END);
    char tail[32768];
    off_t start = end > (off_t)(sizeof(tail)-1) ? end - (off_t)(sizeof(tail)-1) : 0;
    const char *gate = getenv("BTX_RECOVERY_DELAY_GATE");
    int gate_fd = gate ? open(gate, O_RDONLY | O_CLOEXEC) : -1;
    if (gate_fd >= 0) {
        char offset[32] = {0};
        if (read(gate_fd, offset, sizeof(offset)-1) > 0) {
            off_t minimum = (off_t)strtoll(offset, NULL, 10);
            if (minimum > start) start = minimum;
        }
        close(gate_fd);
    }
    ssize_t n = pread(fd, tail, sizeof(tail)-1, start);
    close(fd);
    if (n <= 0) return 0;
    tail[n] = '\0';
    return strstr(tail, marker) != NULL;
}

size_t fread(void *buf, size_t size, size_t count, FILE *stream)
{
    size_t (*read_real)(void *, size_t, size_t, FILE *) = dlsym(RTLD_NEXT, "fread");
    const char *gate = getenv("BTX_RECOVERY_DELAY_GATE");
    const char *observed = getenv("BTX_RECOVERY_DELAY_OBSERVED");
    if (gate && observed && access(gate, F_OK) == 0) {
        char fd_path[64], path[PATH_MAX];
        snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fileno(stream));
        ssize_t n = readlink(fd_path, path, sizeof(path) - 1);
        if (n >= 0) {
            path[n] = '\0';
            if (strstr(path, "/regtest/blocks/blk") && scanner_started()) {
                int marker = open(observed, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
                if (marker >= 0) close(marker);
                for (int i = 0; i < 120 && access(gate, F_OK) == 0; ++i) usleep(100000);
            }
        }
    }
    return read_real(buf, size, count, stream);
}
