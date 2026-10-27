// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

// Helper for the Linux swarm confinement tests. It is linked statically
// because the filesystem jail has no dynamic loader below its root. The tests
// copy it into a root and run it through SwarmRunConfined or
// SwarmRunFilesystemJail with no arguments; it works in its own directory
// (/ inside the jail). A marker file there selects a mode: spread.mode writes
// up to 64 files of 1 MiB, 20 ms apart, and writes spread.done at the end;
// burst.mode writes one file of 1 MiB and burst.done, then extends a second
// file to 2 MiB with a single ftruncate and exits, so its tree goes over a
// limit only in its last step. Each mode writes <mode>.started first. Without
// a mode it records its RLIMIT_FSIZE in probe.out.

#include <fcntl.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>

namespace {

char g_dir[4096];
char g_block[1 << 20];

const char* At(const char* name)
{
    static char path[sizeof(g_dir) + 64];
    std::snprintf(path, sizeof(path), "%s/%s", g_dir, name);
    return path;
}

bool Exists(const char* name)
{
    return access(At(name), F_OK) == 0;
}

void Mark(const char* name)
{
    const int fd = open(At(name), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd >= 0) close(fd);
}

bool WriteBlock(const char* name)
{
    const int fd = open(At(name), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return false;
    const bool full = write(fd, g_block, sizeof(g_block)) == static_cast<ssize_t>(sizeof(g_block));
    return close(fd) == 0 && full;
}

} // namespace

int main(int argc, char** argv)
{
    const char* self = argc > 0 && argv[0] != nullptr ? argv[0] : "";
    const char* slash = std::strrchr(self, '/');
    if (slash == nullptr || static_cast<size_t>(slash - self) >= sizeof(g_dir)) return 2;
    std::memcpy(g_dir, self, static_cast<size_t>(slash - self));
    std::memset(g_block, 'x', sizeof(g_block));
    if (Exists("spread.mode")) {
        Mark("spread.started");
        const timespec pause{0, 20 * 1000 * 1000};
        char name[32];
        for (int i = 0; i < 64; ++i) {
            std::snprintf(name, sizeof(name), "spread%d.bin", i);
            if (!WriteBlock(name)) return 3;
            nanosleep(&pause, nullptr);
        }
        Mark("spread.done");
        return 0;
    }
    if (Exists("burst.mode")) {
        Mark("burst.started");
        if (!WriteBlock("burst0.bin")) return 4;
        Mark("burst.done");
        const int fd = open(At("burst1.bin"), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (fd < 0) return 4;
        const bool extended = ftruncate(fd, 2 << 20) == 0;
        return close(fd) == 0 && extended ? 0 : 4;
    }
    rlimit limit{};
    if (getrlimit(RLIMIT_FSIZE, &limit) != 0) return 5;
    const int fd = open(At("probe.out"), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return 6;
    char line[64];
    const int length = std::snprintf(line, sizeof(line), "fsize=%llu\n", static_cast<unsigned long long>(limit.rlim_cur));
    const bool written = length > 0 && write(fd, line, static_cast<size_t>(length)) == length;
    return close(fd) == 0 && written ? 0 : 7;
}
