#pragma once
#include <stdint.h>
#include <windows.h>

struct statvfs {
    unsigned long f_bsize;
    unsigned long f_frsize;
    uint64_t f_blocks;
    uint64_t f_bfree;
    uint64_t f_bavail;
};

inline int statvfs(const wchar_t* path, struct statvfs* out)
{
    if (path == nullptr || out == nullptr) return -1;
    ULARGE_INTEGER avail{};
    ULARGE_INTEGER total{};
    ULARGE_INTEGER free_bytes{};
    if (!GetDiskFreeSpaceExW(path, &avail, &total, &free_bytes)) return -1;
    out->f_bsize = 1;
    out->f_frsize = 1;
    out->f_blocks = total.QuadPart;
    out->f_bfree = free_bytes.QuadPart;
    out->f_bavail = avail.QuadPart;
    return 0;
}

inline int statvfs(const char* path, struct statvfs* out)
{
    if (path == nullptr || out == nullptr) return -1;
    ULARGE_INTEGER avail{};
    ULARGE_INTEGER total{};
    ULARGE_INTEGER free_bytes{};
    if (!GetDiskFreeSpaceExA(path, &avail, &total, &free_bytes)) return -1;
    out->f_bsize = 1;
    out->f_frsize = 1;
    out->f_blocks = total.QuadPart;
    out->f_bfree = free_bytes.QuadPart;
    out->f_bavail = avail.QuadPart;
    return 0;
}
