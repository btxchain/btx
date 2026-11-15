// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

// Standalone Windows compile/runtime regression; no node or wallet required.
// Keep the compatibility header first so missing CRT includes are observable.
#ifdef BTX_CORE_FIRST
#include <compat/compat.h>
#endif
#include <compat/mingw/posix_extra.h>
#include <compat/compat.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <type_traits>

static_assert(sizeof(ssize_t) == sizeof(void*));
static_assert(std::is_signed_v<ssize_t>);
#ifdef _MSC_VER
static_assert(std::is_same_v<ssize_t, SSIZE_T>);
#endif

int main(int argc, char** argv)
{
    if (argc != 2) return 1;
    const char* name = "BTX_POSIX_HEADER_REGRESSION";
    const char* original = std::getenv(name);
    const bool had_original = original != nullptr;
    const std::string old = had_original ? original : "";
    const auto restore_environment = [&] {
        return had_original ? setenv(name, old.c_str(), 1) : unsetenv(name);
    };
    if (setenv(name, "first", 1) != 0) return 2;
    if (setenv(name, "second", 0) != 0 || !std::getenv(name) ||
        std::strcmp(std::getenv(name), "first") != 0) return 3;
    if (setenv(name, "second", 1) != 0 || !std::getenv(name) ||
        std::strcmp(std::getenv(name), "second") != 0) return 4;
    if (unsetenv(name) != 0 || std::getenv(name) != nullptr) return 5;
    if (restore_environment() != 0) return 6;

    const int fd = _open(argv[1], _O_CREAT | _O_EXCL | _O_RDWR | _O_BINARY,
                         _S_IREAD | _S_IWRITE);
    if (fd < 0) return 7;
    int result = 0;
    char bytes[7]{};
    if (_write(fd, "abcdef", 6) != 6) result = 8;
    if (!result && (btx_pread(fd, bytes, 3, 1) != 3 ||
                    std::memcmp(bytes, "bcd", 3) != 0 ||
                    _lseeki64(fd, 0, SEEK_CUR) != 6)) result = 9;
    if (!result && (btx_pwrite(fd, "XY", 2, 2) != 2 ||
                    _lseeki64(fd, 0, SEEK_CUR) != 6)) result = 10;
    if (!result && (btx_pread(fd, bytes, 6, 0) != 6 ||
                    std::memcmp(bytes, "abXYef", 6) != 0)) result = 11;
    if (!result && btx_fsync(fd) != 0) result = 12;
    if (_close(fd) != 0 && !result) result = 13;
    if (std::remove(argv[1]) != 0 && !result) result = 14;
    if (result) return result;

    errno = 0;
    if (btx_fork() != -1 || errno != ENOSYS) return 15;
    std::puts("PASS: native type, include order, environment and file controls");
    return 0;
}
