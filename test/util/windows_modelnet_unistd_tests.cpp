// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

// Standalone native-compiler include-route control. This is not test_btx.
#include <unistd.h>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <string>

#if !defined(_MSC_VER) || !defined(BITCOIN_COMPAT_MSVC_UNISTD_H)
#error This control must resolve the native Modelnet unistd adapter.
#endif

int main()
{
    unsigned checks = 0;
    const auto check = [&](bool ok, const char* what) {
        if (!ok) { std::fprintf(stderr, "FAIL: %s\n", what); std::exit(1); }
        ++checks;
    };
    const std::string name = "BTX_UNISTD_ROUTE_" + std::to_string(GetCurrentProcessId());
    check(std::getenv(name.c_str()) == nullptr, "isolated environment name");
    check(setenv(name.c_str(), "first", 1) == 0, "set through adapter");
    check(setenv(name.c_str(), "second", 0) == 0 && std::string(std::getenv(name.c_str())) == "first", "overwrite refusal");
    check(setenv(name.c_str(), "second", 1) == 0 && std::string(std::getenv(name.c_str())) == "second", "overwrite permitted");
    check(unsetenv(name.c_str()) == 0 && std::getenv(name.c_str()) == nullptr, "environment cleanup");
    int fds[2] = {-1, -1};
    check(pipe(fds) == 0, "binary pipe available");
    const std::array<unsigned char, 6> input{0, 10, 13, 26, 128, 255};
    std::array<unsigned char, 6> output{};
    check(_write(fds[1], input.data(), static_cast<unsigned>(input.size())) == static_cast<int>(input.size()), "pipe write");
    check(_read(fds[0], output.data(), static_cast<unsigned>(output.size())) == static_cast<int>(output.size()) && input == output, "binary pipe bytes");
    const int close_read = _close(fds[0]);
    const int close_write = _close(fds[1]);
    check(close_read == 0 && close_write == 0, "pipe cleanup");
    errno = 0;
    check(fork() == -1 && errno == ENOSYS, "unsupported fork remains refused");
    std::printf("PASS %u direct-header checks\n", checks);
    return 0;
}
