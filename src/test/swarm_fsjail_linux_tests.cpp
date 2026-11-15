// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

// Dedicated target: report fault injection must never wrap production binaries
// or unrelated test_btx tests. A real static worker runs inside the actual jail.
#include <modelnet/swarm_fsjail.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#include <algorithm>
#include <cstdlib>
#include <csignal>
#include <stdexcept>
#include <fstream>
#include <iostream>
#include <string>

namespace {
int g_fault{0};
bool g_reporting{false};

struct TempRoot {
    fs::path path;
    TempRoot()
    {
        std::string name = (fs::canonical(fs::temp_directory_path()) / "btx-fsjail-supervision-XXXXXX").native();
        char* created = mkdtemp(name.data());
        if (created == nullptr) throw std::runtime_error("mkdtemp failed");
        path = fs::path{created};
    }
    ~TempRoot() { std::error_code ignored; fs::remove_all(path, ignored); }
};
}

extern "C" pid_t __real_waitpid(pid_t, int*, int);
extern "C" ssize_t __real_write(int, const void*, size_t);
extern "C" pid_t __wrap_waitpid(pid_t pid, int* status, int options)
{
    const pid_t result = __real_waitpid(pid, status, options);
    // Init alone waits for any child; the outer wrapper waits for a positive PID.
    if (pid == -1 && result > 0) g_reporting = true;
    return result;
}
extern "C" ssize_t __wrap_write(int fd, const void* data, size_t size)
{
    if (g_reporting && size == sizeof(int)) {
        if (g_fault == 1) return 0;
        if (g_fault == 2) return __real_write(fd, data, sizeof(int) / 2);
        if (g_fault == 3) _exit(0);
        if (g_fault == 4) {
            const int stopped = (SIGSTOP << 8) | 0x7f;
            return __real_write(fd, &stopped, sizeof(stopped));
        }
    }
    return __real_write(fd, data, size);
}

int main(int argc, char** argv)
{
    if (argc != 2) return 2;
    try {
        rlimit inherited{};
        if (getrlimit(RLIMIT_AS, &inherited) != 0) return 2;
        const auto expected_cap = static_cast<unsigned long long>(std::min<rlim_t>(8ULL << 30, inherited.rlim_max));
        const std::string expected = "pid=2 cap=" + std::to_string(expected_cap) + " hard=" +
                                     std::to_string(expected_cap) + " child=17";
        int failed = 0;
        for (int scenario = 0; scenario < 12; ++scenario) {
            TempRoot root;
            const fs::path helper = root.path / "worker";
            fs::copy_file(fs::path{argv[1]}, helper, fs::copy_options::none);
            const int exit_code = scenario == 1 ? 37 : scenario == 2 ? 126 : scenario == 3 ? 99 : 0;
            { std::ofstream mode{root.path / "mode"}; mode << exit_code; if (!mode) return 2; }
            g_fault = scenario >= 4 && scenario <= 7 ? scenario - 3 : 0;
            g_reporting = false;
            modelnet::SwarmFilesystemJailRequest request;
            request.root = root.path;
            request.helper = helper;
            request.network_denied = true;
            request.max_wall_seconds = 3;
            request.max_tree_bytes = 8 << 20;
            // Preserve legitimate refusal controls: failed exec, pivot setup,
            // pre-launch tree limit and unsupported network policy.
            if (scenario == 8) { std::ofstream bad{helper, std::ios::trunc}; bad << "not executable"; }
            if (scenario == 9) { std::ofstream blocker{root.path / ".btx-fsjail-old"}; blocker << 'x'; }
            if (scenario == 10) request.max_tree_bytes = 1;
            if (scenario == 11) request.network_denied = false;
            std::string error;
            const auto result = modelnet::SwarmRunFilesystemJail(request, error);
            if (scenario == 0 && result.code == "JAIL_ABSENT") {
                std::cout << "Linux namespace jail unavailable; no runtime coverage\n";
                return std::getenv("BTX_TEST_REQUIRE_LINUX_JAIL") != nullptr ? 1 : 77;
            }
            std::ifstream output{root.path / "result"};
            std::string observed;
            std::getline(output, observed);
            const bool ran = scenario < 8;
            const char* refusal = scenario == 10 ? "TREE_LIMIT" : scenario == 11 ? "NETWORK" : "JAIL_ABSENT";
            const bool refused = scenario >= 3;
            const bool correct_result = refused ?
                (!result.launched && !result.jailed && result.code == refusal && error == refusal) :
                (result.launched && result.jailed && result.code == "JAILED" && error.empty() && result.child_status == (exit_code << 8));
            const bool correct_worker = ran ? observed == expected : observed.empty();
            const bool passed = correct_result && correct_worker;
            std::cout << "scenario=" << scenario << " fault=" << g_fault << " exit=" << exit_code
                      << " code=" << result.code << " status=" << result.child_status
                      << " worker=[" << observed << "] pass=" << passed << '\n';
            if (!passed) ++failed;
        }
        return failed == 0 ? 0 : 1;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 2;
    }
}
