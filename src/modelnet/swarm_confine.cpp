// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license. See COPYING.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <modelnet/swarm_confine.h>
#include <modelnet/swarm_process_guard.h>
#include <modelnet/swarm_windows_sandbox.h>

namespace modelnet {
namespace {
SwarmConfineResult Refuse(const char* code, std::string& err)
{
    SwarmConfineResult result;
    result.code = code; err = code; return result;
}
}
SwarmConfineResult SwarmRunConfined(const SwarmConfineRequest& request, std::string& err)
{
    if (request.helper.empty() || request.root.empty()) return Refuse("CONFINEMENT", err);
    std::error_code ec;
    if (!fs::is_regular_file(request.helper, ec) || ec) return Refuse("SANDBOX_ABSENT", err);
    if (!request.network_denied) return Refuse("NETWORK", err);
    if (request.max_address_bytes <= 0 || request.max_cpu_seconds <= 0 || request.max_nofile < 4 ||
        request.max_wall_seconds <= 0 || request.max_wall_seconds > 86400) return Refuse("LIMIT", err);
    if (!process_guard::InsideRoot(request.helper, request.root)) return Refuse("PATH", err);
#if defined(__linux__) || defined(__APPLE__)
    // max_tree_bytes: RLIMIT_FSIZE caps each file during the run, and the
    // whole tree below root is checked before launch, every 10 ms while the
    // helper runs (process_guard::Wait, in this unconfined parent) and after
    // exit.
    if (request.max_tree_bytes == 0) return Refuse("LIMIT", err);
    if (!process_guard::TreeWithinLimit(request.root, request.max_tree_bytes)) return Refuse("TREE_LIMIT", err);
#ifdef __APPLE__
    const process_guard::Seatbelt seatbelt;
    if (!seatbelt.Available()) return Refuse("CONFINEMENT_ABSENT", err);
    // Opens before the profile and must not open after it (checked in the child).
    const fs::path witness = process_guard::SeatbeltWitness(request.root);
    if (witness.empty()) return Refuse("CONFINEMENT_ABSENT", err);
    // The kernel enforces neither limit fully here; process_guard::Wait does.
    const uint64_t max_footprint_bytes = static_cast<uint64_t>(request.max_address_bytes);
    const int max_cpu_seconds = request.max_cpu_seconds;
#else
    const uint64_t max_footprint_bytes = 0;
    const int max_cpu_seconds = 0;
#endif
    int pipefd[2];
    if (!process_guard::ErrorPipe(pipefd)) return Refuse("CONFINEMENT_ABSENT", err);
    const long fd_max = std::max(1024L, sysconf(_SC_OPEN_MAX));
    // Construct everything before fork: no allocating C++ operations in child.
    char* const argv[]{const_cast<char*>(request.helper.c_str()), nullptr};
    char lang[] = "LANG=C", path[] = "PATH=/usr/bin:/bin", offline[] = "HF_HUB_OFFLINE=1";
    char* const env[]{lang, path, offline, nullptr};
    const pid_t pid = fork();
    if (pid < 0) { close(pipefd[0]); close(pipefd[1]); return Refuse("CONFINEMENT_ABSENT", err); }
    if (pid == 0) {
        close(pipefd[0]);
        if (setpgid(0, 0) != 0 || !process_guard::NullStandardDescriptors() ||
            !process_guard::CloseDescriptors(pipefd[1], fd_max)) process_guard::ChildFailure(pipefd[1]);
        constexpr int error_fd = 3;
        if (
#ifndef __APPLE__
            !process_guard::Limit(RLIMIT_AS, static_cast<rlim_t>(request.max_address_bytes)) ||
#endif
            !process_guard::Limit(RLIMIT_FSIZE, static_cast<rlim_t>(request.max_tree_bytes)) ||
            !process_guard::Limit(RLIMIT_CPU, static_cast<rlim_t>(request.max_cpu_seconds)) ||
            !process_guard::Limit(RLIMIT_NOFILE, static_cast<rlim_t>(request.max_nofile)) ||
            chdir(request.root.c_str()) != 0) process_guard::ChildFailure(error_fd);
#ifdef __linux__
        if (unshare(CLONE_NEWUSER | CLONE_NEWNET) != 0 ||
            prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) process_guard::ChildFailure(error_fd);
#else
        // Exec only after the child proves the profile: the witness stops
        // opening and a loopback bind is refused.
        if (!process_guard::DirectoryOpenable(witness.c_str()) ||
            !seatbelt.Apply(request.root.c_str(), request.helper.c_str()) ||
            process_guard::DirectoryOpenable(witness.c_str()) ||
            !process_guard::NetworkProvenDenied()) process_guard::ChildFailure(error_fd);
#endif
        if (!process_guard::ChildReady(error_fd)) process_guard::ChildFailure(error_fd);
        execve(request.helper.c_str(), argv, env);
        process_guard::ChildFailure(error_fd);
    }
    close(pipefd[1]);
    const auto waited = process_guard::Wait(pid, pipefd[0], request.max_wall_seconds, max_footprint_bytes,
                                            max_cpu_seconds, request.root, request.max_tree_bytes);
    if (!waited.executed) {
        return Refuse(waited.timed_out ? "CONFINEMENT_TIMEOUT" :
                      waited.over_tree ? "TREE_LIMIT" : "CONFINEMENT_ABSENT", err);
    }
    if (!process_guard::TreeWithinLimit(request.root, request.max_tree_bytes)) return Refuse("TREE_LIMIT", err);
    SwarmConfineResult result;
    result.launched = true; result.limits_applied = true;
    result.child_status = waited.status; result.code = "CONFINED";
    err.clear(); return result;
#elif defined(_WIN32)
    return SwarmRunWindowsAppContainer(request,err);
#else
    // Unsupported kernels remain an explicit deployment blocker.
    return Refuse("CONFINEMENT_ABSENT", err);
#endif
}
} // namespace modelnet
