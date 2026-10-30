// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <modelnet/swarm_fsjail.h>
#include <modelnet/swarm_confine.h>
#include <modelnet/swarm_process_guard.h>

#if defined(__linux__)

#include <fcntl.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>

#endif

namespace modelnet {
namespace {

SwarmFilesystemJailResult Refuse(const char* code, std::string& err)
{
    SwarmFilesystemJailResult result;
    result.code = code;
    err = code;
    return result;
}

#if defined(__linux__)

constexpr char PUT_OLD_NAME[] = ".btx-fsjail-old";
constexpr char PUT_OLD_IN_JAIL[] = "/.btx-fsjail-old";
constexpr size_t MAP_TEXT_MAX = 64;

bool PathContainsDotDot(const fs::path& path)
{
    for (const auto& part : path) {
        if (part == "..") {
            return true;
        }
    }
    return false;
}

bool LexicallyInside(const fs::path& path, const fs::path& root)
{
    if (PathContainsDotDot(path) || PathContainsDotDot(root)) {
        return false;
    }
    const fs::path relative{path.lexically_relative(root)};
    if (relative.empty()) {
        return false;
    }
    if (relative == fs::path(".")) {
        return true;
    }
    return !PathContainsDotDot(relative);
}

bool WriteAll(const char* path, const char* data, size_t length)
{
    const int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        return false;
    }
    size_t written = 0;
    while (written < length) {
        const ssize_t n = write(fd, data + written, length - written);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(fd);
            return false;
        }
        written += static_cast<size_t>(n);
    }
    return close(fd) == 0;
}

bool MapUser(const char* uid_map, int uid_len, const char* gid_map, int gid_len)
{
    if (uid_map == nullptr || gid_map == nullptr || uid_len <= 0 || gid_len <= 0 ||
        static_cast<size_t>(uid_len) >= MAP_TEXT_MAX || static_cast<size_t>(gid_len) >= MAP_TEXT_MAX) {
        return false;
    }
    if (!WriteAll("/proc/self/setgroups", "deny", 4)) {
        return false;
    }
    if (!WriteAll("/proc/self/uid_map", uid_map, static_cast<size_t>(uid_len))) {
        return false;
    }
    return WriteAll("/proc/self/gid_map", gid_map, static_cast<size_t>(gid_len));
}

bool DirectoryOpenable(const char* path)
{
    const int fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        return false;
    }
    close(fd);
    return true;
}

fs::path SelectWitness(const fs::path& root)
{
    auto consider = [&](const fs::path& candidate) -> fs::path {
        if (candidate.empty() || !candidate.is_absolute() || candidate == fs::path("/")) {
            return {};
        }
        if (candidate == root || LexicallyInside(candidate, root)) {
            return {};
        }
        if (!DirectoryOpenable(candidate.c_str())) {
            return {};
        }
        return candidate;
    };

    const fs::path parent = consider(root.parent_path());
    if (!parent.empty()) {
        return parent;
    }
    const char* fallbacks[] = {"/proc", "/sys", "/dev", "/etc", "/usr", "/bin", "/lib"};
    for (const char* fallback : fallbacks) {
        const fs::path found = consider(fs::path(fallback));
        if (!found.empty()) {
            return found;
        }
    }
    return {};
}

int PivotRoot(const char* new_root, const char* put_old)
{
    return syscall(SYS_pivot_root, new_root, put_old);
}

bool PivotToRoot(const fs::path& root, const fs::path& put_old)
{
    if (mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) != 0) {
        return false;
    }
    if (mount(root.c_str(), root.c_str(), nullptr, MS_BIND | MS_REC, nullptr) != 0) {
        return false;
    }
    if (mkdir(put_old.c_str(), 0700) != 0 && errno != EEXIST) {
        return false;
    }
    if (PivotRoot(root.c_str(), put_old.c_str()) != 0) {
        return false;
    }
    if (chdir("/") != 0) {
        return false;
    }
    if (umount2(PUT_OLD_IN_JAIL, MNT_DETACH) != 0) {
        return false;
    }
    rmdir(PUT_OLD_IN_JAIL);
    return !DirectoryOpenable(PUT_OLD_IN_JAIL);
}

bool ConfinedToRoot(const fs::path& root, const fs::path& put_old, const fs::path& witness)
{
    // The witness was opened in the parent. If it still opens after
    // pivot_root, this process can see a path outside root.
    if (!DirectoryOpenable(witness.c_str())) {
        return false;
    }
    // No chroot fallback: the child keeps CAP_SYS_CHROOT in its user
    // namespace and the old root stays mounted, so a chroot would not confine
    // it, yet the witness check below would pass. pivot_root fails, for
    // example, when the package has a regular file at put_old.
    if (!PivotToRoot(root, put_old)) {
        return false;
    }
    if (DirectoryOpenable(witness.c_str())) {
        return false;
    }
    if (DirectoryOpenable(PUT_OLD_IN_JAIL)) {
        return false;
    }
    return true;
}

#endif // __linux__
} // namespace

SwarmFilesystemJailResult SwarmRunFilesystemJail(const SwarmFilesystemJailRequest& request, std::string& err)
{
    if (request.helper.empty() || request.root.empty()) {
        return Refuse("JAIL", err);
    }
    if (!fs::exists(request.helper) || !fs::is_regular_file(request.helper)) {
        return Refuse("SANDBOX_ABSENT", err);
    }
    if (!request.network_denied) {
        return Refuse("NETWORK", err);
    }
    if (!process_guard::InsideRoot(request.helper, request.root)) {
        return Refuse("PATH", err);
    }

    if (request.max_wall_seconds <= 0 || request.max_wall_seconds > 86400 || request.max_tree_bytes == 0) return Refuse("LIMIT", err);
#if defined(__linux__)
    const fs::path root = request.root;
    const fs::path put_old = root / PUT_OLD_NAME;
    const fs::path witness = SelectWitness(root);
    const fs::path relative{request.helper.lexically_relative(root)};
    const fs::path jailed_helper = fs::path("/") / relative;
    const bool helper_in_jail = !jailed_helper.empty() && jailed_helper != fs::path("/");
    char uid_map[MAP_TEXT_MAX];
    char gid_map[MAP_TEXT_MAX];
    const int uid_len = snprintf(uid_map, sizeof(uid_map), "0 %lu 1\n", static_cast<unsigned long>(geteuid()));
    const int gid_len = snprintf(gid_map, sizeof(gid_map), "0 %lu 1\n", static_cast<unsigned long>(getegid()));

    // max_tree_bytes: RLIMIT_FSIZE caps each file, and the tree below root is
    // checked before launch, every 10 ms while the helper runs and after exit.
    if (!process_guard::TreeWithinLimit(root, request.max_tree_bytes)) return Refuse("TREE_LIMIT", err);
    if (witness.empty()) return Refuse("JAIL_ABSENT", err);
    int pipefd[2];
    if (!process_guard::ErrorPipe(pipefd)) return Refuse("JAIL_ABSENT", err);
    const long fd_max = std::max(1024L, sysconf(_SC_OPEN_MAX));
    char* const argv[]{const_cast<char*>(jailed_helper.c_str()), nullptr};
    char lang[] = "LANG=C", path[] = "PATH=/usr/bin:/bin", offline[] = "HF_HUB_OFFLINE=1";
    char* const env[]{lang, path, offline, nullptr};
    const pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]); close(pipefd[1]);
        return Refuse("JAIL_ABSENT", err);
    }
    if (pid == 0) {
        close(pipefd[0]);
        if (setpgid(0, 0) != 0 || !process_guard::NullStandardDescriptors() ||
            !process_guard::CloseDescriptors(pipefd[1], fd_max)) process_guard::ChildFailure(pipefd[1]);
        constexpr int error_fd = 3;
        // The old implementation forgot CLONE_NEWNET and consequently did
        // not enforce its network_denied contract. Map first; then isolate.
        if (unshare(CLONE_NEWUSER) != 0 ||
            !MapUser(uid_map, uid_len, gid_map, gid_len) ||
            unshare(CLONE_NEWNS | CLONE_NEWNET) != 0 || !helper_in_jail ||
            !ConfinedToRoot(root, put_old, witness) ||
            prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
            !process_guard::Limit(RLIMIT_CPU, static_cast<rlim_t>(request.max_wall_seconds)) ||
            !process_guard::Limit(RLIMIT_NOFILE, 256) ||
            !process_guard::Limit(RLIMIT_FSIZE, static_cast<rlim_t>(request.max_tree_bytes))) process_guard::ChildFailure(error_fd);
        if (!process_guard::ChildReady(error_fd)) process_guard::ChildFailure(error_fd);
        execve(jailed_helper.c_str(), argv, env);
        process_guard::ChildFailure(error_fd);
    }
    close(pipefd[1]);
    const auto waited =
        process_guard::Wait(pid, pipefd[0], request.max_wall_seconds, 0, 0, root, request.max_tree_bytes);
    if (!waited.executed) {
        return Refuse(waited.timed_out ? "JAIL_TIMEOUT" : waited.over_tree ? "TREE_LIMIT" : "JAIL_ABSENT", err);
    }
    if (!process_guard::TreeWithinLimit(root, request.max_tree_bytes)) return Refuse("TREE_LIMIT", err);
    SwarmFilesystemJailResult result;
    result.launched = true; result.jailed = true; result.code = "JAILED";
    result.child_status = waited.status;
    err.clear(); return result;
#elif defined(__APPLE__) || defined(_WIN32)
    // Seatbelt and AppContainer enforce native filesystem/network policy.
    // Their OS runtime resources are documented platform exceptions.
    SwarmConfineRequest confined;
    confined.helper = request.helper; confined.root = request.root;
    confined.max_address_bytes = 8LL * 1024 * 1024 * 1024;
    confined.max_cpu_seconds = request.max_wall_seconds;
    confined.max_nofile = 256;
    confined.max_wall_seconds = request.max_wall_seconds;
    confined.max_tree_bytes = request.max_tree_bytes;
    confined.network_denied = true;
    const auto run = SwarmRunConfined(confined, err);
    if (!run.launched) {
        return Refuse(run.code == "CONFINEMENT_TIMEOUT" ? "JAIL_TIMEOUT" :
                      run.code == "TREE_LIMIT" ? "TREE_LIMIT" : "JAIL_ABSENT", err);
    }
    SwarmFilesystemJailResult result;
    result.launched = true; result.jailed = true; result.code = "JAILED";
    result.child_status = run.child_status;
    err.clear(); return result;
#else
    return Refuse("JAIL_ABSENT", err);
#endif
}

} // namespace modelnet
