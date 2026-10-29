// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license. See COPYING.
#ifndef BITCOIN_MODELNET_SWARM_PROCESS_GUARD_H
#define BITCOIN_MODELNET_SWARM_PROCESS_GUARD_H

#include <util/fs.h>
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <functional>
#include <string>
#include <thread>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef __linux__
#include <sched.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#endif
#ifdef __APPLE__
#include <arpa/inet.h>
#include <dlfcn.h>
#include <libproc.h>
#include <mach/mach_time.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif
#endif

namespace modelnet::process_guard {

/** Check every path component. canonical() alone would silently follow links. */
inline bool NoSymlinkPath(const fs::path& path)
{
    if (!path.is_absolute()) return false;
#ifdef _WIN32
    // Reject UNC/device namespaces, alternate data streams and all reparse
    // points (junctions are broader than std::filesystem symlinks).
    const auto spelling=path.native();
    if(spelling.size()<3 || spelling[1]!=L':' || spelling.find(L':',2)!=std::wstring::npos ||
       spelling.starts_with(L"\\"))return false;
#endif
    std::error_code ec;
    fs::path cursor;
    for (const auto& component : path) {
        if (component == "..") return false;
        cursor /= component;
#ifdef _WIN32
        if(!cursor.is_absolute())continue;
        const DWORD attributes=GetFileAttributesW(cursor.c_str());
        if(attributes==INVALID_FILE_ATTRIBUTES || (attributes&FILE_ATTRIBUTE_REPARSE_POINT))return false;
#endif
        const auto status = fs::symlink_status(cursor, ec);
        if (ec || fs::is_symlink(status)) return false;
    }
    return true;
}

inline bool InsideRoot(const fs::path& helper, const fs::path& root)
{
    if (!NoSymlinkPath(root) || !NoSymlinkPath(helper)) return false;
    std::error_code ec;
    if (!fs::is_directory(root, ec) || ec || !fs::is_regular_file(helper, ec) || ec) return false;
    const fs::path relative{helper.lexically_normal().lexically_relative(root.lexically_normal())};
    if (relative.empty() || relative == fs::path(".") || relative.is_absolute()) return false;
    for (const auto& part : relative) if (part == "..") return false;
    return true;
}

#ifndef _WIN32
inline bool Limit(int resource, rlim_t value)
{
    rlimit current{};
    if (getrlimit(resource, &current) != 0) return false;
    const rlim_t bounded = std::min(value, current.rlim_max);
    const rlimit limit{bounded, bounded};
    return bounded != 0 && setrlimit(resource, &limit) == 0;
}

inline bool ErrorPipe(int (&fds)[2])
{
    if (pipe(fds) != 0) return false;
    for (int fd : fds) {
        if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
            close(fds[0]); close(fds[1]); return false;
        }
    }
    return true;
}

[[noreturn]] inline void ChildFailure(int fd)
{
    int error = errno == 0 ? EACCES : errno;
    const auto* bytes = reinterpret_cast<const char*>(&error);
    size_t written = 0;
    while (written < sizeof(error)) {
        const ssize_t n = write(fd, bytes + written, sizeof(error) - written);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        written += static_cast<size_t>(n);
    }
    _exit(126);
}

/** No inherited wallet/RPC descriptors or process environment survive exec. */
inline bool ChildReady(int fd)
{
    const int ready = 0;
    ssize_t n;
    do { n = write(fd, &ready, sizeof(ready)); } while (n < 0 && errno == EINTR);
    return n == static_cast<ssize_t>(sizeof(ready));
}

inline bool CloseDescriptors(int error_fd, long maximum)
{
    if (error_fd != 3) {
        if (dup2(error_fd, 3) < 0) return false;
        close(error_fd);
    }
    if (fcntl(3, F_SETFD, FD_CLOEXEC) < 0) return false;
#ifdef __linux__
#ifdef SYS_close_range
    if (syscall(SYS_close_range, 4U, ~0U, 0U) == 0) return true;
    if (errno != ENOSYS && errno != EINVAL) return false;
#endif
#endif
    // maximum is captured in the parent before reducing RLIMIT_NOFILE.
    for (long fd = 4; fd < maximum; ++fd) close(static_cast<int>(fd));
    return true;
}

inline bool NullStandardDescriptors()
{
    const int fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (fd < 0) return false;
    bool ok = true;
    for (int target = 0; target < 3; ++target) if (dup2(fd, target) < 0) ok = false;
    if (fd > 2) close(fd);
    return ok;
}

/**
 * True while the regular files below root total at most limit. Symbolic
 * links, other file types, more than 8192 entries, a depth above 64 or any
 * error reading the tree count as over the limit. Shared by the filesystem
 * jail and the confinement (before launch, while the helper runs, and after
 * exit). With running set, an entry that is gone by the time it is read is
 * skipped: a helper that is still running may rename or delete its files.
 * during, if set, is called after every 256 entries, so a caller can keep
 * its other checks going while a large tree is walked.
 */
inline bool TreeWithinLimit(const fs::path& root, uint64_t limit, bool running = false,
                            const std::function<void()>& during = {})
{
    std::error_code ec;
    uint64_t total = 0;
    size_t entries = 0;
    size_t vanished_steps = 0;
    fs::recursive_directory_iterator current(root, fs::directory_options::none, ec), end;
    if (ec) return false;
    const auto vanished = [&] {
        std::error_code missing;
        return running && fs::symlink_status(current->path(), missing).type() == fs::file_type::not_found;
    };
    for (; current != end; current.increment(ec)) {
        if (ec) {
            // readdir can report an entry the helper already removed. Cap the
            // skips so an iterator that does not advance cannot spin.
            if (running && ec == std::errc::no_such_file_or_directory && ++vanished_steps < 64) {
                ec.clear();
                continue;
            }
            return false;
        }
        vanished_steps = 0;
        if (++entries > 8192 || current.depth() > 64) return false;
        if (during && entries % 256 == 0) during();
        if (!NoSymlinkPath(current->path())) {
            std::error_code leaf;
            const auto kind = fs::symlink_status(current->path(), leaf);
            const bool missing = leaf == std::errc::no_such_file_or_directory || kind.type() == fs::file_type::not_found;
            if (running && missing) {
                current.disable_recursion_pending();
                continue;
            }
            if (!(running && !leaf && (kind.type() == fs::file_type::regular || kind.type() == fs::file_type::directory))) {
                return false;
            }
        }
        if (current->is_directory(ec)) {
            if (!ec) continue;
            if (running && (ec == std::errc::no_such_file_or_directory || vanished())) {
                ec.clear();
                current.disable_recursion_pending();
                continue;
            }
            return false;
        }
        // A rename or unlink between the directory read and this stat is not
        // growth. ENOENT stays a skip even if the helper recreates the name
        // before a second stat. Only a live non-file counts as over the limit.
        if (!current->is_regular_file(ec) || ec) {
            if (running && (ec == std::errc::no_such_file_or_directory || vanished())) {
                ec.clear();
                continue;
            }
            return false;
        }
        const auto size = current->file_size(ec);
        if (ec && running && (ec == std::errc::no_such_file_or_directory || vanished())) {
            ec.clear();
            continue;
        }
        if (ec) return false;
        const auto bytes = static_cast<uint64_t>(size);
        if (bytes > limit || total > limit - bytes) return false;
        total += bytes;
    }
    return !ec;
}

#ifdef __APPLE__
inline bool DirectoryOpenable(const char* path)
{
    const int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return false;
    close(fd);
    return true;
}

/** A directory outside root that the Seatbelt profile does not allow to be read. */
inline fs::path SeatbeltWitness(const fs::path& root)
{
    for (const fs::path& candidate : {root.parent_path(), fs::path{"/private/etc"}}) {
        if (candidate.empty() || candidate == candidate.root_path()) continue;
        if (!DirectoryOpenable(candidate.c_str())) continue;
        bool readable = false;
        for (const char* allowed : {"/System/Library", "/usr/lib"}) {
            const fs::path relative{candidate.lexically_relative(allowed)};
            if (!relative.empty() && *relative.begin() != "..") readable = true;
        }
        if (!readable) return candidate;
    }
    return {};
}

/** Only a refused loopback UDP bind proves that the profile denies the network. */
inline bool NetworkProvenDenied()
{
    const int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return errno == EPERM || errno == EACCES;
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    const bool bound = bind(fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == 0;
    const int error = errno;
    close(fd);
    return !bound && (error == EPERM || error == EACCES);
}

/**
 * True once the child is above a limit the macOS kernel does not enforce:
 * its physical footprint (macOS refuses an RLIMIT_AS below the address
 * space a process already maps, far above any useful limit), or its CPU time
 * 250 ms past max_cpu_seconds (macOS only sends SIGXCPU at RLIMIT_CPU, so a
 * helper that ignores it keeps running). 0 turns a limit off.
 */
inline bool OverLimits(pid_t pid, uint64_t max_footprint_bytes, int max_cpu_seconds)
{
    rusage_info_v4 usage{};
    if (proc_pid_rusage(pid, RUSAGE_INFO_V4, reinterpret_cast<rusage_info_t*>(&usage)) != 0) return false;
    if (max_footprint_bytes != 0 && usage.ri_phys_footprint > max_footprint_bytes) return true;
    if (max_cpu_seconds <= 0) return false;
    mach_timebase_info_data_t base{};
    if (mach_timebase_info(&base) != KERN_SUCCESS || base.denom == 0) return false;
    // ri_user_time and ri_system_time are Mach absolute-time ticks.
    const uint64_t cpu_ns = (usage.ri_user_time + usage.ri_system_time) * base.numer / base.denom;
    return cpu_ns > static_cast<uint64_t>(max_cpu_seconds) * 1'000'000'000ULL + 250'000'000ULL;
}
#endif

struct WaitResult {
    bool executed{false};
    bool timed_out{false};
    bool over_tree{false};
    int status{-1};
    int setup_errno{0};
};

/**
 * max_footprint_bytes and max_cpu_seconds (macOS only, 0 = off): see
 * OverLimits. Both are sampled every 10 ms; a child can overshoot by what it
 * touches or computes within one interval. The SIGKILL to its process group
 * reads as a signal, i.e. not executed.
 * max_tree_bytes (0 = off): the tree below tree_root is checked with
 * TreeWithinLimit at the same interval, and the process group gets SIGKILL
 * once it is over (over_tree). A failed walk is repeated once before the
 * kill, since a directory removed during a walk ends it early. A walk reads
 * every entry below tree_root, so a large tree lengthens the interval. On
 * macOS the walk also checks the footprint and CPU limits every 256 entries,
 * so a large tree does not delay them.
 */
inline WaitResult Wait(pid_t child, int error_fd, int wall_seconds, uint64_t max_footprint_bytes = 0,
                       int max_cpu_seconds = 0, const fs::path& tree_root = {}, uint64_t max_tree_bytes = 0)
{
    WaitResult result;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(wall_seconds);
#ifdef __APPLE__
    // Every 10 ms, and every 256 entries of a tree walk.
    const std::function<void()> limits = [&] {
        if (OverLimits(child, max_footprint_bytes, max_cpu_seconds)) {
            kill(-child, SIGKILL);
            kill(child, SIGKILL);
        }
    };
#else
    (void)max_footprint_bytes;
    (void)max_cpu_seconds;
    const std::function<void()> limits;
#endif
    while (true) {
        const pid_t done = waitpid(child, &result.status, WNOHANG);
        if (done == child) break;
        if (done < 0 && errno != EINTR) { close(error_fd); return result; }
        if (max_tree_bytes != 0 && !TreeWithinLimit(tree_root, max_tree_bytes, true, limits) &&
            !TreeWithinLimit(tree_root, max_tree_bytes, true, limits)) {
            result.over_tree = true;
            kill(-child, SIGKILL);
            kill(child, SIGKILL);
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            result.timed_out = true;
            // Only the dedicated process group created by this invocation.
            kill(-child, SIGKILL);
            kill(child, SIGKILL);
            while (waitpid(child, &result.status, 0) < 0 && errno == EINTR) {}
            break;
        }
        if (limits) limits();
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    int messages[2]{-1, -1};
    size_t got = 0;
    while (got < sizeof(messages)) {
        const ssize_t n = read(error_fd, reinterpret_cast<char*>(messages) + got, sizeof(messages) - got);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        got += static_cast<size_t>(n);
    }
    close(error_fd);
    result.setup_errno = got >= sizeof(int) && messages[0] != 0 ? messages[0] :
                         got == sizeof(messages) ? messages[1] : 0;
    // A ready marker followed by CLOEXEC EOF and normal exit proves setup
    // completed and exec did not report failure. Signals are ambiguous.
    result.executed = got == sizeof(int) && messages[0] == 0 &&
                      WIFEXITED(result.status) && !result.timed_out;
    return result;
}

#ifdef __APPLE__
/** The SDK's removed named sandbox profiles are deliberately not used. */
class Seatbelt {
    using Init = int (*)(const char*, uint64_t, const char* const*, char**);
    using FreeError = void (*)(char*);
    using Check = int (*)(pid_t, const char*, int, ...);
    void* m_library{nullptr};
    Init m_init{nullptr};
    FreeError m_free{nullptr};
    Check m_check{nullptr};
public:
    Seatbelt()
    {
        m_library = dlopen("/usr/lib/libsandbox.dylib", RTLD_NOW | RTLD_LOCAL);
        if (!m_library) return;
        m_init = reinterpret_cast<Init>(dlsym(m_library, "sandbox_init_with_parameters"));
        m_free = reinterpret_cast<FreeError>(dlsym(m_library, "sandbox_free_error"));
        m_check = reinterpret_cast<Check>(dlsym(m_library, "sandbox_check"));
    }
    ~Seatbelt() { if (m_library) dlclose(m_library); }
    bool Available() const { return m_init && m_free && m_check; }
    bool Apply(const char* root, const char* helper) const
    {
        if (!Available()) return false;
        static constexpr const char* profile =
            "(version 1)\n(deny default)\n"
            "(deny network*)\n"
            "(allow process-exec (literal (param \"HELPER\")))\n"
            // dyld reads "/" itself when it starts a binary. Without it every
            // helper aborts (SIGABRT) before main. Only the directory, not below.
            "(allow file-read* (literal \"/\") (subpath (param \"ROOT\"))"
            " (subpath \"/System/Library\") (subpath \"/usr/lib\")"
            " (literal \"/dev/null\") (literal \"/dev/urandom\") (literal \"/dev/random\"))\n"
            "(allow file-write* (subpath (param \"ROOT\")) (literal \"/dev/null\"))\n"
            // sysctl KERN_PROCARGS2 returns argv and the environment of any
            // process of this user, the parent included. It stays open while
            // sysctl-read is allowed for every name or process-info is not
            // denied ((deny default) does not cover it), so allow only the
            // hardware and OS identification names and deny process-info.
            // uname() also reads kern.hostname and fails without it.
            "(allow sysctl-read (sysctl-name-prefix \"hw.\") (sysctl-name-prefix \"kern.os\")"
            " (sysctl-name \"kern.version\") (sysctl-name \"kern.hostname\"))\n"
            "(deny process-info*)\n";
        const char* params[]{"ROOT", root, "HELPER", helper, nullptr};
        char* error = nullptr;
        const int rc = m_init(profile, 0, params, &error);
        if (error) m_free(error);
        return rc == 0 && m_check(getpid(), nullptr, 0) == 1;
    }
};
#endif
#endif // !_WIN32
} // namespace modelnet::process_guard
#endif
