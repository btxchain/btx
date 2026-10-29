// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_confine.h>
#include <modelnet/swarm_process_guard.h>
#include <test/util/setup_common.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <sys/stat.h>
#include <sys/wait.h>

#ifndef _WIN32
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#endif
#ifdef __linux__
#include <sys/prctl.h>
#endif

#include <cerrno>
#include <chrono>
#include <fstream>
#include <iterator>
#include <string>
#include <thread>
#include <vector>

namespace {

modelnet::SwarmConfineRequest BaseRequest(const fs::path& helper, const fs::path& root)
{
    modelnet::SwarmConfineRequest request;
    request.helper = helper;
    request.root = root;
    request.max_address_bytes = 8LL * 1024 * 1024 * 1024 * 1024;
    request.max_cpu_seconds = 30;
    request.max_nofile = 64;
    request.network_denied = true;
    return request;
}

void ExpectRefusal(const modelnet::SwarmConfineRequest& request, const char* code)
{
    std::string err = "stale";
    const modelnet::SwarmConfineResult result = modelnet::SwarmRunConfined(request, err);
    BOOST_CHECK(!result.launched);
    BOOST_CHECK(!result.limits_applied);
    BOOST_CHECK_EQUAL(result.child_status, -1);
    BOOST_CHECK_EQUAL(result.code, code);
    BOOST_CHECK_EQUAL(err, code);
}

fs::path WriteRegularFile(const fs::path& path)
{
    fs::create_directories(path.parent_path());
    std::ofstream out{path};
    BOOST_REQUIRE(out);
    out << "probe\n";
    BOOST_REQUIRE(out);
    return path;
}

} // namespace

#ifndef _WIN32
namespace {

// Resolved: InsideRoot refuses symlinks, and macOS TMPDIR is below /var.
fs::path FreshRoot(const char* name)
{
    const fs::path root = fs::canonical(fs::temp_directory_path()) / name;
    fs::remove_all(root);
    fs::create_directories(root);
    return root;
}

int CountFiles(const fs::path& root, const std::string& prefix)
{
    int count = 0;
    for (const auto& entry : fs::directory_iterator(root)) {
        if (entry.path().filename().native().rfind(prefix, 0) == 0) ++count;
    }
    return count;
}

volatile sig_atomic_t g_child_signals{0};

void CountChildSignal(int)
{
    g_child_signals = g_child_signals + 1;
}

// Every child that ends sends SIGCHLD, so 0 shows that call started no
// helper. A refusal before launch has to hold on its own: the tree check
// while the helper runs would refuse the same root, but only after fork.
template <typename Call>
int ChildSignalsDuring(Call call)
{
    struct sigaction action{}, previous{};
    action.sa_handler = CountChildSignal;
    action.sa_flags = SA_RESTART;
    sigemptyset(&action.sa_mask);
    g_child_signals = 0;
    BOOST_REQUIRE(sigaction(SIGCHLD, &action, &previous) == 0);
    call();
    BOOST_REQUIRE(sigaction(SIGCHLD, &previous, nullptr) == 0);
    return g_child_signals;
}

} // namespace
#endif

BOOST_FIXTURE_TEST_SUITE(swarm_confine_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_helper_or_root)
{
    ExpectRefusal(BaseRequest(fs::path{}, fs::temp_directory_path()), "CONFINEMENT");
    const fs::path helper = WriteRegularFile(fs::temp_directory_path() / "btx-swarm-confine-empty-helper");
    ExpectRefusal(BaseRequest(helper, fs::path{}), "CONFINEMENT");
    fs::remove(helper);
}

BOOST_AUTO_TEST_CASE(helper_not_regular_file)
{
    const fs::path root = fs::temp_directory_path() / "btx-swarm-confine-notfile";
    const fs::path directory = root / "directory";
    fs::create_directories(directory);
    ExpectRefusal(BaseRequest(directory, root), "SANDBOX_ABSENT");
    ExpectRefusal(BaseRequest(root / "missing", root), "SANDBOX_ABSENT");
    fs::remove_all(root);
}

BOOST_AUTO_TEST_CASE(network_not_denied)
{
    const fs::path root = fs::temp_directory_path() / "btx-swarm-confine-network";
    const fs::path helper = WriteRegularFile(root / "helper.sh");
    modelnet::SwarmConfineRequest request = BaseRequest(helper, root);
    request.network_denied = false;
    ExpectRefusal(request, "NETWORK");
    fs::remove_all(root);
}

BOOST_AUTO_TEST_CASE(non_positive_limits)
{
    const fs::path root = fs::temp_directory_path() / "btx-swarm-confine-limit";
    const fs::path helper = WriteRegularFile(root / "helper.sh");
    modelnet::SwarmConfineRequest address = BaseRequest(helper, root);
    address.max_address_bytes = 0;
    ExpectRefusal(address, "LIMIT");
    modelnet::SwarmConfineRequest cpu = BaseRequest(helper, root);
    cpu.max_cpu_seconds = 0;
    ExpectRefusal(cpu, "LIMIT");
    modelnet::SwarmConfineRequest nofile = BaseRequest(helper, root);
    nofile.max_nofile = -1;
    ExpectRefusal(nofile, "LIMIT");
    fs::remove_all(root);
}

#if defined(__linux__) || defined(__APPLE__)
// Windows refuses a zero max_tree_bytes in its own sandbox (WINDOWS_SANDBOX_POLICY).
BOOST_AUTO_TEST_CASE(zero_tree_limit)
{
    const fs::path root = FreshRoot("btx-swarm-confine-zero-tree");
    modelnet::SwarmConfineRequest request = BaseRequest(WriteRegularFile(root / "helper.sh"), root);
    request.max_tree_bytes = 0;
    ExpectRefusal(request, "LIMIT");
    fs::remove_all(root);
}
#endif

BOOST_AUTO_TEST_CASE(path_outside_or_dotdot)
{
    const fs::path root = fs::temp_directory_path() / "btx-swarm-confine-path";
    const fs::path helper = WriteRegularFile(root / "helper.sh");
    const fs::path outside_root = fs::temp_directory_path() / "btx-swarm-confine-outside";
    const fs::path outside = WriteRegularFile(outside_root / "helper.sh");
    ExpectRefusal(BaseRequest(outside, root), "PATH");

    const fs::path dotted = root / ".." / root.filename() / "helper.sh";
    BOOST_REQUIRE(fs::exists(dotted));
    BOOST_REQUIRE(fs::is_regular_file(dotted));
    ExpectRefusal(BaseRequest(dotted, root), "PATH");

    fs::remove_all(root);
    fs::remove_all(outside_root);
}

BOOST_AUTO_TEST_CASE(confined_helper_or_namespace_absent)
{
    // canonical: InsideRoot refuses symlinks, and macOS TMPDIR is below /var.
    const fs::path root = fs::canonical(fs::temp_directory_path()) / "btx-swarm-confine-run";
    const fs::path helper = root / "helper.sh";
    fs::create_directories(root);
    {
        std::ofstream out{helper};
        BOOST_REQUIRE(out);
        out << "#!/bin/sh\n";
        out << "echo ok\n";
        BOOST_REQUIRE(out);
    }
    BOOST_REQUIRE(chmod(helper.c_str(), S_IRUSR | S_IWUSR | S_IXUSR) == 0);

    std::string err = "stale";
    const modelnet::SwarmConfineResult result = modelnet::SwarmRunConfined(BaseRequest(helper, root), err);
    fs::remove_all(root);

    const bool confined = result.code == "CONFINED" && result.launched && result.limits_applied && err.empty();
    const bool absent = result.code == "CONFINEMENT_ABSENT" && !result.launched && !result.limits_applied &&
                        err == "CONFINEMENT_ABSENT";
    BOOST_CHECK(confined || absent);
    BOOST_CHECK(!(result.launched && result.code == "CONFINEMENT_ABSENT"));
    if (confined) {
        BOOST_CHECK(WIFEXITED(result.child_status));
        BOOST_CHECK_EQUAL(WEXITSTATUS(result.child_status), 0);
    }
}

#if defined(__APPLE__) && defined(BTX_SWARM_JAIL_PROBE)
namespace {

// The Seatbelt profile matches resolved paths and InsideRoot refuses
// symlinks; TMPDIR on macOS is below the /var symlink.
fs::path MacRoot(const char* name)
{
    const fs::path root = fs::canonical(fs::temp_directory_path()) / name;
    fs::remove_all(root);
    fs::create_directories(root);
    return root;
}

fs::path CopyProbe(const fs::path& root, const char* marker)
{
    const fs::path helper = root / "probe";
    fs::copy_file(fs::path{BTX_SWARM_JAIL_PROBE}, helper, fs::copy_options::overwrite_existing);
    BOOST_REQUIRE(chmod(helper.c_str(), S_IRUSR | S_IWUSR | S_IXUSR) == 0);
    if (marker != nullptr) {
        WriteRegularFile(root / marker);
    }
    return helper;
}

std::string ProbeOutput(const fs::path& root)
{
    std::ifstream in{root / "probe.out"};
    return std::string{std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{}};
}

} // namespace

// macOS: default-deny Seatbelt instead of namespaces. The helper runs, sees
// the CPU and descriptor limits, and can neither bind a loopback socket nor
// read outside root.
BOOST_AUTO_TEST_CASE(macos_helper_runs_confined)
{
    const fs::path root = MacRoot("btx-swarm-confine-macos");
    modelnet::SwarmConfineRequest request = BaseRequest(CopyProbe(root, nullptr), root);
    request.max_address_bytes = 1LL << 30;
    std::string err = "stale";
    const modelnet::SwarmConfineResult result = modelnet::SwarmRunConfined(request, err);
    const std::string out = ProbeOutput(root);
    fs::remove_all(root);
    BOOST_CHECK_EQUAL(result.code, "CONFINED");
    BOOST_CHECK(result.launched && result.limits_applied && err.empty());
    BOOST_CHECK(WIFEXITED(result.child_status));
    BOOST_CHECK_EQUAL(WEXITSTATUS(result.child_status), 0);
    BOOST_CHECK(out.find("outside_dir=0\n") != std::string::npos);
    BOOST_CHECK(out.find("etc_hosts=0\n") != std::string::npos);
    BOOST_CHECK(out.find("loopback_bind=0\n") != std::string::npos);
    BOOST_CHECK(out.find("nofile=64\n") != std::string::npos);
    BOOST_CHECK(out.find("cpu=30\n") != std::string::npos);
    BOOST_CHECK(out.find("fsize=1073741824\n") != std::string::npos);
    // Regression checks for the default-deny profile.
    for (const char* line : {"mach_lookup=0\n", "fork=0\n", "signal_parent=0\n", "procargs_parent=0\n",
                             "uname=1\n", "posix_shm=0\n", "cwd_root=1\n"}) {
        BOOST_CHECK_MESSAGE(out.find(line) != std::string::npos, "probe line " << line);
    }
}

// macOS refuses RLIMIT_AS; the parent kills a child whose footprint passes
// max_address_bytes. A signal reads as not executed, so the run is refused:
// the probe started but did not finish its 4 GiB.
BOOST_AUTO_TEST_CASE(macos_address_limit_enforced)
{
    const fs::path root = MacRoot("btx-swarm-confine-macos-alloc");
    modelnet::SwarmConfineRequest request = BaseRequest(CopyProbe(root, "alloc.mode"), root);
    request.max_address_bytes = 256LL << 20;
    std::string err;
    const modelnet::SwarmConfineResult result = modelnet::SwarmRunConfined(request, err);
    const bool started = fs::exists(root / "alloc.started");
    const bool done = fs::exists(root / "alloc.done");
    fs::remove_all(root);
    BOOST_CHECK_EQUAL(result.code, "CONFINEMENT_ABSENT");
    BOOST_CHECK(!result.launched);
    BOOST_CHECK(started);
    BOOST_CHECK(!done);
}

// RLIMIT_CPU is enforced by the kernel (SIGXCPU): the probe started but did
// not finish its 20 s of CPU.
BOOST_AUTO_TEST_CASE(macos_cpu_limit_enforced)
{
    const fs::path root = MacRoot("btx-swarm-confine-macos-spin");
    modelnet::SwarmConfineRequest request = BaseRequest(CopyProbe(root, "spin.mode"), root);
    request.max_cpu_seconds = 1;
    std::string err;
    const modelnet::SwarmConfineResult result = modelnet::SwarmRunConfined(request, err);
    const bool started = fs::exists(root / "spin.started");
    const bool done = fs::exists(root / "spin.done");
    fs::remove_all(root);
    BOOST_CHECK_EQUAL(result.code, "CONFINEMENT_ABSENT");
    BOOST_CHECK(!result.launched);
    BOOST_CHECK(started);
    BOOST_CHECK(!done);
}

// macOS only sends SIGXCPU at RLIMIT_CPU. A helper that ignores it is killed
// by the parent 250 ms past the limit, long before its 20 s spin ends.
BOOST_AUTO_TEST_CASE(macos_cpu_limit_holds_when_sigxcpu_ignored)
{
    const fs::path root = MacRoot("btx-swarm-confine-macos-spin-ignore");
    modelnet::SwarmConfineRequest request = BaseRequest(CopyProbe(root, "spin_ignore.mode"), root);
    request.max_cpu_seconds = 1;
    std::string err;
    const auto start = std::chrono::steady_clock::now();
    const modelnet::SwarmConfineResult result = modelnet::SwarmRunConfined(request, err);
    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - start).count();
    const bool started = fs::exists(root / "spin.started");
    const bool done = fs::exists(root / "spin.done");
    fs::remove_all(root);
    BOOST_CHECK_EQUAL(result.code, "CONFINEMENT_ABSENT");
    BOOST_CHECK(!result.launched);
    BOOST_CHECK(started);
    BOOST_CHECK(!done);
    BOOST_CHECK_LT(seconds, 10);
}

namespace {
void WriteBytes(const fs::path& path, size_t bytes)
{
    std::ofstream out{path, std::ios::binary};
    out << std::string(bytes, 'x');
    BOOST_REQUIRE(out);
}

uintmax_t FileBytes(const fs::path& path)
{
    return fs::exists(path) ? fs::file_size(path) : 0;
}
} // namespace

// A root that is already over max_tree_bytes is refused before launch.
BOOST_AUTO_TEST_CASE(macos_tree_limit_refuses_root_before_launch)
{
    const fs::path root = MacRoot("btx-swarm-confine-macos-tree-before");
    modelnet::SwarmConfineRequest request = BaseRequest(CopyProbe(root, nullptr), root);
    request.max_tree_bytes = fs::file_size(request.helper) + 1024;
    WriteBytes(root / "input.bin", 4096);
    BOOST_CHECK_EQUAL(ChildSignalsDuring([&] { ExpectRefusal(request, "TREE_LIMIT"); }), 0);
    const bool ran = fs::exists(root / "probe.out");
    fs::remove_all(root);
    BOOST_CHECK(!ran);
}

// RLIMIT_FSIZE stops one large file during the run: SIGXFSZ kills the probe
// (a signal reads as not executed), and the file never passes max_tree_bytes.
// The probe removes itself and its marker first, so the tree stays within the
// limit and the tree check while it runs never fires.
BOOST_AUTO_TEST_CASE(macos_file_size_limit_enforced)
{
    const fs::path root = MacRoot("btx-swarm-confine-macos-fill");
    modelnet::SwarmConfineRequest request = BaseRequest(CopyProbe(root, "fill.mode"), root);
    request.max_tree_bytes = fs::file_size(request.helper) + (8 << 20);
    std::string err;
    const modelnet::SwarmConfineResult result = modelnet::SwarmRunConfined(request, err);
    const bool started = fs::exists(root / "fill.started");
    const bool done = fs::exists(root / "fill.done");
    const uintmax_t written = FileBytes(root / "fill.bin");
    fs::remove_all(root);
    BOOST_CHECK_EQUAL(result.code, "CONFINEMENT_ABSENT");
    BOOST_CHECK(!result.launched);
    BOOST_CHECK(started);
    BOOST_CHECK(!done);
    BOOST_CHECK_LE(written, request.max_tree_bytes);
}

// A helper that ignores SIGXFSZ gets EFBIG and exits normally. The file still
// stops at max_tree_bytes. The tree goes over only with the probe's last
// write, after fill.refused exists, and the result is refused.
BOOST_AUTO_TEST_CASE(macos_file_size_limit_holds_when_sigxfsz_ignored)
{
    const fs::path root = MacRoot("btx-swarm-confine-macos-fill-ignore");
    modelnet::SwarmConfineRequest request = BaseRequest(CopyProbe(root, "fill_ignore.mode"), root);
    request.max_tree_bytes = fs::file_size(request.helper) + (8 << 20);
    ExpectRefusal(request, "TREE_LIMIT");
    const bool refused = fs::exists(root / "fill.refused");
    const bool done = fs::exists(root / "fill.done");
    const uintmax_t written = FileBytes(root / "fill.bin");
    fs::remove_all(root);
    BOOST_CHECK(refused);
    BOOST_CHECK(!done);
    BOOST_CHECK_GT(written, 0U);
    BOOST_CHECK_LE(written, request.max_tree_bytes);
}

// A helper whose tree goes past max_tree_bytes only in its last step before
// exit, too late for a walk while it runs, is refused by the check after exit.
BOOST_AUTO_TEST_CASE(macos_tree_limit_refuses_result_after_run)
{
    const fs::path root = MacRoot("btx-swarm-confine-macos-burst");
    modelnet::SwarmConfineRequest request = BaseRequest(CopyProbe(root, "burst.mode"), root);
    request.max_tree_bytes = fs::file_size(request.helper) + (2 << 20);
    ExpectRefusal(request, "TREE_LIMIT");
    const bool done = fs::exists(root / "burst.done");
    fs::remove_all(root);
    BOOST_CHECK(done);
}

// A helper that keeps writing files below RLIMIT_FSIZE under Seatbelt is
// killed while it runs, once the tree passes max_tree_bytes.
BOOST_AUTO_TEST_CASE(macos_tree_limit_enforced_during_run)
{
    const fs::path root = MacRoot("btx-swarm-confine-macos-spread");
    modelnet::SwarmConfineRequest request = BaseRequest(CopyProbe(root, "spread.mode"), root);
    request.max_tree_bytes = fs::file_size(request.helper) + (8 << 20);
    ExpectRefusal(request, "TREE_LIMIT");
    const bool started = fs::exists(root / "spread.started");
    const bool done = fs::exists(root / "spread.done");
    const int files = CountFiles(root, "spread");
    fs::remove_all(root);
    BOOST_CHECK(started);
    BOOST_CHECK(!done);
    BOOST_CHECK_LT(files, 64);
}
#endif

#ifndef _WIN32
namespace process_guard = modelnet::process_guard;

namespace {

// A plain forked child (no namespaces) for the process_guard::Wait checks:
// it reports ready on the error pipe like a confined child, then runs work.
template <typename Work>
process_guard::WaitResult WaitOnChild(const fs::path& root, uint64_t max_tree_bytes, Work work)
{
    int fds[2];
    BOOST_REQUIRE(process_guard::ErrorPipe(fds));
    const pid_t pid = fork();
    BOOST_REQUIRE(pid >= 0);
    if (pid == 0) {
        close(fds[0]);
        if (setpgid(0, 0) != 0 || !process_guard::ChildReady(fds[1])) _exit(126);
        work();
        _exit(0);
    }
    close(fds[1]);
    return process_guard::Wait(pid, fds[0], 30, 0, 0, root, max_tree_bytes);
}

// Only async-signal-safe calls run in the forked child.
void ChildWrite(const char* path, const char* data, size_t bytes)
{
    const int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) _exit(3);
    if (write(fd, data, bytes) != static_cast<ssize_t>(bytes)) _exit(4);
    close(fd);
}

} // namespace

// A walk calls back after every 256 entries, so a caller's other checks keep
// running while it walks a large tree (Wait's footprint and CPU limits on macOS).
BOOST_AUTO_TEST_CASE(tree_within_limit_calls_back_during_walk)
{
    const fs::path root = FreshRoot("btx-swarm-tree-within-during");
    for (int i = 0; i < 1024; ++i) std::ofstream{root / fs::PathFromString("f" + std::to_string(i))};
    int calls = 0;
    const bool within = process_guard::TreeWithinLimit(root, 1, false, [&] { ++calls; });
    fs::remove_all(root);
    BOOST_CHECK(within);
    BOOST_CHECK_EQUAL(calls, 4);
}

// A directory that is gone after the walk read its entry, before the walk
// checks it and opens it, is skipped while the helper runs: not walked into,
// not an error. The strict walk (before launch, after exit) still refuses
// it. The callback after 256 entries removes every directory at that point.
BOOST_AUTO_TEST_CASE(tree_within_limit_skips_directory_removed_during_walk)
{
    const fs::path root = FreshRoot("btx-swarm-tree-within-vanish");
    const auto make_dirs = [&] {
        for (int i = 0; i < 300; ++i) fs::create_directory(root / fs::PathFromString("d" + std::to_string(i)));
    };
    const auto remove_dirs = [&] {
        std::error_code ec;
        for (int i = 0; i < 300; ++i) fs::remove(root / fs::PathFromString("d" + std::to_string(i)), ec);
    };
    int calls = 0;
    make_dirs();
    const bool running = process_guard::TreeWithinLimit(root, 1, true, [&] { ++calls; remove_dirs(); });
    const bool emptied = fs::is_empty(root);
    make_dirs();
    const bool strict = process_guard::TreeWithinLimit(root, 1, false, remove_dirs);
    fs::remove_all(root);
    BOOST_CHECK_EQUAL(calls, 1);
    BOOST_CHECK(emptied);
    BOOST_CHECK(running);
    BOOST_CHECK(!strict);
}

// Wait kills the child's process group once the tree is over the limit.
BOOST_AUTO_TEST_CASE(wait_kills_child_over_tree_limit)
{
    const fs::path root = FreshRoot("btx-swarm-wait-tree");
    const std::string block(1 << 20, 'x');
    std::vector<std::string> names;
    for (int i = 0; i < 64; ++i) names.push_back(fs::PathToString(root / fs::PathFromString("f" + std::to_string(i) + ".bin")));
    const std::string done = fs::PathToString(root / "done");
    const auto waited = WaitOnChild(root, 8 << 20, [&] {
        const timespec pause{0, 20 * 1000 * 1000};
        for (const std::string& name : names) {
            ChildWrite(name.c_str(), block.data(), block.size());
            nanosleep(&pause, nullptr);
        }
        ChildWrite(done.c_str(), "", 0);
    });
    const bool finished = fs::exists(root / "done");
    const int files = CountFiles(root, "f");
    fs::remove_all(root);
    BOOST_CHECK(waited.over_tree);
    BOOST_CHECK(!waited.executed);
    BOOST_CHECK(WIFSIGNALED(waited.status));
    BOOST_CHECK(!finished);
    BOOST_CHECK_GT(files, 8);
    BOOST_CHECK_LT(files, 64);
}

// The kill goes to the whole process group: a grandchild that keeps writing
// is gone too, not only the child. The grandchild sends its pid before its
// first write. On Linux this process is its subreaper, so waitpid shows how
// it ended; on macOS it is gone once kill(pid, 0) finds no process.
BOOST_AUTO_TEST_CASE(wait_kills_process_group_over_tree_limit)
{
    const fs::path root = FreshRoot("btx-swarm-wait-tree-group");
    const std::string block(1 << 20, 'x');
    std::vector<std::string> names;
    for (int i = 0; i < 64; ++i) names.push_back(fs::PathToString(root / fs::PathFromString("g" + std::to_string(i) + ".bin")));
    int pid_pipe[2];
    BOOST_REQUIRE(pipe(pid_pipe) == 0);
#ifdef __linux__
    BOOST_REQUIRE(prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) == 0);
#endif
    const auto waited = WaitOnChild(root, 8 << 20, [&] {
        const pid_t grandchild = fork();
        if (grandchild < 0) _exit(5);
        if (grandchild == 0) {
            const pid_t self = getpid();
            if (write(pid_pipe[1], &self, sizeof(self)) != static_cast<ssize_t>(sizeof(self))) _exit(6);
            // Without the error pipe, so only the kill can end it before Wait returns.
            for (int fd = 3; fd < 1024; ++fd) close(fd);
            const timespec pause{0, 20 * 1000 * 1000};
            timespec start{}, now{};
            clock_gettime(CLOCK_MONOTONIC, &start);
            for (size_t i = 0;; ++i) {
                ChildWrite(names[i % names.size()].c_str(), block.data(), block.size());
                nanosleep(&pause, nullptr);
                clock_gettime(CLOCK_MONOTONIC, &now);
                if (now.tv_sec - start.tv_sec >= 60) _exit(0);
            }
        }
        close(pid_pipe[1]);
        const timespec pause{1, 0};
        for (int i = 0; i < 60; ++i) nanosleep(&pause, nullptr);
    });
    close(pid_pipe[1]);
    pid_t grandchild = -1;
    const bool got = read(pid_pipe[0], &grandchild, sizeof(grandchild)) == static_cast<ssize_t>(sizeof(grandchild));
    close(pid_pipe[0]);
    // SIGKILL is sent before Wait returns; the kernel ends the process soon after.
    bool gone = false;
#ifdef __linux__
    int status = 0;
#endif
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (got && !gone && std::chrono::steady_clock::now() < deadline) {
#ifdef __linux__
        gone = waitpid(grandchild, &status, WNOHANG) == grandchild;
#else
        gone = kill(grandchild, 0) != 0 && errno == ESRCH;
#endif
        if (!gone) std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (got && !gone) {
        kill(grandchild, SIGKILL);
#ifdef __linux__
        waitpid(grandchild, &status, 0);
#endif
    }
#ifdef __linux__
    BOOST_REQUIRE(prctl(PR_SET_CHILD_SUBREAPER, 0, 0, 0, 0) == 0);
#endif
    const int files = CountFiles(root, "g");
    fs::remove_all(root);
    BOOST_REQUIRE(got);
    BOOST_CHECK(waited.over_tree);
    BOOST_CHECK(!waited.executed);
    BOOST_CHECK(gone);
#ifdef __linux__
    BOOST_CHECK(gone && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
#endif
    BOOST_CHECK_GT(files, 8);
}

// The same child under a limit it never reaches runs to the end.
BOOST_AUTO_TEST_CASE(wait_lets_child_within_tree_limit_finish)
{
    const fs::path root = FreshRoot("btx-swarm-wait-tree-ok");
    const std::string block(1 << 20, 'x');
    const std::string first = fs::PathToString(root / "f0.bin");
    const std::string second = fs::PathToString(root / "f1.bin");
    const auto waited = WaitOnChild(root, 2 << 20, [&] {
        const timespec pause{0, 300 * 1000 * 1000};
        ChildWrite(first.c_str(), block.data(), block.size());
        nanosleep(&pause, nullptr);
        ChildWrite(second.c_str(), block.data(), block.size());
        nanosleep(&pause, nullptr);
    });
    fs::remove_all(root);
    BOOST_CHECK(waited.executed);
    BOOST_CHECK(!waited.over_tree);
}

// Files the child renames and removes while the parent walks the tree are
// skipped, not counted as over: the child keeps churning and is not killed.
BOOST_AUTO_TEST_CASE(wait_skips_files_removed_during_walk)
{
    const fs::path root = FreshRoot("btx-swarm-wait-tree-churn");
    std::vector<std::string> from, to;
    for (int i = 0; i < 64; ++i) {
        from.push_back(fs::PathToString(root / fs::PathFromString("a" + std::to_string(i))));
        to.push_back(fs::PathToString(root / fs::PathFromString("b" + std::to_string(i))));
    }
    const auto waited = WaitOnChild(root, 1 << 20, [&] {
        timespec start{}, now{};
        clock_gettime(CLOCK_MONOTONIC, &start);
        do {
            for (size_t i = 0; i < from.size(); ++i) ChildWrite(from[i].c_str(), "x", 1);
            for (size_t i = 0; i < from.size(); ++i) rename(from[i].c_str(), to[i].c_str());
            for (size_t i = 0; i < to.size(); ++i) unlink(to[i].c_str());
            clock_gettime(CLOCK_MONOTONIC, &now);
        } while (now.tv_sec - start.tv_sec < 2);
    });
    fs::remove_all(root);
    BOOST_CHECK(waited.executed);
    BOOST_CHECK(!waited.over_tree);
}
#endif // _WIN32

#ifdef __linux__
// A root that is already over max_tree_bytes is refused before launch.
BOOST_AUTO_TEST_CASE(linux_tree_limit_refuses_root_before_launch)
{
    const fs::path root = FreshRoot("btx-swarm-confine-linux-tree-before");
    const fs::path helper = root / "helper.sh";
    {
        std::ofstream out{helper};
        out << "#!/bin/sh\ntouch ran\n";
        BOOST_REQUIRE(out);
        std::ofstream extra{root / "input.bin", std::ios::binary};
        extra << std::string(4096, 'x');
        BOOST_REQUIRE(extra);
    }
    BOOST_REQUIRE(chmod(helper.c_str(), S_IRUSR | S_IWUSR | S_IXUSR) == 0);
    modelnet::SwarmConfineRequest request = BaseRequest(helper, root);
    request.max_tree_bytes = fs::file_size(helper) + 1024;
    BOOST_CHECK_EQUAL(ChildSignalsDuring([&] { ExpectRefusal(request, "TREE_LIMIT"); }), 0);
    const bool ran = fs::exists(root / "ran");
    fs::remove_all(root);
    BOOST_CHECK(!ran);
}

#ifdef BTX_SWARM_LINUX_PROBE
namespace {

fs::path CopyProbe(const fs::path& root, const char* marker)
{
    const fs::path helper = root / "probe";
    fs::copy_file(fs::path{BTX_SWARM_LINUX_PROBE}, helper, fs::copy_options::overwrite_existing);
    BOOST_REQUIRE(chmod(helper.c_str(), S_IRUSR | S_IWUSR | S_IXUSR) == 0);
    if (marker != nullptr) WriteRegularFile(root / marker);
    return helper;
}

// The cases below need the helper to run. Without user namespaces it never
// starts, and they have nothing to measure.
bool ConfinementAvailable()
{
    const fs::path root = FreshRoot("btx-swarm-confine-linux-available");
    std::string err;
    const auto result = modelnet::SwarmRunConfined(BaseRequest(CopyProbe(root, nullptr), root), err);
    fs::remove_all(root);
    if (result.code != "CONFINED") BOOST_TEST_MESSAGE("Linux confinement absent here: " << result.code);
    return result.code == "CONFINED";
}

} // namespace

// The child sets RLIMIT_FSIZE to max_tree_bytes before exec.
BOOST_AUTO_TEST_CASE(linux_file_size_limit_applied)
{
    if (!ConfinementAvailable()) return;
    const fs::path root = FreshRoot("btx-swarm-confine-linux-fsize");
    modelnet::SwarmConfineRequest request = BaseRequest(CopyProbe(root, nullptr), root);
    request.max_tree_bytes = 64 << 20;
    std::string err;
    const auto result = modelnet::SwarmRunConfined(request, err);
    std::ifstream in{root / "probe.out"};
    const std::string out{std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{}};
    fs::remove_all(root);
    BOOST_CHECK_EQUAL(result.code, "CONFINED");
    BOOST_CHECK_EQUAL(out, "fsize=67108864\n");
}

// A helper that keeps writing files below RLIMIT_FSIZE is killed while it
// runs, once the tree passes max_tree_bytes.
BOOST_AUTO_TEST_CASE(linux_tree_limit_enforced_during_run)
{
    if (!ConfinementAvailable()) return;
    const fs::path root = FreshRoot("btx-swarm-confine-linux-spread");
    modelnet::SwarmConfineRequest request = BaseRequest(CopyProbe(root, "spread.mode"), root);
    request.max_tree_bytes = fs::file_size(request.helper) + (8 << 20);
    ExpectRefusal(request, "TREE_LIMIT");
    const bool started = fs::exists(root / "spread.started");
    const bool done = fs::exists(root / "spread.done");
    const int files = CountFiles(root, "spread");
    fs::remove_all(root);
    BOOST_CHECK(started);
    BOOST_CHECK(!done);
    BOOST_CHECK_LT(files, 64);
}

// A helper whose tree goes past max_tree_bytes only in its last step before
// exit, too late for a walk while it runs, is refused by the check after exit.
BOOST_AUTO_TEST_CASE(linux_tree_limit_refuses_result_after_run)
{
    if (!ConfinementAvailable()) return;
    const fs::path root = FreshRoot("btx-swarm-confine-linux-burst");
    modelnet::SwarmConfineRequest request = BaseRequest(CopyProbe(root, "burst.mode"), root);
    request.max_tree_bytes = fs::file_size(request.helper) + (2 << 20);
    ExpectRefusal(request, "TREE_LIMIT");
    const bool done = fs::exists(root / "burst.done");
    fs::remove_all(root);
    BOOST_CHECK(done);
}
#endif // BTX_SWARM_LINUX_PROBE
#endif // __linux__

#if (defined(__APPLE__) && defined(BTX_SWARM_JAIL_PROBE)) || (defined(__linux__) && defined(BTX_SWARM_LINUX_PROBE))
// A root that is already over max_tree_bytes is refused before launch: the
// probe never writes spread.started, its first file. The limit is one byte
// below the tree and each of the 8,000 files has a byte, so a walk finds the
// tree over only at the last file it reads, in any order. Without the check
// before launch, a probe that can start (macOS, or Linux with user
// namespaces) writes its marker before the walk while it runs has failed
// twice. A Seatbelt helper takes a few hundred ms to start, so on macOS the
// files sit 24 directories down: the walk checks every directory on a path
// for a symlink, and each walk takes longer.
BOOST_AUTO_TEST_CASE(tree_limit_refuses_root_before_probe_starts)
{
    const fs::path root = FreshRoot("btx-swarm-confine-tree-before-probe");
    modelnet::SwarmConfineRequest request = BaseRequest(CopyProbe(root, "spread.mode"), root);
    fs::path dir = root;
#ifdef __APPLE__
    for (int i = 0; i < 24; ++i) dir /= "d";
    fs::create_directories(dir);
#endif
    bool written = true;
    for (int i = 0; i < 8000; ++i) {
        std::ofstream out{dir / fs::PathFromString("f" + std::to_string(i))};
        written = (out << 'x') && written;
    }
    BOOST_REQUIRE(written);
    uint64_t total = 0;
    for (const auto& entry : fs::recursive_directory_iterator(root)) {
        if (entry.is_regular_file()) total += entry.file_size();
    }
    request.max_tree_bytes = total - 1;
    BOOST_CHECK_EQUAL(ChildSignalsDuring([&] { ExpectRefusal(request, "TREE_LIMIT"); }), 0);
    const bool started = fs::exists(root / "spread.started");
    fs::remove_all(root);
    BOOST_CHECK(!started);
}
#endif

BOOST_AUTO_TEST_SUITE_END()
