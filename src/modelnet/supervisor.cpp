// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/supervisor.h>

#include <logging.h>
#include <modelnet/helper.h>
#include <modelnet/profile.h>
#include <tinyformat.h>
#include <univalue.h>
#include <util/fs.h>
#include <util/strencodings.h>

#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstring>
#include <filesystem>
#include <stdexcept>
#include <system_error>
#include <thread>

#ifndef WIN32
#include <spawn.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#ifdef __linux__
#include <sys/syscall.h>
#endif
#include <unistd.h>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif
extern char** environ;
#else
#include <windows.h>
#endif

namespace modelnet {
namespace {

HelperSupervisor* g_managed = nullptr;

} // namespace

fs::path SelfExeDir()
{
#ifndef WIN32
#ifdef __linux__
    char buf[4096];
    const ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = 0;
        return fs::path(buf).parent_path();
    }
#endif
#ifdef __APPLE__
    char buf[4096];
    uint32_t sz = sizeof(buf);
    if (_NSGetExecutablePath(buf, &sz) == 0) {
        return fs::path(buf).parent_path();
    }
#endif
#else
    std::vector<wchar_t> buf(32768);
    const DWORD n = GetModuleFileNameW(nullptr, buf.data(), static_cast<DWORD>(buf.size()));
    if (n > 0 && n < buf.size()) {
        return fs::path(std::wstring(buf.data(), n)).parent_path();
    }
#endif
    return {};
}

namespace {

bool SocketReady(const fs::path& sock, std::string& err, std::atomic<bool>* stop)
{
    const fs::path path = UnixRpcListenPath(sock);
    if (!UnixSocketSafeToAdopt(path, err)) return false;
    UniValue result;
    UniValue params(UniValue::VARR);
    return CallUnixRpc(path, "getmodelnetworkinfo", params, result, err, stop, /*reply_timeout_ms=*/0, /*check_peer=*/true);
}

} // namespace

const char* HelperStateName(HelperState s)
{
    switch (s) {
    case HelperState::DISABLED: return "DISABLED";
    case HelperState::STARTING: return "STARTING";
    case HelperState::READY: return "READY";
    case HelperState::DEGRADED: return "DEGRADED";
    case HelperState::FAILED_RETRYING: return "FAILED_RETRYING";
    }
    return "DISABLED";
}

bool EnvLooksLikeWalletSecret(const std::string& key)
{
    const std::string k = ToLower(key);
    if (k.find("cookie") != std::string::npos) return true;
    if (k.find("wallet") != std::string::npos) return true;
    if (k == "rpcuser" || k == "rpcpassword" || k == "rpcauth") return true;
    if (k.rfind("rpc", 0) == 0 && (k.find("user") != std::string::npos || k.find("pass") != std::string::npos || k.find("auth") != std::string::npos)) {
        return true;
    }
    if (k.find("mnemonic") != std::string::npos || k.find("seed_phrase") != std::string::npos) return true;
    if (k == "bitcoin_cookie" || k.find("btx_wallet") != std::string::npos) return true;
    return false;
}

std::vector<std::string> SanitizeHelperEnv(char** envp)
{
    std::vector<std::string> out;
    if (!envp) return out;
    for (char** p = envp; p && *p; ++p) {
        const std::string e = *p;
        const auto eq = e.find('=');
        const std::string key = eq == std::string::npos ? e : e.substr(0, eq);
        if (EnvLooksLikeWalletSecret(key)) continue;
        out.push_back(e);
    }
    return out;
}

std::vector<std::string> BuildHelperArgv(const HelperLaunchConfig& cfg)
{
    std::vector<std::string> argv;
    argv.push_back(fs::PathToString(cfg.helper_exe));
    argv.push_back("-modeldir=" + fs::PathToString(cfg.modeldir));
    argv.push_back("-modelrpcsocket=" + fs::PathToString(cfg.rpc_socket));
    argv.push_back("-modelstorage=" + (cfg.storage_arg.empty() ? std::string("auto") : cfg.storage_arg));
    argv.push_back("-modelseed=" + (cfg.seed.empty() ? std::string("auto") : cfg.seed));
    if (!cfg.bind.empty()) argv.push_back("-modelbind=" + cfg.bind);
    if (!cfg.bind.empty() && !cfg.natpmp) argv.push_back("-modelnatpmp=0");
    if (cfg.preserve_rare) argv.push_back("-modelpreserverare");
    if (!cfg.follow_peers) argv.push_back("-modelfollowpeers=0");
    if (!cfg.lan_discovery) argv.push_back("-modellandiscovery=0");
    for (const auto& proxy : cfg.proxies) argv.push_back("-modelproxy=" + proxy);
    if (!cfg.proxies.empty() && !cfg.proxy_randomize) argv.push_back("-modelproxyrandomize=0");
    for (const auto& net : cfg.onlynets) argv.push_back("-modelonlynet=" + net);
    for (const auto& peer : cfg.peers) {
        if (!peer.empty()) argv.push_back("-modelpeer=" + peer);
    }
    if (cfg.auto_cap_bytes > 0) argv.push_back("-modelstorageautocap=" + std::to_string(cfg.auto_cap_bytes));
    if (cfg.reserve_bytes > 0) argv.push_back("-modelfreespacereserve=" + std::to_string(cfg.reserve_bytes));
    if (cfg.upload_bps > 0) argv.push_back("-modeluploadlimit=" + std::to_string(cfg.upload_bps));
    if (!cfg.watch_dir.empty()) argv.push_back("-modelwatch=" + cfg.watch_dir);
    if (cfg.relay) argv.push_back("-modelrelay");
    if (!cfg.pwc_chain.empty()) argv.push_back("-pwcchain=" + cfg.pwc_chain);
    if (!cfg.qualification_file.empty()) argv.push_back("-computequalificationfile=" + cfg.qualification_file);
    if (cfg.host_mode == HostMode::AUTO) argv.push_back("-modelhost=auto");
    else if (cfg.host_mode == HostMode::ON) argv.push_back("-modelhost=1");
    return argv;
}

void ApplyProfileToLaunchConfig(const ProfilePolicy& policy, HelperLaunchConfig& cfg)
{
    cfg.relay = policy.relay;
    cfg.index = policy.index;
    cfg.host_mode = policy.host_mode;
    if (!policy.storage_arg.empty()) cfg.storage_arg = policy.storage_arg;
    cfg.auto_cap_bytes = policy.auto_cap_bytes;
    cfg.upload_bps = policy.upload_bps;
    cfg.follow_peers = policy.follow_peers;
    cfg.preserve_rare = policy.preserve_rare;
    if (!policy.seed.empty()) cfg.seed = policy.seed;
}

void ApplyHelperNetworkInfo(HelperStatus& st, const UniValue& result)
{
    try {
        if (result.exists("advertised_host")) {
            const UniValue& v = result["advertised_host"];
            if (v.isBool()) st.advertised_host = v.get_bool();
            else if (v.isNum()) st.advertised_host = v.getInt<int>() != 0;
        }
        if (result.exists("public_host_reachable")) {
            const UniValue& v = result["public_host_reachable"];
            if (v.isBool()) st.public_host_reachable = v.get_bool();
            else if (v.isNum()) st.public_host_reachable = v.getInt<int>() != 0;
        }
    } catch (const std::exception&) {
        st.advertised_host = false;
        st.public_host_reachable = false;
    }
}

bool ArgvContainsWalletMaterial(const std::vector<std::string>& argv)
{
    for (const auto& a : argv) {
        const std::string l = ToLower(a);
        if (l.find("wallet") != std::string::npos) return true;
        if (l.find("cookie") != std::string::npos) return true;
        if (l.find("rpcpassword") != std::string::npos || l.find("rpcuser") != std::string::npos) return true;
        if (l.find("mnemonic") != std::string::npos) return true;
    }
    return false;
}

int NextBackoffMs(int fail_count, uint32_t jitter)
{
    static const int kSteps[] = {1000, 2000, 5000, 10000, 30000, 60000};
    int idx = fail_count;
    if (idx < 0) idx = 0;
    if (idx > 5) idx = 5;
    const int base = kSteps[idx];
    const int extra = static_cast<int>((static_cast<uint64_t>(base) * (jitter % 21)) / 100);
    return base + extra;
}

fs::path FindPackagedModeldIn(const fs::path& dir)
{
    const fs::path cands[] = {
        dir / MODELD_FILE_NAME,
        dir / "libexec" / MODELD_FILE_NAME,
        dir.parent_path() / "libexec" / MODELD_FILE_NAME,
        dir.parent_path() / "bin" / MODELD_FILE_NAME,
    };
    for (const auto& c : cands) {
        if (!c.empty() && fs::exists(c)) return c;
    }
    return {};
}

fs::path FindPackagedModeld(const fs::path& override_path)
{
    if (!override_path.empty()) {
        if (fs::exists(override_path)) return override_path;
        return {};
    }
    return FindPackagedModeldIn(SelfExeDir());
}

void SetManagedSupervisor(HelperSupervisor* p)
{
    g_managed = p;
}

HelperStatus SnapshotManagedHelper()
{
    if (!g_managed) return {};
    return g_managed->Snapshot();
}

HelperSupervisor::HelperSupervisor(HelperLaunchConfig cfg, std::function<bool()> shutdown)
    : m_cfg(std::move(cfg)), m_shutdown(std::move(shutdown))
{
    const fs::path requested = m_cfg.rpc_socket;
    m_cfg.rpc_socket = UnixRpcListenPath(requested);
    if (m_cfg.rpc_socket != requested) {
        LogPrintf("model helper: unix RPC path %s is not a private sun_path; using %s\n",
                  fs::PathToString(requested), fs::PathToString(m_cfg.rpc_socket));
    }
    m_st.enabled = true;
    m_st.state = HelperState::STARTING;
}

HelperSupervisor::~HelperSupervisor()
{
    Stop();
}

HelperStatus HelperSupervisor::Snapshot() const
{
    std::lock_guard<std::mutex> lock(m_mu);
    return m_st;
}

void HelperSupervisor::ClearHostBit()
{
    {
        std::lock_guard<std::mutex> lock(m_mu);
        m_st.advertised_host = false;
        m_st.public_host_reachable = false;
    }
    SetNodeModelHostAdvertised(false);
}

void HelperSupervisor::PollAndSyncHostBit()
{
    UniValue result;
    std::string err;
    UniValue params(UniValue::VARR);
    HelperStatus info;
    const bool ok = CallUnixRpc(m_cfg.rpc_socket, "getmodelnetworkinfo", params, result, err, &m_stop);
    if (ok) ApplyHelperNetworkInfo(info, result);
    {
        std::lock_guard<std::mutex> lock(m_mu);
        if (ok) {
            m_st.advertised_host = info.advertised_host;
            m_st.public_host_reachable = info.public_host_reachable;
        } else {
            m_st.advertised_host = false;
            m_st.public_host_reachable = false;
        }
    }
    SetNodeModelHostAdvertised(ok && info.advertised_host);
}

bool HelperSupervisor::WaitReady(int timeout_ms, std::string& err)
{
    const int step = 100;
    for (int waited = 0; waited < timeout_ms; waited += step) {
        if (m_stop.load()) {
            err = "stopped";
            return false;
        }
        if (SocketReady(m_cfg.rpc_socket, err, &m_stop)) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(step));
    }
    if (err.empty()) err = "helper unix RPC not ready";
    return false;
}

bool HelperSupervisor::SpawnLocked(std::string& err)
{
#ifndef WIN32
    if (m_cfg.helper_exe.empty()) {
        err = "btx-modeld not found next to btxd";
        return false;
    }
    if (!fs::exists(m_cfg.helper_exe)) {
        err = "btx-modeld missing: " + fs::PathToString(m_cfg.helper_exe);
        return false;
    }
    fs::create_directories(m_cfg.modeldir);
    fs::create_directories(m_cfg.rpc_socket.parent_path());
#ifndef WIN32
    if (!m_cfg.modeldir.empty()) ::chmod(fs::PathToString(m_cfg.modeldir).c_str(), 0700);
    if (!m_cfg.rpc_socket.parent_path().empty()) {
        ::chmod(fs::PathToString(m_cfg.rpc_socket.parent_path()).c_str(), 0700);
    }
#endif
    std::string sock_err;
    if (!SocketReady(m_cfg.rpc_socket, sock_err, &m_stop)) {
        if (m_stop.load()) return false;
        std::error_code rec;
        std::filesystem::remove(m_cfg.rpc_socket, rec);
    } else {
        err = "socket already live";
        return false;
    }

    const auto argv_s = BuildHelperArgv(m_cfg);
    if (ArgvContainsWalletMaterial(argv_s)) {
        err = "refusing to spawn helper with wallet material in argv";
        return false;
    }
    auto env_s = SanitizeHelperEnv(environ);
    // The helper exits if this process dies, so a crash does not leave it
    // holding the model port. A manually started btx-modeld does not set this.
    env_s.emplace_back("BTX_HELPER_PARENT_WATCH=1");
    std::vector<char*> argv;
    std::vector<char*> envp;
    argv.reserve(argv_s.size() + 1);
    for (const auto& a : argv_s) argv.push_back(const_cast<char*>(a.c_str()));
    argv.push_back(nullptr);
    envp.reserve(env_s.size() + 1);
    for (const auto& e : env_s) envp.push_back(const_cast<char*>(e.c_str()));
    envp.push_back(nullptr);

    posix_spawn_file_actions_t actions;
    if (posix_spawn_file_actions_init(&actions) != 0) {
        err = "posix_spawn_file_actions_init";
        return false;
    }
    posix_spawnattr_t* attrp{nullptr};
#if defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 34))
    // Do not leak btxd's descriptors (P2P/RPC listen sockets, datadir locks,
    // log files) into the helper. A leaked listen socket outlives a crashed
    // btxd in the orphaned helper and blocks btxd from binding on restart.
    if (posix_spawn_file_actions_addclosefrom_np(&actions, 3) != 0) {
        posix_spawn_file_actions_destroy(&actions);
        err = "posix_spawn_file_actions_addclosefrom_np";
        return false;
    }
#elif defined(__APPLE__)
    // Same on macOS, which has no closefrom file action: POSIX_SPAWN_CLOEXEC_DEFAULT
    // closes every descriptor that no file action names, so name 0, 1 and 2.
    posix_spawnattr_t attr;
    if (posix_spawnattr_init(&attr) != 0) {
        posix_spawn_file_actions_destroy(&actions);
        err = "posix_spawnattr_init";
        return false;
    }
    attrp = &attr;
    if (posix_spawnattr_setflags(&attr, POSIX_SPAWN_CLOEXEC_DEFAULT) != 0 ||
        posix_spawn_file_actions_addinherit_np(&actions, STDIN_FILENO) != 0 ||
        posix_spawn_file_actions_addinherit_np(&actions, STDOUT_FILENO) != 0 ||
        posix_spawn_file_actions_addinherit_np(&actions, STDERR_FILENO) != 0) {
        posix_spawnattr_destroy(&attr);
        posix_spawn_file_actions_destroy(&actions);
        err = "posix_spawn CLOEXEC_DEFAULT";
        return false;
    }
#endif
    pid_t pid = -1;
    const int rc = posix_spawn(&pid, fs::PathToString(m_cfg.helper_exe).c_str(), &actions, attrp, argv.data(), envp.data());
    if (attrp) posix_spawnattr_destroy(attrp);
    posix_spawn_file_actions_destroy(&actions);
    if (rc != 0) {
        err = std::strerror(rc);
        return false;
    }
#if defined(__linux__) && defined(SYS_pidfd_open) && defined(SYS_pidfd_send_signal)
    // The supervisor is the child's sole waiter. Its PID cannot be reused
    // before that wait, including if the child exits during this call.
    m_pidfd = static_cast<int>(::syscall(SYS_pidfd_open, pid, 0));
#endif
    m_pid = pid;
    m_st.pid = pid;
    m_st.managed_by_btxd = true;
    m_st.state = HelperState::STARTING;
    return true;
#else
    err = "helper spawn is not supported on this platform";
    return false;
#endif
}

void HelperSupervisor::ClearChildLocked()
{
#ifdef __linux__
    if (m_pidfd >= 0) ::close(m_pidfd);
    m_pidfd = -1;
#endif
    m_pid = -1;
    m_st.pid = -1;
}

void HelperSupervisor::RequestStopOwned()
{
#ifndef WIN32
    pid_t pid;
    {
        std::lock_guard<std::mutex> lock(m_mu);
        pid = m_pid;
    }
    if (pid <= 0) return;

    const auto wait_child = [&](int options) {
        int status = 0;
        pid_t waited;
        do {
            waited = ::waitpid(pid, &status, options);
        } while (waited < 0 && errno == EINTR);
        if (waited == pid || (waited < 0 && errno == ECHILD)) {
            std::lock_guard<std::mutex> lock(m_mu);
            ClearChildLocked();
        }
        return waited;
    };
    const auto signal_child = [&](int signal) {
#if defined(__linux__) && defined(SYS_pidfd_open) && defined(SYS_pidfd_send_signal)
        if (m_pidfd >= 0) {
            const auto result = ::syscall(SYS_pidfd_send_signal, m_pidfd, signal, nullptr, 0);
            if (result == 0 || errno != ENOSYS) return static_cast<int>(result);
        }
#endif
        // Stop() has joined the only other waiter. Confirm a live direct
        // child before signalling by PID on macOS and older Linux kernels.
        if (wait_child(WNOHANG) != 0) {
            errno = ESRCH;
            return -1;
        }
        return ::kill(pid, signal);
    };

    if (wait_child(WNOHANG) != 0) return;
    UniValue ignore;
    std::string err;
    UniValue params(UniValue::VARR);
    (void)CallUnixRpc(m_cfg.rpc_socket, "stop", params, ignore, err, nullptr, /*reply_timeout_ms=*/1000, /*check_peer=*/true, pid);
    if (signal_child(SIGTERM) != 0 && errno != ESRCH) {
        LogPrintf("model helper: SIGTERM pid=%d failed (%s)\n", static_cast<int>(pid), std::strerror(errno));
    }
    for (int i = 0; i < 50; ++i) {
        if (wait_child(WNOHANG) != 0) return;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    if (signal_child(SIGKILL) != 0 && errno != ESRCH) {
        LogPrintf("model helper: SIGKILL pid=%d failed (%s)\n", static_cast<int>(pid), std::strerror(errno));
    }
    (void)wait_child(0);
#endif
}

void HelperSupervisor::Loop()
{
    int fails = 0;
    int poll_div = 0;
    while (!m_stop.load()) {
        if (m_shutdown && m_shutdown()) break;
        if (m_cfg.external_socket) {
            std::string err;
            UniValue result;
            UniValue params(UniValue::VARR);
            const bool ok = CallUnixRpc(m_cfg.rpc_socket, "getmodelnetworkinfo", params, result, err, &m_stop);
            HelperStatus info;
            if (ok) ApplyHelperNetworkInfo(info, result);
            {
                std::lock_guard<std::mutex> lock(m_mu);
                m_st.managed_by_btxd = false;
                m_st.pid = -1;
                m_st.state = ok ? HelperState::READY : HelperState::DEGRADED;
                m_st.error = ok ? std::string{} : err;
                m_st.advertised_host = ok && info.advertised_host;
                m_st.public_host_reachable = ok && info.public_host_reachable;
            }
            SetNodeModelHostAdvertised(ok && info.advertised_host);
            for (int i = 0; i < 20 && !m_stop.load(); ++i) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            continue;
        }

#ifndef WIN32
        pid_t pid = -1;
        {
            std::lock_guard<std::mutex> lock(m_mu);
            pid = m_pid;
        }
        if (pid > 0) {
            int status = 0;
            const pid_t w = waitpid(pid, &status, WNOHANG);
            if (w == pid || (w < 0 && errno == ECHILD)) {
                bool died = false;
                {
                    std::lock_guard<std::mutex> lock(m_mu);
                    if (m_pid == pid) {
                        ClearChildLocked();
                        m_st.state = HelperState::FAILED_RETRYING;
                        ++m_st.restart_count;
                        m_st.error = "helper exited";
                        m_st.advertised_host = false;
                        m_st.public_host_reachable = false;
                        died = true;
                    }
                    fails = m_st.restart_count;
                }
                if (died) SetNodeModelHostAdvertised(false);
            }
        }
#endif

        bool need_spawn = false;
        {
            std::lock_guard<std::mutex> lock(m_mu);
            need_spawn = m_pid <= 0 && !m_cfg.external_socket && !m_cfg.helper_exe.empty() &&
                         !m_cfg.helper_explicitly_missing;
        }
        if (m_cfg.helper_explicitly_missing || m_cfg.helper_exe.empty()) {
            {
                std::lock_guard<std::mutex> lock(m_mu);
                m_st.state = HelperState::FAILED_RETRYING;
                m_st.managed_by_btxd = true;
                if (m_st.error.empty()) m_st.error = "btx-modeld not found next to btxd";
                m_st.advertised_host = false;
                m_st.public_host_reachable = false;
            }
            SetNodeModelHostAdvertised(false);
        } else if (need_spawn && !m_stop.load()) {
            std::string sock_err;
            if (SocketReady(m_cfg.rpc_socket, sock_err, &m_stop)) {
                // START-15: a live socket means an already-running helper. Do not
                // spawn a duplicate. Do not SIGTERM it on our shutdown (unmanaged).
                {
                    std::lock_guard<std::mutex> lock(m_mu);
                    m_st.state = HelperState::READY;
                    m_st.managed_by_btxd = false;
                    m_st.error.clear();
                    fails = 0;
                }
                PollAndSyncHostBit();
            } else {
                std::string err;
                bool spawned = false;
                {
                    std::lock_guard<std::mutex> lock(m_mu);
                    if (m_stop.load()) break;
                    m_st.state = HelperState::STARTING;
                    spawned = SpawnLocked(err);
                    if (!spawned) {
                        m_st.state = HelperState::FAILED_RETRYING;
                        m_st.error = err;
                    }
                }
                if (spawned) {
                    std::string ready_err;
                    if (WaitReady(15000, ready_err)) {
                        {
                            std::lock_guard<std::mutex> lock(m_mu);
                            m_st.state = HelperState::READY;
                            m_st.error.clear();
                            fails = 0;
                        }
                        PollAndSyncHostBit();
                    } else {
                        LogPrintf("model helper: started but RPC not ready (%s); monetary node continues\n", ready_err);
                        {
                            std::lock_guard<std::mutex> lock(m_mu);
                            m_st.state = HelperState::DEGRADED;
                            m_st.error = ready_err;
                            m_st.advertised_host = false;
                            m_st.public_host_reachable = false;
                        }
                        SetNodeModelHostAdvertised(false);
                    }
                } else {
                    LogPrintf("model helper: spawn failed (%s); monetary node continues\n", err);
                    SetNodeModelHostAdvertised(false);
                    const int wait_ms = NextBackoffMs(fails, static_cast<uint32_t>(fails + 1) * 1103515245u + 12345u);
                    ++fails;
                    for (int slept = 0; slept < wait_ms && !m_stop.load(); slept += 100) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    }
                    continue;
                }
            }
        } else if (!m_stop.load()) {
            if (++poll_div >= 5) {
                poll_div = 0;
                HelperState st = HelperState::DISABLED;
                {
                    std::lock_guard<std::mutex> lock(m_mu);
                    st = m_st.state;
                }
                if (st == HelperState::READY) PollAndSyncHostBit();
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
}

bool HelperSupervisor::Start(std::string& err)
{
    if (m_cfg.external_socket) {
        std::lock_guard<std::mutex> lock(m_mu);
        m_st.managed_by_btxd = false;
        m_st.state = HelperState::STARTING;
    } else if (m_cfg.helper_explicitly_missing || m_cfg.helper_exe.empty()) {
        err = "btx-modeld not found next to btxd";
        std::lock_guard<std::mutex> lock(m_mu);
        m_st.state = HelperState::FAILED_RETRYING;
        m_st.error = err;
        m_st.managed_by_btxd = true;
        if (m_cfg.required) return false;
        LogPrintf("model helper: %s; monetary node continues\n", err);
        // START-03: never start a spawn loop that could pick up a packaged substitute.
        return true;
    }
#ifndef WIN32
    if (const std::string sock = fs::PathToString(m_cfg.rpc_socket);
        !m_cfg.external_socket && sock.size() >= sizeof(sockaddr_un::sun_path)) {
        // UnixRpcListenPath() found no short private directory. The helper
        // could never bind this path, so do not start a loop that respawns
        // it every 15 seconds.
        err = strprintf("helper socket path %s is %u bytes, over the %u-byte limit; set XDG_RUNTIME_DIR to a private directory or use a shorter -datadir",
                        sock, sock.size(), sizeof(sockaddr_un::sun_path) - 1);
        std::lock_guard<std::mutex> lock(m_mu);
        m_st.state = HelperState::FAILED_RETRYING;
        m_st.error = err;
        m_st.managed_by_btxd = true;
        if (m_cfg.required) return false;
        LogPrintf("model helper: %s; monetary node continues\n", err);
        return true;
    }
#endif
    m_stop.store(false);
    m_thread = std::thread([this] { Loop(); });
    if (m_cfg.required) {
        if (!WaitReady(20000, err)) {
            std::lock_guard<std::mutex> lock(m_mu);
            m_st.state = HelperState::FAILED_RETRYING;
            m_st.error = err;
            return false;
        }
    }
    return true;
}

void HelperSupervisor::Stop()
{
    m_stop.store(true);
    // The loop may be finishing a spawn or reaping a child. Join it before
    // deciding which child to stop so only one thread can reap that PID.
    if (m_thread.joinable()) m_thread.join();
    bool owned = false;
    {
        std::lock_guard<std::mutex> lock(m_mu);
        owned = m_st.managed_by_btxd && m_pid > 0;
    }
    if (owned) {
        RequestStopOwned();
    }
    {
        std::lock_guard<std::mutex> lock(m_mu);
        m_st.state = HelperState::DISABLED;
        m_st.enabled = false;
    }
    ClearHostBit();
}

} // namespace modelnet
