// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/supervisor.h>

#include <logging.h>
#include <modelnet/helper.h>
#include <univalue.h>
#include <util/fs.h>
#include <util/strencodings.h>

#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstring>
#include <filesystem>
#include <system_error>
#include <thread>

#ifndef WIN32
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif
extern char** environ;
#endif

namespace modelnet {
namespace {

HelperSupervisor* g_managed = nullptr;

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
#endif
    return {};
}

bool SocketReady(const fs::path& sock, std::string& err)
{
    UniValue result;
    UniValue params(UniValue::VARR);
    return CallUnixRpc(sock, "getmodelnetworkinfo", params, result, err);
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
    if (cfg.preserve_rare) argv.push_back("-modelpreserverare");
    if (!cfg.follow_peers) argv.push_back("-modelfollowpeers=0");
    for (const auto& peer : cfg.peers) {
        if (!peer.empty()) argv.push_back("-modelpeer=" + peer);
    }
    if (cfg.auto_cap_bytes > 0) argv.push_back("-modelstorageautocap=" + std::to_string(cfg.auto_cap_bytes));
    if (cfg.reserve_bytes > 0) argv.push_back("-modelfreespacereserve=" + std::to_string(cfg.reserve_bytes));
    if (cfg.upload_bps > 0) argv.push_back("-modeluploadlimit=" + std::to_string(cfg.upload_bps));
    return argv;
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

fs::path FindPackagedModeld(const fs::path& override_path)
{
    if (!override_path.empty()) {
        if (fs::exists(override_path)) return override_path;
        return {};
    }
    const fs::path dir = SelfExeDir();
    const fs::path cands[] = {
        dir / "btx-modeld",
        dir / "libexec" / "btx-modeld",
        dir.parent_path() / "libexec" / "btx-modeld",
        dir.parent_path() / "bin" / "btx-modeld",
    };
    for (const auto& c : cands) {
        if (!c.empty() && fs::exists(c)) return c;
    }
    return {};
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

bool HelperSupervisor::WaitReady(int timeout_ms, std::string& err)
{
    const int step = 100;
    for (int waited = 0; waited < timeout_ms; waited += step) {
        if (m_stop.load()) {
            err = "stopped";
            return false;
        }
        if (SocketReady(m_cfg.rpc_socket, err)) return true;
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
    std::string sock_err;
    if (!SocketReady(m_cfg.rpc_socket, sock_err)) {
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
    const auto env_s = SanitizeHelperEnv(environ);
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
    pid_t pid = -1;
    const int rc = posix_spawn(&pid, fs::PathToString(m_cfg.helper_exe).c_str(), &actions, nullptr, argv.data(), envp.data());
    posix_spawn_file_actions_destroy(&actions);
    if (rc != 0) {
        err = std::strerror(rc);
        return false;
    }
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

void HelperSupervisor::RequestStopOwned()
{
#ifndef WIN32
    pid_t pid = -1;
    {
        std::lock_guard<std::mutex> lock(m_mu);
        pid = m_pid;
    }
    if (pid <= 0) return;
    UniValue ignore;
    std::string err;
    UniValue params(UniValue::VARR);
    (void)CallUnixRpc(m_cfg.rpc_socket, "stop", params, ignore, err);
    if (kill(pid, SIGTERM) != 0 && errno != ESRCH) {
        LogPrintf("model helper: SIGTERM pid=%d failed (%s)\n", static_cast<int>(pid), std::strerror(errno));
    }
    for (int i = 0; i < 50; ++i) {
        int status = 0;
        const pid_t w = waitpid(pid, &status, WNOHANG);
        if (w == pid || (w < 0 && errno == ECHILD)) {
            std::lock_guard<std::mutex> lock(m_mu);
            if (m_pid == pid) {
                m_pid = -1;
                m_st.pid = -1;
            }
            return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    if (kill(pid, SIGKILL) != 0 && errno != ESRCH) {
        LogPrintf("model helper: SIGKILL pid=%d failed (%s)\n", static_cast<int>(pid), std::strerror(errno));
    }
    int status = 0;
    (void)waitpid(pid, &status, 0);
    std::lock_guard<std::mutex> lock(m_mu);
    if (m_pid == pid) {
        m_pid = -1;
        m_st.pid = -1;
    }
#endif
}

void HelperSupervisor::Loop()
{
    int fails = 0;
    while (!m_stop.load()) {
        if (m_shutdown && m_shutdown()) break;
        if (m_cfg.external_socket) {
            std::string err;
            const bool ok = SocketReady(m_cfg.rpc_socket, err);
            {
                std::lock_guard<std::mutex> lock(m_mu);
                m_st.managed_by_btxd = false;
                m_st.pid = -1;
                m_st.state = ok ? HelperState::READY : HelperState::DEGRADED;
                m_st.error = ok ? std::string{} : err;
            }
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
            if (w == pid) {
                std::lock_guard<std::mutex> lock(m_mu);
                if (m_pid == pid) {
                    m_pid = -1;
                    m_st.pid = -1;
                    m_st.state = HelperState::FAILED_RETRYING;
                    ++m_st.restart_count;
                    m_st.error = "helper exited";
                }
                fails = m_st.restart_count;
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
            std::lock_guard<std::mutex> lock(m_mu);
            m_st.state = HelperState::FAILED_RETRYING;
            m_st.managed_by_btxd = true;
            if (m_st.error.empty()) m_st.error = "btx-modeld not found next to btxd";
        } else if (need_spawn && !m_stop.load()) {
            std::string sock_err;
            if (SocketReady(m_cfg.rpc_socket, sock_err)) {
                // START-15: a live socket means an already-running helper. Do not
                // spawn a duplicate. Do not SIGTERM it on our shutdown (unmanaged).
                std::lock_guard<std::mutex> lock(m_mu);
                m_st.state = HelperState::READY;
                m_st.managed_by_btxd = false;
                m_st.error.clear();
                fails = 0;
            } else {
                std::string err;
                bool spawned = false;
                {
                    std::lock_guard<std::mutex> lock(m_mu);
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
                        std::lock_guard<std::mutex> lock(m_mu);
                        m_st.state = HelperState::READY;
                        m_st.error.clear();
                        fails = 0;
                    } else {
                        LogPrintf("model helper: started but RPC not ready (%s); monetary node continues\n", ready_err);
                        std::lock_guard<std::mutex> lock(m_mu);
                        m_st.state = HelperState::DEGRADED;
                        m_st.error = ready_err;
                    }
                } else {
                    LogPrintf("model helper: spawn failed (%s); monetary node continues\n", err);
                    const int wait_ms = NextBackoffMs(fails, static_cast<uint32_t>(fails + 1) * 1103515245u + 12345u);
                    ++fails;
                    for (int slept = 0; slept < wait_ms && !m_stop.load(); slept += 100) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    }
                    continue;
                }
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
    bool owned = false;
    {
        std::lock_guard<std::mutex> lock(m_mu);
        owned = m_st.managed_by_btxd && m_pid > 0;
    }
    if (owned) {
        RequestStopOwned();
    }
    if (m_thread.joinable()) m_thread.join();
    {
        std::lock_guard<std::mutex> lock(m_mu);
        m_st.state = HelperState::DISABLED;
        m_st.enabled = false;
    }
}

} // namespace modelnet
