// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SUPERVISOR_H
#define BITCOIN_MODELNET_SUPERVISOR_H

#include <util/fs.h>

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace modelnet {

enum class HelperState : uint8_t {
    DISABLED = 0,
    STARTING = 1,
    READY = 2,
    DEGRADED = 3,
    FAILED_RETRYING = 4,
};

const char* HelperStateName(HelperState s);

struct HelperLaunchConfig {
    fs::path helper_exe;
    fs::path modeldir;
    fs::path rpc_socket;
    std::string storage_arg{"auto"};
    std::string seed{"auto"};
    bool preserve_rare{false};
    bool follow_peers{true};
    uint64_t auto_cap_bytes{0};
    uint64_t reserve_bytes{0};
    uint64_t upload_bps{0};
    /** PQ1 listen host:port. Empty = unix RPC only. Packaged btxd default is 0.0.0.0:29447. */
    std::string bind;
    std::vector<std::string> peers;
    /** Operator set -modelrpcsocket: connect, do not spawn, do not kill. */
    bool external_socket{false};
    bool required{false};
    /** Operator set -modeld/-modelhelper to a missing path: never search packaged substitutes. */
    bool helper_explicitly_missing{false};
};

struct HelperStatus {
    bool enabled{false};
    bool managed_by_btxd{false};
    HelperState state{HelperState::DISABLED};
    int64_t pid{-1};
    int restart_count{0};
    std::string error;
    bool public_host_reachable{false};
    bool advertised_host{false};
};

struct HelperSpawnSpec {
    fs::path exe;
    std::vector<std::string> argv;
    std::vector<std::string> env;
};

bool EnvLooksLikeWalletSecret(const std::string& key);
std::vector<std::string> SanitizeHelperEnv(char** envp);
std::vector<std::string> BuildHelperArgv(const HelperLaunchConfig& cfg);
bool ArgvContainsWalletMaterial(const std::vector<std::string>& argv);
int NextBackoffMs(int fail_count, uint32_t jitter);

fs::path FindPackagedModeld(const fs::path& override_path);

class HelperSupervisor {
    HelperLaunchConfig m_cfg;
    mutable std::mutex m_mu;
    HelperStatus m_st;
    pid_t m_pid{-1};
    std::atomic<bool> m_stop{false};
    std::thread m_thread;
    std::function<bool()> m_shutdown;

    void Loop();
    bool SpawnLocked(std::string& err);
    void ReapLocked();
    bool WaitReady(int timeout_ms, std::string& err);
    void RequestStopOwned();

public:
    explicit HelperSupervisor(HelperLaunchConfig cfg, std::function<bool()> shutdown = {});
    ~HelperSupervisor();

    HelperSupervisor(const HelperSupervisor&) = delete;
    HelperSupervisor& operator=(const HelperSupervisor&) = delete;

    /** Never fails monetary init. required=true is the only hard fail. */
    bool Start(std::string& err);
    void Stop();
    HelperStatus Snapshot() const;
};

void SetManagedSupervisor(HelperSupervisor* p);
HelperStatus SnapshotManagedHelper();

} // namespace modelnet

#endif // BITCOIN_MODELNET_SUPERVISOR_H
