// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_BOUND_SWARM_BOUND_H
#define BITCOIN_MODELNET_SWARM_BOUND_SWARM_BOUND_H

#include <modelnet/dt_dense/dt_dense.h>
#include <modelnet/dt_twonode/dt_twonode.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/realm_roles/realm_roles.h>
#include <modelnet/replay_check/replay_check.h>
#include <modelnet/snapshot_pull/snapshot_pull.h>
#include <modelnet/swarm_decode/swarm_decode_run.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * One bounded pass of the native inference and training engines.
 *
 * The first Pass runs a memory decode, one dense CPU step, one socketpair
 * exchange of two ranks, and one integer replay. A later Pass does not
 * step again. vLLM and the dense GPU step stay ENGINE_ABSENT.
 * hosts() stays 1. passed(), gpu_passed(), and windows_passed() stay false.
 * Spend returns NIFDT_AUTOMATIC_SPEND. No child process is started.
 */
class SwarmBoundProbe {
public:
    bool Pass(int64_t now_ms, std::string& err);
    bool Spend(std::string& err);
    bool Release(std::string& err);

    int64_t ticks() const { return m_ticks; }
    int64_t infer_tokens() const { return m_decode.tokens(); }
    int64_t train_steps() const { return m_dense.adam_step(); }
    int64_t exchange_bytes() const { return m_pair.bytes_moved(); }
    int hosts() const { return 1; }
    int ranks() const { return m_pair.ranks(); }
    bool replay_ok() const { return m_replay_ok; }
    bool gpu() const { return false; }
    bool gpu_passed() const { return false; }
    bool windows_passed() const { return false; }
    bool passed() const { return false; }
    bool launched() const { return false; }
    bool broadcast() const { return false; }
    bool release_qualified() const { return false; }
    std::string remote_engine() const { return m_remote; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    bool Once(std::string& err);

    SwarmDecodeRun m_decode;
    DtDense m_dense;
    DtTwoNode m_pair;
    ReplayCheck m_replay;
    SnapshotPull m_snap;
    RealmRoles m_roles;
    int64_t m_ticks{0};
    int64_t m_now_ms{0};
    bool m_done{false};
    bool m_replay_ok{false};
    std::string m_remote;
};

} // namespace modelnet

#endif
