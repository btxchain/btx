// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_islandopt.h>

namespace modelnet {

bool SwarmIslandOpt::LocalStep(std::string& err)
{
    if (IntegerDataset().size() != 8) {
        err = "PAIRS";
        return false;
    }
    if (!m_trainer.Step(err)) return false;
    if (!m_trainer.ReplayMatches(m_trainer.State(), err)) return false;
    m_steps = m_trainer.State().step;
    m_state_hash = m_trainer.State().state_hash;
    err.clear();
    return true;
}

bool SwarmIslandOpt::AcceptRemote(uint64_t remote_step, const std::string& remote_hash, bool stale, std::string& err)
{
    if (stale) {
        err = "NOT_ADMITTED";
        return false;
    }
    if (remote_hash.empty()) {
        err = "HASH";
        return false;
    }
    if (remote_step != m_steps + 1) {
        err = "STALE";
        return false;
    }
    m_pending_hash = remote_hash;
    err.clear();
    return true;
}

bool SwarmIslandOpt::RejectAverage(std::string& err)
{
    err = "NOT_AVERAGED";
    return false;
}

} // namespace modelnet
