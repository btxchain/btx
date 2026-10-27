// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_paycycle/split.h>

#include <modelnet/swarm_paycycle/codes.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool SwarmPaySplitBook::Store(int64_t rollout, int64_t negative, int64_t reproduction, int64_t evaluation,
                              int64_t challengers, int64_t milestone, std::string& err)
{
    const int64_t parts[] = {rollout, negative, reproduction, evaluation, challengers, milestone};
    int64_t sum = 0;
    for (const int64_t part : parts) {
        // Each part fits in the ppm total, so the sum cannot overflow int64_t.
        if (part < 0 || part > 1000000) {
            err = SWARM_PAYCYCLE_SPLIT;
            return false;
        }
        sum += part;
    }
    if (sum != 1000000) {
        err = SWARM_PAYCYCLE_SPLIT;
        return false;
    }
    m_rollout = rollout;
    m_negative = negative;
    m_reproduction = reproduction;
    m_evaluation = evaluation;
    m_challengers = challengers;
    m_milestone = milestone;
    m_ok = true;
    err.clear();
    return true;
}

bool SwarmPaySplitBook::ok() const
{
    return m_ok;
}

int64_t SwarmPaySplitBook::part(const std::string& name) const
{
    if (name == "rollout") return m_rollout;
    if (name == "negative") return m_negative;
    if (name == "reproduction") return m_reproduction;
    if (name == "evaluation") return m_evaluation;
    if (name == "challengers") return m_challengers;
    if (name == "milestone") return m_milestone;
    return -1;
}

} // namespace modelnet
