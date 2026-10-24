// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_execnbhd/nearby.h>

#include <modelnet/swarm_execnbhd/limits.h>
#include <modelnet/swarm_execnbhd/order.h>

#include <cstddef>
#include <vector>

namespace modelnet {

std::vector<SwarmExecNbhdRecord> SwarmExecNbhdSelectNearby(const std::vector<SwarmExecNbhdRecord>& eligible)
{
    std::vector<SwarmExecNbhdRecord> ranked;
    ranked.reserve(eligible.size());
    for (const SwarmExecNbhdRecord& row : eligible) {
        if (!SwarmExecNbhdRecordAdmitted(row)) {
            continue;
        }
        ranked.push_back(row);
    }
    SwarmExecNbhdRank(ranked);
    const std::size_t cap = static_cast<std::size_t>(kSwarmExecNbhdNearbyCap);
    if (ranked.size() > cap) {
        ranked.resize(cap);
    }
    return ranked;
}

} // namespace modelnet
