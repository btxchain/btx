// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_execnbhd/remote.h>

#include <modelnet/swarm_execnbhd/limits.h>
#include <modelnet/swarm_execnbhd/order.h>

#include <cstddef>
#include <set>
#include <string>
#include <vector>

namespace modelnet {

std::vector<SwarmExecNbhdRecord> SwarmExecNbhdSelectRemote(const std::vector<SwarmExecNbhdRecord>& eligible,
                                                           const std::vector<SwarmExecNbhdRecord>& nearby)
{
    std::set<std::string> nearby_peers;
    std::set<std::string> nearby_domains;
    for (const SwarmExecNbhdRecord& row : nearby) {
        nearby_peers.insert(row.peer);
        nearby_domains.insert(row.trust_domain);
    }

    std::vector<SwarmExecNbhdRecord> ranked;
    ranked.reserve(eligible.size());
    for (const SwarmExecNbhdRecord& row : eligible) {
        if (!SwarmExecNbhdRecordAdmitted(row)) {
            continue;
        }
        if (nearby_peers.count(row.peer) != 0) {
            continue;
        }
        if (nearby_domains.count(row.trust_domain) != 0) {
            continue;
        }
        ranked.push_back(row);
    }
    SwarmExecNbhdRank(ranked);
    const std::size_t cap = static_cast<std::size_t>(kSwarmExecNbhdRemoteCap);
    if (ranked.size() > cap) {
        ranked.resize(cap);
    }
    return ranked;
}

} // namespace modelnet
