// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_islandgate/admit.h>

#include <modelnet/swarm_islandgate/codes.h>
#include <modelnet/swarm_islandgate/gate.h>

namespace modelnet {

bool SwarmIslandGateApply(SwarmIslandGateRoster& roster,
                          const std::string& island,
                          int64_t epoch,
                          int64_t now,
                          std::string& err)
{
    const std::string refusal = SwarmIslandGateRefusal(roster, island, epoch, now);
    if (!refusal.empty()) {
        err = refusal;
        return false;
    }
    if (!roster.store(island, epoch)) {
        err = roster.contains(island) ? std::string{kSwarmIslandGateReplay} : std::string{kSwarmIslandGateIsland};
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
