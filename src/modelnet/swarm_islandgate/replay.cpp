// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_islandgate/replay.h>

namespace modelnet {

bool SwarmIslandGateIsReplay(const SwarmIslandGateRoster& roster, const std::string& island)
{
    if (island.empty()) return false;
    return roster.contains(island);
}

} // namespace modelnet
