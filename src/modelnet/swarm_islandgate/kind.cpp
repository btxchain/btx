// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_islandgate/kind.h>

#include <modelnet/swarm_islandgate/blank.h>
#include <modelnet/swarm_islandgate/codes.h>
#include <modelnet/swarm_islandgate/fresh.h>

namespace modelnet {

SwarmIslandGateKind SwarmIslandGateClassify(const std::string& island, int64_t epoch, int64_t now)
{
    if (SwarmIslandGateBlank(island)) return SwarmIslandGateKind::Island;
    if (SwarmIslandGateEpochStale(epoch, now)) return SwarmIslandGateKind::Stale;
    if (SwarmIslandGateEpochFresh(epoch, now)) return SwarmIslandGateKind::Fresh;
    return SwarmIslandGateKind::Stale;
}

const char* SwarmIslandGateKindCode(SwarmIslandGateKind kind)
{
    switch (kind) {
    case SwarmIslandGateKind::Island:
        return kSwarmIslandGateIsland;
    case SwarmIslandGateKind::Stale:
        return kSwarmIslandGateStale;
    case SwarmIslandGateKind::Fresh:
        return nullptr;
    }
    return kSwarmIslandGateIsland;
}

} // namespace modelnet
