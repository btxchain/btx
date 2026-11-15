// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_islandgate/gate.h>

#include <modelnet/swarm_islandgate/codes.h>
#include <modelnet/swarm_islandgate/kind.h>
#include <modelnet/swarm_islandgate/replay.h>

namespace modelnet {

std::string SwarmIslandGateRefusal(const SwarmIslandGateRoster& roster,
                                   const std::string& island,
                                   int64_t epoch,
                                   int64_t now)
{
    const SwarmIslandGateKind kind = SwarmIslandGateClassify(island, epoch, now);
    if (kind == SwarmIslandGateKind::Island) {
        const char* code = SwarmIslandGateKindCode(kind);
        if (code == nullptr) return std::string{kSwarmIslandGateIsland};
        return std::string{code};
    }
    if (SwarmIslandGateIsReplay(roster, island)) return std::string{kSwarmIslandGateReplay};
    if (kind == SwarmIslandGateKind::Stale) {
        const char* code = SwarmIslandGateKindCode(kind);
        if (code == nullptr) return std::string{kSwarmIslandGateStale};
        return std::string{code};
    }
    return {};
}

} // namespace modelnet
