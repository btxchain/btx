// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cachepair/pair.h>

#include <modelnet/swarm_cachepair/known.h>
#include <modelnet/swarm_cachepair/limits.h>

namespace modelnet {

bool SwarmCachePairIsPair(const SwarmCachePairRoster& roster, const std::string& page)
{
    if (!SwarmCachePairPageKnown(roster, page)) return false;
    return roster.members(page) >= kSwarmCachePairShareMin;
}

} // namespace modelnet
