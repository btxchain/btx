// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cachepair/known.h>

#include <modelnet/swarm_cachepair/blank.h>

namespace modelnet {

bool SwarmCachePairPageKnown(const SwarmCachePairRoster& roster, const std::string& page)
{
    if (SwarmCachePairPageBlank(page)) return false;
    return roster.known(page);
}

} // namespace modelnet
