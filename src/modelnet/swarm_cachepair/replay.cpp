// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cachepair/replay.h>

namespace modelnet {

bool SwarmCachePairPlaceReplay(const SwarmCachePairRoster& roster,
                               const std::string& page,
                               const std::string& member)
{
    if (page.empty() || member.empty()) return false;
    return roster.contains(page, member);
}

bool SwarmCachePairShareReplay(const SwarmCachePairBook& book, const std::string& page)
{
    if (page.empty()) return false;
    return book.contains(page);
}

} // namespace modelnet
