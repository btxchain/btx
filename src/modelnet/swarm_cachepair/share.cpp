// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cachepair/share.h>

#include <modelnet/swarm_cachepair/alone.h>
#include <modelnet/swarm_cachepair/codes.h>
#include <modelnet/swarm_cachepair/known.h>
#include <modelnet/swarm_cachepair/pair.h>
#include <modelnet/swarm_cachepair/replay.h>

#include <vector>

namespace modelnet {

bool SwarmCachePairShare(const SwarmCachePairRoster& roster,
                         SwarmCachePairBook& book,
                         const std::string& page,
                         std::string& err)
{
    if (!SwarmCachePairPageKnown(roster, page)) {
        err = kSwarmCachePairPage;
        return false;
    }
    if (SwarmCachePairShareReplay(book, page)) {
        err = kSwarmCachePairReplay;
        return false;
    }
    if (SwarmCachePairAlone(roster, page) || !SwarmCachePairIsPair(roster, page)) {
        err = kSwarmCachePairAlone;
        return false;
    }
    const std::vector<std::string> members = roster.list(page);
    if (!book.store(page, members)) {
        err = book.contains(page) ? std::string{kSwarmCachePairReplay} : std::string{kSwarmCachePairAlone};
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
