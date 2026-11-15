// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cachepair/place.h>

#include <modelnet/swarm_cachepair/codes.h>
#include <modelnet/swarm_cachepair/gate.h>

namespace modelnet {

bool SwarmCachePairPlace(SwarmCachePairRoster& roster,
                         const std::string& page,
                         const std::string& member,
                         std::string& err)
{
    const std::string refusal = SwarmCachePairPlaceRefusal(roster, page, member);
    if (!refusal.empty()) {
        err = refusal;
        return false;
    }
    if (!roster.place(page, member)) {
        if (roster.contains(page, member)) {
            err = kSwarmCachePairReplay;
        } else if (page.empty()) {
            err = kSwarmCachePairPage;
        } else {
            err = kSwarmCachePairMember;
        }
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
