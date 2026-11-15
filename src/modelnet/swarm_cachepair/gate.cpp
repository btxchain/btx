// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cachepair/gate.h>

#include <modelnet/swarm_cachepair/codes.h>
#include <modelnet/swarm_cachepair/member.h>
#include <modelnet/swarm_cachepair/page.h>
#include <modelnet/swarm_cachepair/replay.h>

namespace modelnet {

std::string SwarmCachePairPlaceRefusal(const SwarmCachePairRoster& roster,
                                       const std::string& page,
                                       const std::string& member)
{
    const char* page_code = SwarmCachePairPageCode(SwarmCachePairClassifyPage(page));
    if (page_code != nullptr) return std::string{page_code};
    const char* member_code = SwarmCachePairMemberCode(SwarmCachePairClassifyMember(member));
    if (member_code != nullptr) return std::string{member_code};
    if (SwarmCachePairPlaceReplay(roster, page, member)) return std::string{kSwarmCachePairReplay};
    return {};
}

} // namespace modelnet
