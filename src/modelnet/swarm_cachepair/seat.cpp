// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cachepair/seat.h>

#include <modelnet/swarm_cachepair/member.h>
#include <modelnet/swarm_cachepair/page.h>

namespace modelnet {

SwarmCachePairSeat SwarmCachePairMakeSeat(const std::string& page, const std::string& member)
{
    SwarmCachePairSeat seat;
    seat.page = page;
    seat.member = member;
    return seat;
}

bool SwarmCachePairSeatUsable(const SwarmCachePairSeat& seat)
{
    return SwarmCachePairClassifyPage(seat.page) == SwarmCachePairPageKind::Named &&
           SwarmCachePairClassifyMember(seat.member) == SwarmCachePairMemberKind::Named;
}

} // namespace modelnet
