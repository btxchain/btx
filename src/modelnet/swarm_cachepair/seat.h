// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CACHEPAIR_SEAT_H
#define BITCOIN_MODELNET_SWARM_CACHEPAIR_SEAT_H

#include <string>

namespace modelnet {

/**
 * One placement: a named member on a named page.
 * An empty page or an empty member is not a seat that can be stored.
 */
struct SwarmCachePairSeat {
    std::string page;
    std::string member;
};

SwarmCachePairSeat SwarmCachePairMakeSeat(const std::string& page, const std::string& member);

/** True when both the page and the member are named. */
bool SwarmCachePairSeatUsable(const SwarmCachePairSeat& seat);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CACHEPAIR_SEAT_H
