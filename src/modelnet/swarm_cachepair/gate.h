// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CACHEPAIR_GATE_H
#define BITCOIN_MODELNET_SWARM_CACHEPAIR_GATE_H

#include <modelnet/swarm_cachepair/roster.h>

#include <string>

namespace modelnet {

/**
 * Refusal code for a Place that must not store, or empty when the
 * member may be stored on the page.
 * An empty page is PAGE. An empty member is MEMBER. A page and member
 * already stored is REPLAY. PAGE is decided before MEMBER, and both
 * are decided before REPLAY. This function does not modify the roster.
 */
std::string SwarmCachePairPlaceRefusal(const SwarmCachePairRoster& roster,
                                       const std::string& page,
                                       const std::string& member);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CACHEPAIR_GATE_H
