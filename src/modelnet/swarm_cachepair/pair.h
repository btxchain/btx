// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CACHEPAIR_PAIR_H
#define BITCOIN_MODELNET_SWARM_CACHEPAIR_PAIR_H

#include <modelnet/swarm_cachepair/roster.h>

#include <string>

namespace modelnet {

/**
 * True when page has two or more distinct members.
 * One member is not a pair. An unknown page is not a pair.
 * This function does not record a share and does not move bytes.
 */
bool SwarmCachePairIsPair(const SwarmCachePairRoster& roster, const std::string& page);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CACHEPAIR_PAIR_H
