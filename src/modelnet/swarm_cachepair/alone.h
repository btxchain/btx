// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CACHEPAIR_ALONE_H
#define BITCOIN_MODELNET_SWARM_CACHEPAIR_ALONE_H

#include <modelnet/swarm_cachepair/roster.h>

#include <string>

namespace modelnet {

/**
 * True when page is known and has fewer than two distinct members.
 * An unknown page is not alone. A page that meets the share minimum
 * is not alone. This function records nothing.
 */
bool SwarmCachePairAlone(const SwarmCachePairRoster& roster, const std::string& page);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CACHEPAIR_ALONE_H
