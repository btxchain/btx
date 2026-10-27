// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CACHEPAIR_KNOWN_H
#define BITCOIN_MODELNET_SWARM_CACHEPAIR_KNOWN_H

#include <modelnet/swarm_cachepair/roster.h>

#include <string>

namespace modelnet {

/**
 * True when page holds at least one placed member.
 * An empty page is not known. A page that Place refused is not known.
 * This function does not modify the roster.
 */
bool SwarmCachePairPageKnown(const SwarmCachePairRoster& roster, const std::string& page);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CACHEPAIR_KNOWN_H
