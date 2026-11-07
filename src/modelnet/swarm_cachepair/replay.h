// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CACHEPAIR_REPLAY_H
#define BITCOIN_MODELNET_SWARM_CACHEPAIR_REPLAY_H

#include <modelnet/swarm_cachepair/book.h>
#include <modelnet/swarm_cachepair/roster.h>

#include <string>

namespace modelnet {

/**
 * True when this page and member are already placed.
 * An empty page or an empty member is not a replay. The first
 * placement is not compared for replacement and is not removed.
 */
bool SwarmCachePairPlaceReplay(const SwarmCachePairRoster& roster,
                               const std::string& page,
                               const std::string& member);

/**
 * True when this page already has a recorded share.
 * An empty page is not a replay. The stored member list is left
 * as it was.
 */
bool SwarmCachePairShareReplay(const SwarmCachePairBook& book, const std::string& page);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CACHEPAIR_REPLAY_H
