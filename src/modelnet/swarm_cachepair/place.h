// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CACHEPAIR_PLACE_H
#define BITCOIN_MODELNET_SWARM_CACHEPAIR_PLACE_H

#include <modelnet/swarm_cachepair/roster.h>

#include <string>

namespace modelnet {

/**
 * Place member on page.
 * On success the member is stored and err is cleared.
 * On failure nothing new is stored and err is PAGE, MEMBER, or REPLAY.
 * A replay leaves the first placement in place.
 * This does not record a share, move a byte, or start a process.
 */
bool SwarmCachePairPlace(SwarmCachePairRoster& roster,
                         const std::string& page,
                         const std::string& member,
                         std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CACHEPAIR_PLACE_H
