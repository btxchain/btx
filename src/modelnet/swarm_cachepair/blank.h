// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CACHEPAIR_BLANK_H
#define BITCOIN_MODELNET_SWARM_CACHEPAIR_BLANK_H

#include <string>

namespace modelnet {

/** An empty page cannot be stored. */
bool SwarmCachePairPageBlank(const std::string& page);

/** An empty member cannot be stored. */
bool SwarmCachePairMemberBlank(const std::string& member);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CACHEPAIR_BLANK_H
