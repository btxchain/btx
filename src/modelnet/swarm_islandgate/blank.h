// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ISLANDGATE_BLANK_H
#define BITCOIN_MODELNET_SWARM_ISLANDGATE_BLANK_H

#include <string>

namespace modelnet {

/**
 * An empty island cannot be stored.
 * Epoch and now do not change this. The check does not trim.
 */
bool SwarmIslandGateBlank(const std::string& island);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ISLANDGATE_BLANK_H
