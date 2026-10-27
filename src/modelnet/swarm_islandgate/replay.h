// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ISLANDGATE_REPLAY_H
#define BITCOIN_MODELNET_SWARM_ISLANDGATE_REPLAY_H

#include <modelnet/swarm_islandgate/roster.h>

#include <string>

namespace modelnet {

/**
 * True when island is already stored.
 * An empty island is not a replay. The stored epoch is not compared and
 * is not replaced.
 */
bool SwarmIslandGateIsReplay(const SwarmIslandGateRoster& roster, const std::string& island);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ISLANDGATE_REPLAY_H
