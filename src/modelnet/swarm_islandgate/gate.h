// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ISLANDGATE_GATE_H
#define BITCOIN_MODELNET_SWARM_ISLANDGATE_GATE_H

#include <modelnet/swarm_islandgate/roster.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Refusal code for an Admit that must not store, or empty when the island
 * may be stored.
 * Empty island is ISLAND. An island already stored is REPLAY and the
 * first epoch stays, including when the new epoch is stale or later.
 * Otherwise epoch < now is STALE. This function does not modify the roster.
 */
std::string SwarmIslandGateRefusal(const SwarmIslandGateRoster& roster,
                                   const std::string& island,
                                   int64_t epoch,
                                   int64_t now);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ISLANDGATE_GATE_H
