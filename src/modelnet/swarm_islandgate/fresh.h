// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ISLANDGATE_FRESH_H
#define BITCOIN_MODELNET_SWARM_ISLANDGATE_FRESH_H

#include <cstdint>

namespace modelnet {

/**
 * epoch < now.
 * A stale island is not admitted. Equality is not stale.
 */
bool SwarmIslandGateEpochStale(int64_t epoch, int64_t now);

/**
 * epoch >= now.
 * Equality is fresh and may be stored when the island is usable.
 */
bool SwarmIslandGateEpochFresh(int64_t epoch, int64_t now);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ISLANDGATE_FRESH_H
