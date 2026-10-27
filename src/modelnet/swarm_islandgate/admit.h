// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ISLANDGATE_ADMIT_H
#define BITCOIN_MODELNET_SWARM_ISLANDGATE_ADMIT_H

#include <modelnet/swarm_islandgate/roster.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Admit island when it is non-empty, not already stored, and epoch >= now.
 * On success the island is stored with epoch and err is cleared.
 * On failure nothing is stored and err is ISLAND, REPLAY, or STALE.
 * A replay leaves the first epoch in place.
 * This does not exchange bytes.
 */
bool SwarmIslandGateApply(SwarmIslandGateRoster& roster,
                          const std::string& island,
                          int64_t epoch,
                          int64_t now,
                          std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ISLANDGATE_ADMIT_H
