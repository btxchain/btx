// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ISLANDGATE_RECORD_H
#define BITCOIN_MODELNET_SWARM_ISLANDGATE_RECORD_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * One admitted island and the epoch stored with it.
 * The epoch is the value from the successful Admit. Nothing here
 * exchanges bytes or launches work.
 */
struct SwarmIslandGateRecord {
    std::string island;
    int64_t epoch{0};
};

SwarmIslandGateRecord SwarmIslandGateMakeRecord(const std::string& island, int64_t epoch);

/** The island id must be non-empty. Any epoch is usable. */
bool SwarmIslandGateRecordUsable(const SwarmIslandGateRecord& record);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ISLANDGATE_RECORD_H
