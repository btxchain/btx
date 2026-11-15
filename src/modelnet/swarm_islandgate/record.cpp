// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_islandgate/record.h>

namespace modelnet {

SwarmIslandGateRecord SwarmIslandGateMakeRecord(const std::string& island, int64_t epoch)
{
    SwarmIslandGateRecord record;
    record.island = island;
    record.epoch = epoch;
    return record;
}

bool SwarmIslandGateRecordUsable(const SwarmIslandGateRecord& record)
{
    return !record.island.empty();
}

} // namespace modelnet
