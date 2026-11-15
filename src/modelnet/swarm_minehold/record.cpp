// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_minehold/record.h>

#include <modelnet/swarm_minehold/limits.h>
#include <modelnet/swarm_minehold/name.h>

namespace modelnet {

SwarmMineHoldRecord SwarmMineHoldRecord::Make(const std::string& name)
{
    SwarmMineHoldRecord record;
    record.m_name = SwarmMineHoldName{}.copy(name);
    record.m_mined = kSwarmMineHoldMined;
    record.m_blocks = kSwarmMineHoldBlocks;
    record.m_bytes_moved = kSwarmMineHoldBytesMoved;
    record.m_broadcast = kSwarmMineHoldBroadcast;
    record.m_gpu = kSwarmMineHoldGpu;
    return record;
}

bool SwarmMineHoldRecordUsable(const SwarmMineHoldRecord& record)
{
    return !record.name().empty() &&
           record.mined() == kSwarmMineHoldMined &&
           record.blocks() == kSwarmMineHoldBlocks &&
           record.bytes_moved() == kSwarmMineHoldBytesMoved &&
           record.broadcast() == kSwarmMineHoldBroadcast &&
           record.gpu() == kSwarmMineHoldGpu;
}

} // namespace modelnet
