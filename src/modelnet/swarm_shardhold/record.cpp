// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_shardhold/record.h>

#include <modelnet/swarm_shardhold/limits.h>
#include <modelnet/swarm_shardhold/name.h>

namespace modelnet {

SwarmShardHoldRecord SwarmShardHoldRecord::Make(const std::string& name)
{
    SwarmShardHoldRecord record;
    record.m_name = SwarmShardHoldName{}.copy(name);
    record.m_sharded = kSwarmShardHoldSharded;
    record.m_running = kSwarmShardHoldRunning;
    record.m_bytes_moved = kSwarmShardHoldBytesMoved;
    record.m_gpu = kSwarmShardHoldGpu;
    record.m_launched = kSwarmShardHoldLaunched;
    return record;
}

bool SwarmShardHoldRecordUsable(const SwarmShardHoldRecord& record)
{
    return !record.name().empty() &&
           record.sharded() == kSwarmShardHoldSharded &&
           record.running() == kSwarmShardHoldRunning &&
           record.bytes_moved() == kSwarmShardHoldBytesMoved &&
           record.gpu() == kSwarmShardHoldGpu &&
           record.launched() == kSwarmShardHoldLaunched;
}

} // namespace modelnet
