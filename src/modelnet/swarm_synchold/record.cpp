// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_synchold/record.h>

#include <modelnet/swarm_synchold/limits.h>
#include <modelnet/swarm_synchold/name.h>

namespace modelnet {

SwarmSyncHoldRecord SwarmSyncHoldRecord::Make(const std::string& name)
{
    SwarmSyncHoldRecord record;
    record.m_name = SwarmSyncHoldName{}.copy(name);
    record.m_synced = kSwarmSyncHoldSynced;
    record.m_bytes_moved = kSwarmSyncHoldBytesMoved;
    record.m_gpu = kSwarmSyncHoldGpu;
    record.m_launched = kSwarmSyncHoldLaunched;
    return record;
}

bool SwarmSyncHoldRecordUsable(const SwarmSyncHoldRecord& record)
{
    return !record.name().empty() &&
           record.synced() == kSwarmSyncHoldSynced &&
           record.bytes_moved() == kSwarmSyncHoldBytesMoved &&
           record.gpu() == kSwarmSyncHoldGpu &&
           record.launched() == kSwarmSyncHoldLaunched;
}

} // namespace modelnet
