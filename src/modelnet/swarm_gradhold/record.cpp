// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_gradhold/record.h>

#include <modelnet/swarm_gradhold/limits.h>
#include <modelnet/swarm_gradhold/name.h>

namespace modelnet {

SwarmGradHoldRecord SwarmGradHoldRecord::Make(const std::string& update_id)
{
    SwarmGradHoldRecord record;
    record.m_update_id = SwarmGradHoldName{}.copy(update_id);
    record.m_exported = kSwarmGradHoldExported;
    record.m_bytes_moved = kSwarmGradHoldBytesMoved;
    record.m_gpu = kSwarmGradHoldGpu;
    record.m_launched = kSwarmGradHoldLaunched;
    return record;
}

bool SwarmGradHoldRecordUsable(const SwarmGradHoldRecord& record)
{
    return !record.update_id().empty() &&
           record.exported() == kSwarmGradHoldExported &&
           record.bytes_moved() == kSwarmGradHoldBytesMoved &&
           record.gpu() == kSwarmGradHoldGpu &&
           record.launched() == kSwarmGradHoldLaunched;
}

} // namespace modelnet
