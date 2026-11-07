// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_ablatehold/record.h>

#include <modelnet/swarm_ablatehold/limits.h>
#include <modelnet/swarm_ablatehold/name.h>

namespace modelnet {

SwarmAblateHoldRecord SwarmAblateHoldRecord::Make(const std::string& name)
{
    SwarmAblateHoldRecord record;
    record.m_name = SwarmAblateHoldName{}.copy(name);
    record.m_published = kSwarmAblateHoldPublished;
    record.m_bytes_moved = kSwarmAblateHoldBytesMoved;
    record.m_gpu = kSwarmAblateHoldGpu;
    record.m_launched = kSwarmAblateHoldLaunched;
    return record;
}

bool SwarmAblateHoldRecordUsable(const SwarmAblateHoldRecord& record)
{
    return !record.name().empty() &&
           record.published() == kSwarmAblateHoldPublished &&
           record.bytes_moved() == kSwarmAblateHoldBytesMoved &&
           record.gpu() == kSwarmAblateHoldGpu &&
           record.launched() == kSwarmAblateHoldLaunched;
}

} // namespace modelnet
