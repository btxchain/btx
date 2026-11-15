// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fsdphold/record.h>

#include <modelnet/swarm_fsdphold/limits.h>
#include <modelnet/swarm_fsdphold/name.h>

namespace modelnet {

SwarmFsdpHoldRecord SwarmFsdpHoldRecord::Make(const std::string& name)
{
    SwarmFsdpHoldRecord record;
    record.m_name = SwarmFsdpHoldName{}.copy(name);
    record.m_running = kSwarmFsdpHoldRunning;
    record.m_bytes_moved = kSwarmFsdpHoldBytesMoved;
    record.m_gpu = kSwarmFsdpHoldGpu;
    record.m_launched = kSwarmFsdpHoldLaunched;
    return record;
}

bool SwarmFsdpHoldRecordUsable(const SwarmFsdpHoldRecord& record)
{
    return !record.name().empty() &&
           record.running() == kSwarmFsdpHoldRunning &&
           record.bytes_moved() == kSwarmFsdpHoldBytesMoved &&
           record.gpu() == kSwarmFsdpHoldGpu &&
           record.launched() == kSwarmFsdpHoldLaunched;
}

} // namespace modelnet
