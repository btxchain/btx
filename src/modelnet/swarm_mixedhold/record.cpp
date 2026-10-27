// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_mixedhold/record.h>

#include <modelnet/swarm_mixedhold/limits.h>
#include <modelnet/swarm_mixedhold/name.h>

namespace modelnet {

SwarmMixedHoldRecord SwarmMixedHoldRecord::Make(const std::string& name)
{
    SwarmMixedHoldRecord record;
    record.m_name = SwarmMixedHoldName{}.copy(name);
    record.m_running = kSwarmMixedHoldRunning;
    record.m_bytes_moved = kSwarmMixedHoldBytesMoved;
    record.m_gpu = kSwarmMixedHoldGpu;
    record.m_launched = kSwarmMixedHoldLaunched;
    return record;
}

bool SwarmMixedHoldRecordUsable(const SwarmMixedHoldRecord& record)
{
    return !record.name().empty() &&
           record.running() == kSwarmMixedHoldRunning &&
           record.bytes_moved() == kSwarmMixedHoldBytesMoved &&
           record.gpu() == kSwarmMixedHoldGpu &&
           record.launched() == kSwarmMixedHoldLaunched;
}

} // namespace modelnet
