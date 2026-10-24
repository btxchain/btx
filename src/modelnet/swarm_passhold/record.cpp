// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_passhold/record.h>

#include <modelnet/swarm_passhold/limits.h>
#include <modelnet/swarm_passhold/name.h>

namespace modelnet {

SwarmPassHoldRecord SwarmPassHoldRecord::Make(const std::string& name)
{
    SwarmPassHoldRecord record;
    record.m_name = SwarmPassHoldName{}.copy(name);
    record.m_started = kSwarmPassHoldStarted;
    record.m_passed = kSwarmPassHoldPassed;
    record.m_bytes_moved = kSwarmPassHoldBytesMoved;
    record.m_gpu = kSwarmPassHoldGpu;
    record.m_launched = kSwarmPassHoldLaunched;
    return record;
}

bool SwarmPassHoldRecordUsable(const SwarmPassHoldRecord& record)
{
    return !record.name().empty() &&
           record.started() == kSwarmPassHoldStarted &&
           record.passed() == kSwarmPassHoldPassed &&
           record.bytes_moved() == kSwarmPassHoldBytesMoved &&
           record.gpu() == kSwarmPassHoldGpu &&
           record.launched() == kSwarmPassHoldLaunched;
}

} // namespace modelnet
