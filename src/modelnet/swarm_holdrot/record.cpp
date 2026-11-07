// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_holdrot/record.h>

#include <modelnet/swarm_holdrot/limits.h>
#include <modelnet/swarm_holdrot/name.h>

namespace modelnet {

SwarmHoldoutRotateRecord SwarmHoldoutRotateRecord::Make(const std::string& holdout)
{
    SwarmHoldoutRotateRecord record;
    record.m_holdout = SwarmHoldoutRotateName{}.copy(holdout);
    record.m_rotated = kSwarmHoldoutRotateRotated;
    record.m_bytes_moved = kSwarmHoldoutRotateBytesMoved;
    record.m_gpu = kSwarmHoldoutRotateGpu;
    record.m_launched = kSwarmHoldoutRotateLaunched;
    return record;
}

bool SwarmHoldoutRotateRecordUsable(const SwarmHoldoutRotateRecord& record)
{
    return !record.holdout().empty() &&
           record.rotated() == kSwarmHoldoutRotateRotated &&
           record.bytes_moved() == kSwarmHoldoutRotateBytesMoved &&
           record.gpu() == kSwarmHoldoutRotateGpu &&
           record.launched() == kSwarmHoldoutRotateLaunched;
}

} // namespace modelnet
