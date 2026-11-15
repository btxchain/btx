// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_loginhold/record.h>

#include <modelnet/swarm_loginhold/limits.h>
#include <modelnet/swarm_loginhold/name.h>

namespace modelnet {

SwarmLoginHoldRecord SwarmLoginHoldRecord::Make(const std::string& name)
{
    SwarmLoginHoldRecord record;
    record.m_name = SwarmLoginHoldName{}.copy(name);
    record.m_logged_in = kSwarmLoginHoldLoggedIn;
    record.m_bytes_moved = kSwarmLoginHoldBytesMoved;
    record.m_gpu = kSwarmLoginHoldGpu;
    record.m_launched = kSwarmLoginHoldLaunched;
    return record;
}

bool SwarmLoginHoldRecordUsable(const SwarmLoginHoldRecord& record)
{
    return !record.name().empty() &&
           record.logged_in() == kSwarmLoginHoldLoggedIn &&
           record.bytes_moved() == kSwarmLoginHoldBytesMoved &&
           record.gpu() == kSwarmLoginHoldGpu &&
           record.launched() == kSwarmLoginHoldLaunched;
}

} // namespace modelnet
