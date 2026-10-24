// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_launchprof/record.h>

#include <modelnet/swarm_launchprof/limits.h>
#include <modelnet/swarm_launchprof/name.h>

namespace modelnet {

SwarmLaunchProfileRecord SwarmLaunchProfileRecord::Make(const std::string& name)
{
    SwarmLaunchProfileRecord record;
    record.m_name = SwarmLaunchProfileName{}.copy(name);
    record.m_renamed = kSwarmLaunchProfileRenamed;
    record.m_bytes_moved = kSwarmLaunchProfileBytesMoved;
    record.m_gpu = kSwarmLaunchProfileGpu;
    record.m_launched = kSwarmLaunchProfileLaunched;
    return record;
}

bool SwarmLaunchProfileRecordUsable(const SwarmLaunchProfileRecord& record)
{
    return !record.name().empty() &&
           record.renamed() == kSwarmLaunchProfileRenamed &&
           record.bytes_moved() == kSwarmLaunchProfileBytesMoved &&
           record.gpu() == kSwarmLaunchProfileGpu &&
           record.launched() == kSwarmLaunchProfileLaunched;
}

} // namespace modelnet
