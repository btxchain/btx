// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_rescap/record.h>

#include <modelnet/swarm_rescap/limits.h>

namespace modelnet {

SwarmResCapRecord SwarmResCapRecord::Make(int64_t threads)
{
    SwarmResCapRecord record;
    if (threads >= kSwarmResCapMinThreads && threads <= kSwarmResCapThreadCap) {
        record.m_threads = threads;
    } else {
        record.m_threads = kSwarmResCapUnset;
    }
    record.m_raised = kSwarmResCapRaised;
    record.m_bytes_moved = kSwarmResCapBytesMoved;
    record.m_gpu = kSwarmResCapGpu;
    record.m_launched = kSwarmResCapLaunched;
    return record;
}

bool SwarmResCapRecordUsable(const SwarmResCapRecord& record)
{
    return record.threads() >= kSwarmResCapMinThreads &&
           record.threads() <= kSwarmResCapThreadCap &&
           record.raised() == kSwarmResCapRaised &&
           record.bytes_moved() == kSwarmResCapBytesMoved &&
           record.gpu() == kSwarmResCapGpu &&
           record.launched() == kSwarmResCapLaunched;
}

} // namespace modelnet
