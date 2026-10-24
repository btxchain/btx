// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_idledrain/workers.h>

#include <modelnet/swarm_idledrain/limits.h>

namespace modelnet {

void SwarmIdleDrainWorkers::start()
{
    m_count = kSwarmIdleDrainOpenWorkers;
}

void SwarmIdleDrainWorkers::increment()
{
    if (m_count >= kSwarmIdleDrainWorkerCap) return;
    ++m_count;
}

void SwarmIdleDrainWorkers::zero()
{
    m_count = kSwarmIdleDrainZeroWorkers;
}

} // namespace modelnet
