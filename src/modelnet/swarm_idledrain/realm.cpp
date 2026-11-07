// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_idledrain/realm.h>

#include <modelnet/swarm_idledrain/limits.h>

namespace modelnet {

int64_t SwarmIdleDrainRealm::bytes_moved() const
{
    return kSwarmIdleDrainBytesMoved;
}

bool SwarmIdleDrainRealm::gpu() const
{
    return kSwarmIdleDrainGpu;
}

bool SwarmIdleDrainRealm::launched() const
{
    return kSwarmIdleDrainLaunched;
}

} // namespace modelnet
