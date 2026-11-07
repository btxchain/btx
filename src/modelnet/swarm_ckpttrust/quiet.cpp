// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_ckpttrust/quiet.h>

#include <modelnet/swarm_ckpttrust/limits.h>

namespace modelnet {

int64_t SwarmCheckpointTrustQuiet::bytes_moved() const
{
    return kSwarmCheckpointTrustBytesMoved;
}

bool SwarmCheckpointTrustQuiet::gpu() const
{
    return kSwarmCheckpointTrustGpu;
}

bool SwarmCheckpointTrustQuiet::launched() const
{
    return kSwarmCheckpointTrustLaunched;
}

} // namespace modelnet
