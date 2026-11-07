// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_shardhold/quiet.h>

#include <modelnet/swarm_shardhold/limits.h>

namespace modelnet {

int64_t SwarmShardHoldQuiet::bytes_moved() const
{
    return kSwarmShardHoldBytesMoved;
}

bool SwarmShardHoldQuiet::gpu() const
{
    return kSwarmShardHoldGpu;
}

bool SwarmShardHoldQuiet::launched() const
{
    return kSwarmShardHoldLaunched;
}

} // namespace modelnet
