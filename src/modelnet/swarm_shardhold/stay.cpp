// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_shardhold/stay.h>

#include <modelnet/swarm_shardhold/codes.h>
#include <modelnet/swarm_shardhold/limits.h>

namespace modelnet {

std::string SwarmShardHoldStay::refusal() const
{
    return std::string{kSwarmShardHoldHeld};
}

bool SwarmShardHoldStay::sharded() const
{
    return kSwarmShardHoldSharded;
}

bool SwarmShardHoldStay::running() const
{
    return kSwarmShardHoldRunning;
}

} // namespace modelnet
