// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_collatbook/quiet.h>

#include <modelnet/swarm_collatbook/limits.h>

namespace modelnet {

bool SwarmCollatBroadcast()
{
    return kSwarmCollatBroadcast;
}

int64_t SwarmCollatBytesMoved()
{
    return kSwarmCollatBytesMoved;
}

int64_t SwarmCollatEarned()
{
    return kSwarmCollatEarned;
}

} // namespace modelnet
