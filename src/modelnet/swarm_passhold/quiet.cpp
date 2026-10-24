// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_passhold/quiet.h>

#include <modelnet/swarm_passhold/limits.h>

namespace modelnet {

int64_t SwarmPassHoldQuiet::bytes_moved() const
{
    return kSwarmPassHoldBytesMoved;
}

bool SwarmPassHoldQuiet::gpu() const
{
    return kSwarmPassHoldGpu;
}

bool SwarmPassHoldQuiet::launched() const
{
    return kSwarmPassHoldLaunched;
}

} // namespace modelnet
