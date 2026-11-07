// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_gradhold/quiet.h>

#include <modelnet/swarm_gradhold/limits.h>

namespace modelnet {

int64_t SwarmGradHoldQuiet::bytes_moved() const
{
    return kSwarmGradHoldBytesMoved;
}

bool SwarmGradHoldQuiet::gpu() const
{
    return kSwarmGradHoldGpu;
}

bool SwarmGradHoldQuiet::launched() const
{
    return kSwarmGradHoldLaunched;
}

} // namespace modelnet
