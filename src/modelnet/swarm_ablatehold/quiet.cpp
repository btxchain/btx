// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_ablatehold/quiet.h>

#include <modelnet/swarm_ablatehold/limits.h>

namespace modelnet {

int64_t SwarmAblateHoldQuiet::bytes_moved() const
{
    return kSwarmAblateHoldBytesMoved;
}

bool SwarmAblateHoldQuiet::gpu() const
{
    return kSwarmAblateHoldGpu;
}

bool SwarmAblateHoldQuiet::launched() const
{
    return kSwarmAblateHoldLaunched;
}

} // namespace modelnet
