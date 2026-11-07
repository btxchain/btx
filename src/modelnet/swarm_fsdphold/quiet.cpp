// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fsdphold/quiet.h>

#include <modelnet/swarm_fsdphold/limits.h>

namespace modelnet {

int64_t SwarmFsdpHoldQuiet::bytes_moved() const
{
    return kSwarmFsdpHoldBytesMoved;
}

bool SwarmFsdpHoldQuiet::gpu() const
{
    return kSwarmFsdpHoldGpu;
}

bool SwarmFsdpHoldQuiet::launched() const
{
    return kSwarmFsdpHoldLaunched;
}

} // namespace modelnet
