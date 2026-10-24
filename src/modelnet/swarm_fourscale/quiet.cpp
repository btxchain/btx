// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fourscale/quiet.h>

#include <modelnet/swarm_fourscale/limits.h>

namespace modelnet {

int64_t SwarmFourScaleQuiet::bytes_moved() const
{
    return kSwarmFourScaleBytesMoved;
}

bool SwarmFourScaleQuiet::gpu() const
{
    return kSwarmFourScaleGpu;
}

} // namespace modelnet
