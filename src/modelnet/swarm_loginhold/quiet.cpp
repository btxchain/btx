// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_loginhold/quiet.h>

#include <modelnet/swarm_loginhold/limits.h>

namespace modelnet {

int64_t SwarmLoginHoldQuiet::bytes_moved() const
{
    return kSwarmLoginHoldBytesMoved;
}

bool SwarmLoginHoldQuiet::gpu() const
{
    return kSwarmLoginHoldGpu;
}

bool SwarmLoginHoldQuiet::launched() const
{
    return kSwarmLoginHoldLaunched;
}

} // namespace modelnet
