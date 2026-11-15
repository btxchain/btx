// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_holdrot/quiet.h>

#include <modelnet/swarm_holdrot/limits.h>

namespace modelnet {

int64_t SwarmHoldoutRotateQuiet::bytes_moved() const
{
    return kSwarmHoldoutRotateBytesMoved;
}

bool SwarmHoldoutRotateQuiet::gpu() const
{
    return kSwarmHoldoutRotateGpu;
}

bool SwarmHoldoutRotateQuiet::launched() const
{
    return kSwarmHoldoutRotateLaunched;
}

} // namespace modelnet
