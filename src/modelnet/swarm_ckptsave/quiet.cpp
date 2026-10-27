// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_ckptsave/quiet.h>

#include <modelnet/swarm_ckptsave/limits.h>

namespace modelnet {

int64_t SwarmCkptSaveQuiet::bytes_moved() const
{
    return kSwarmCkptSaveBytesMoved;
}

bool SwarmCkptSaveQuiet::gpu() const
{
    return kSwarmCkptSaveGpu;
}

bool SwarmCkptSaveQuiet::launched() const
{
    return kSwarmCkptSaveLaunched;
}

} // namespace modelnet
