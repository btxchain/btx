// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cursorfence/quiet.h>

#include <modelnet/swarm_cursorfence/limits.h>

namespace modelnet {

int64_t SwarmCursorFenceQuiet::bytes_moved() const
{
    return kSwarmCursorFenceBytesMoved;
}

bool SwarmCursorFenceQuiet::mined() const
{
    return kSwarmCursorFenceMined;
}

int64_t SwarmCursorFenceQuiet::blocks() const
{
    return kSwarmCursorFenceBlocks;
}

} // namespace modelnet
