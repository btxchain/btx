// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_synchold/quiet.h>

#include <modelnet/swarm_synchold/limits.h>

namespace modelnet {

int64_t SwarmSyncHoldQuiet::bytes_moved() const
{
    return kSwarmSyncHoldBytesMoved;
}

bool SwarmSyncHoldQuiet::gpu() const
{
    return kSwarmSyncHoldGpu;
}

bool SwarmSyncHoldQuiet::launched() const
{
    return kSwarmSyncHoldLaunched;
}

} // namespace modelnet
