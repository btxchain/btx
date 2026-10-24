// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_mixedhold/quiet.h>

#include <modelnet/swarm_mixedhold/limits.h>

namespace modelnet {

int64_t SwarmMixedHoldQuiet::bytes_moved() const
{
    return kSwarmMixedHoldBytesMoved;
}

bool SwarmMixedHoldQuiet::gpu() const
{
    return kSwarmMixedHoldGpu;
}

bool SwarmMixedHoldQuiet::launched() const
{
    return kSwarmMixedHoldLaunched;
}

} // namespace modelnet
