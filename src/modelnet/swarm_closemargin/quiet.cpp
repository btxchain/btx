// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_closemargin/quiet.h>

#include <modelnet/swarm_closemargin/limits.h>

#include <cstdint>

namespace modelnet {

int64_t SwarmCloseMarginHoldQuiet::bytes_moved() const
{
    return kSwarmCloseMarginHoldBytesMoved;
}

bool SwarmCloseMarginHoldQuiet::gpu() const
{
    return kSwarmCloseMarginHoldGpu;
}

bool SwarmCloseMarginHoldQuiet::launched() const
{
    return kSwarmCloseMarginHoldLaunched;
}

bool SwarmCloseMarginHoldQuiet::mined() const
{
    return kSwarmCloseMarginHoldMined;
}

} // namespace modelnet
