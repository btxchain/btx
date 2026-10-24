// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_capact/quiet.h>

#include <modelnet/swarm_capact/limits.h>

namespace modelnet {

bool SwarmCapActQuiet::launched() const
{
    return kSwarmCapActLaunched;
}

int64_t SwarmCapActQuiet::bytes_moved() const
{
    return kSwarmCapActBytesMoved;
}

bool SwarmCapActQuiet::gpu() const
{
    return kSwarmCapActGpu;
}

std::string SwarmCapActQuiet::automatic_spend() const
{
    return std::string{kSwarmCapActAutomaticSpend};
}

} // namespace modelnet
