// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_dupreceipt/quiet.h>

#include <modelnet/swarm_dupreceipt/limits.h>

namespace modelnet {

bool SwarmDupQuiet::broadcast() const
{
    return kSwarmDupBroadcast;
}

bool SwarmDupQuiet::mined() const
{
    return kSwarmDupMined;
}

int64_t SwarmDupQuiet::bytes_moved() const
{
    return kSwarmDupBytesMoved;
}

std::string SwarmDupQuiet::automatic_spend() const
{
    return std::string{kSwarmDupAutomaticSpend};
}

} // namespace modelnet
