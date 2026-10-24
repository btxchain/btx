// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_quotefiat/quiet.h>

#include <modelnet/swarm_quotefiat/limits.h>

namespace modelnet {

bool SwarmQuoteFiatQuiet::broadcast() const
{
    return kSwarmQuoteFiatBroadcast;
}

bool SwarmQuoteFiatQuiet::mined() const
{
    return kSwarmQuoteFiatMined;
}

int64_t SwarmQuoteFiatQuiet::bytes_moved() const
{
    return kSwarmQuoteFiatBytesMoved;
}

std::string SwarmQuoteFiatQuiet::automatic_spend() const
{
    return std::string{kSwarmQuoteFiatAutomaticSpend};
}

} // namespace modelnet
