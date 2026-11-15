// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_channelset/policy.h>

#include <modelnet/swarm_channelset/limits.h>
#include <modelnet/swarm_paymesh.h>

namespace modelnet {

std::string ChannelSetAutomaticSpend()
{
    // The scheduler never receives a spend key. This stays the string "0".
    return std::string(SWARM_AUTOMATIC_SPEND_ATOMS);
}

bool ChannelSetBroadcast()
{
    return false;
}

bool ChannelSetMined()
{
    return false;
}

int64_t ChannelSetBytesMoved()
{
    return kChannelSetBytesMoved;
}

bool ChannelSetMultiHopQualified()
{
    return false;
}

} // namespace modelnet
