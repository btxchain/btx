// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_paystage/spend_policy.h>

namespace modelnet {

bool SwarmPayAcceptSpend(bool research_key, bool scheduler, std::string& err)
{
    if (research_key || scheduler) {
        err = "NOT_SIGNED";
        return false;
    }
    err.clear();
    return true;
}

std::string SwarmPayAutomaticSpend()
{
    // The scheduler never receives a spend key. This stays the string "0".
    return "0";
}

bool SwarmPayBroadcast()
{
    return false;
}

bool SwarmPayMined()
{
    return false;
}

} // namespace modelnet
