// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_workpay/spend_policy.h>

#include <modelnet/swarm_workpay/codes.h>

namespace modelnet {

bool SwarmWorkAcceptPay(bool research_key, bool scheduler, std::string& err)
{
    if (research_key || scheduler) {
        err = SWARM_WORK_NOT_SIGNED;
        return false;
    }
    err.clear();
    return true;
}

std::string SwarmWorkAutomaticSpend()
{
    // The scheduler never receives a spend key. This stays the string "0".
    return "0";
}

bool SwarmWorkBroadcast()
{
    return false;
}

bool SwarmWorkMined()
{
    return false;
}

int64_t SwarmWorkBytesMoved()
{
    return 0;
}

} // namespace modelnet
