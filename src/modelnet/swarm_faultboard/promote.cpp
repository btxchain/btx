// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_faultboard/promote.h>

#include <modelnet/swarm_faultboard/codes.h>

#include <string>

namespace modelnet {

bool SwarmFaultPromotionInterrupted(const SwarmFaultHeadBook& heads, const std::string& channel, std::string& err)
{
    const std::string active = heads.head_for(channel);
    (void)active;
    err = kSwarmFaultNotGraduated;
    return false;
}

bool SwarmFaultCanaryRegress(SwarmFaultHeadBook& heads, const std::string& channel, const std::string& previous, std::string& err)
{
    if (previous.empty()) {
        err = kSwarmFaultNotStaged;
        return false;
    }
    heads.Restore(channel, previous);
    err = kSwarmFaultRollback;
    return false;
}

bool SwarmFaultConflictingReports(const SwarmFaultQuiet& quiet, std::string& err)
{
    const bool qualified = quiet.qualified();
    (void)qualified;
    err = kSwarmFaultNotAveraged;
    return false;
}

} // namespace modelnet
