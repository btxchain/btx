// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_faultboard/coordinator.h>

#include <modelnet/swarm_faultboard/codes.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool SwarmFaultCoordinatorGone(const SwarmFaultClaimBook& claims, std::string& err)
{
    if (claims.count() != 0) {
        err = kSwarmFaultDurable;
        return false;
    }
    err = kSwarmFaultLost;
    return false;
}

bool SwarmFaultReplaceCoordinator(SwarmFaultEpoch& epoch, int64_t old_epoch, int64_t new_epoch, std::string& err)
{
    if (!(new_epoch > old_epoch)) {
        err = kSwarmFaultStaleEpoch;
        return false;
    }
    epoch.Assign(new_epoch);
    err.clear();
    return true;
}

bool SwarmFaultResumeStale(int64_t epoch, int64_t current, std::string& err)
{
    if (epoch < current) {
        err = kSwarmFaultStale;
        return false;
    }
    err.clear();
    return true;
}

bool SwarmFaultPermanentGone(const SwarmFaultClaimBook& claims, const SwarmFaultEarnedBook& earned, std::string& err)
{
    if (claims.count() != 0 || earned.count() != 0) {
        err = kSwarmFaultDurable;
        return false;
    }
    err = kSwarmFaultLost;
    return false;
}

} // namespace modelnet
