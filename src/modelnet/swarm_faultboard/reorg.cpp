// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_faultboard/reorg.h>

#include <modelnet/swarm_faultboard/codes.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool SwarmFaultReorg(SwarmFaultReserve& reserve, std::string& err)
{
    reserve.Freeze();
    err = kSwarmFaultFreeze;
    return false;
}

bool SwarmFaultDoubleCollateral(SwarmFaultReserve& reserve, int64_t amount, std::string& err)
{
    if (reserve.has()) {
        err = kSwarmFaultCollateralReuse;
        return false;
    }
    if (amount < 1) {
        err = kSwarmFaultCollateral;
        return false;
    }
    if (!reserve.store(amount)) {
        err = reserve.has() ? kSwarmFaultCollateralReuse : kSwarmFaultCollateral;
        return false;
    }
    err.clear();
    return true;
}

bool SwarmFaultReserveAmount(SwarmFaultReserve& reserve, int64_t amount, std::string& err)
{
    if (reserve.frozen()) {
        err = kSwarmFaultFrozen;
        return false;
    }
    if (reserve.has()) {
        err = kSwarmFaultCollateralReuse;
        return false;
    }
    if (amount < 1) {
        err = kSwarmFaultCollateral;
        return false;
    }
    if (!reserve.store(amount)) {
        err = reserve.has() ? kSwarmFaultCollateralReuse : kSwarmFaultCollateral;
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
