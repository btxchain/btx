// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_elechold/watthour.h>

#include <modelnet/swarm_elechold/limits.h>

namespace modelnet {

bool SwarmElecHoldBelowOne(int64_t watt_hours)
{
    return watt_hours < kSwarmElecHoldMinWattHour;
}

bool SwarmElecHoldStorable(int64_t watt_hours)
{
    return !SwarmElecHoldBelowOne(watt_hours);
}

} // namespace modelnet
