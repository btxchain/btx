// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_elechold/under.h>

#include <modelnet/swarm_elechold/codes.h>
#include <modelnet/swarm_elechold/watthour.h>

namespace modelnet {

bool SwarmElecHoldUnder::accept(int64_t watt_hours, std::string& err) const
{
    if (SwarmElecHoldBelowOne(watt_hours)) {
        err = kSwarmElecHoldMeasure;
        return false;
    }
    return true;
}

} // namespace modelnet
