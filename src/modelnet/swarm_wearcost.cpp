// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_wearcost.h>

namespace modelnet {

SwarmWearCostResult SwarmNoteWearCost(const SwarmWearCost& meter, std::string& err)
{
    // An unmeasured wear cost charges nothing.
    if (meter.meter_id.empty()) {
        err = "METER";
        return SwarmWearCostResult{"METER", false, 0};
    }
    if (!meter.measured) {
        err = "HELD";
        return SwarmWearCostResult{"HELD", false, 0};
    }
    if (meter.want_charge) {
        err = "HELD";
        return SwarmWearCostResult{"HELD", false, 0};
    }
    err.clear();
    return SwarmWearCostResult{"NOTED", false, 0};
}

} // namespace modelnet
