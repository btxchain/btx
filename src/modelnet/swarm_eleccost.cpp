// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_eleccost.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmElecCostResult SwarmNoteElecCost(const SwarmElecCost& meter, std::string& err)
{
    SwarmElecCostResult result;
    result.charged = false;
    result.atoms = 0;
    // An unmeasured electricity cost charges nothing.
    if (meter.meter_id.empty()) {
        result.code = "METER";
        result.charged = false;
        result.atoms = 0;
        err = "METER";
        return result;
    }
    if (!meter.measured) {
        result.code = "HELD";
        result.charged = false;
        result.atoms = 0;
        err = "HELD";
        return result;
    }
    if (meter.want_charge) {
        result.code = "HELD";
        result.charged = false;
        result.atoms = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.charged = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
