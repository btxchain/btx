// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_meter0.h>

#include <cstdint>

namespace modelnet {

SwarmMeter0Result SwarmNoteMeter0(const SwarmMeter0& note, std::string& err)
{
    SwarmMeter0Result result;
    result.electricity_atoms = 0;
    result.recorded = false;
    if (note.node_id.empty()) {
        result.code = "METER";
        result.electricity_atoms = 0;
        result.recorded = false;
        err = "METER";
        return result;
    }
    // Do not invent electricity, wear, or network meter readings.
    if (note.want_invent) {
        result.code = "INVENTED";
        result.electricity_atoms = 0;
        result.recorded = false;
        err = "INVENTED";
        return result;
    }
    if (!note.measurement_supplied) {
        result.code = "UNMEASURED";
        result.electricity_atoms = 0;
        result.recorded = false;
        err = "UNMEASURED";
        return result;
    }
    result.code = "NOTED";
    result.electricity_atoms = 0;
    result.recorded = false;
    err.clear();
    return result;
}

} // namespace modelnet
