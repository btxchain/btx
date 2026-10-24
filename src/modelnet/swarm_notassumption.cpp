// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notassumption.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotAssumptionResult SwarmNoteNotAssumption(const SwarmNotAssumption& note, std::string& err)
{
    SwarmNotAssumptionResult result;
    result.measured = false;
    result.assumed_bytes = 0;
    // An 8000-byte close size is an assumption and is not a measurement.
    if (note.close_id.empty()) {
        result.code = "CLOSE";
        result.measured = false;
        result.assumed_bytes = 0;
        err = "CLOSE";
        return result;
    }
    if (note.want_measure) {
        result.code = "MEASURE_REFUSED";
        result.measured = false;
        result.assumed_bytes = 0;
        err = "MEASURE_REFUSED";
        return result;
    }
    result.code = "NOTED";
    result.measured = false;
    result.assumed_bytes = 0;
    err.clear();
    return result;
}

} // namespace modelnet
