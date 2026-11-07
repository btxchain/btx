// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoavgweight2.h>

#include <string>

namespace modelnet {

SwarmNotNoAvgWeight2Result SwarmNoteNotNoAvgWeight2(const SwarmNotNoAvgWeight2& note, std::string& err)
{
    SwarmNotNoAvgWeight2Result result;
    result.averaged = false;
    result.bytes_moved = false;
    // Island admission averages no weights.
    if (note.run_id.empty()) {
        result.code = "RUN";
        result.averaged = false;
        result.bytes_moved = false;
        err = "RUN";
        return result;
    }
    if (note.want_average) {
        result.code = "HELD";
        result.averaged = false;
        result.bytes_moved = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.averaged = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
