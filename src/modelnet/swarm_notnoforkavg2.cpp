// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoforkavg2.h>

#include <string>

namespace modelnet {

SwarmNotNoForkAvg2Result SwarmNoteNotNoForkAvg2(const SwarmNotNoForkAvg2& note, std::string& err)
{
    SwarmNotNoForkAvg2Result result;
    result.averaged = false;
    // Incompatible branches are not averaged.
    if (note.branch_id.empty()) {
        result.code = "BRANCH";
        result.averaged = false;
        err = "BRANCH";
        return result;
    }
    if (note.incompatible) {
        result.code = "NOT_AVERAGED";
        result.averaged = false;
        err = "NOT_AVERAGED";
        return result;
    }
    if (note.want_average) {
        result.code = "HELD";
        result.averaged = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.averaged = false;
    err.clear();
    return result;
}

} // namespace modelnet
