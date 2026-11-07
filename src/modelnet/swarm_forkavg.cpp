// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_forkavg.h>

namespace modelnet {

// Incompatible branches are not averaged.
SwarmForkAvgResult SwarmNoteForkAverage(const SwarmForkAvg& branch, std::string& err)
{
    SwarmForkAvgResult out;
    out.averaged = false;
    out.bytes_moved = 0;
    if (branch.branch_id.empty()) {
        out.code = "BRANCH";
        err = "BRANCH";
        return out;
    }
    if (!branch.compatible) {
        out.code = "NOT_AVERAGED";
        err = "NOT_AVERAGED";
        return out;
    }
    if (branch.want_average) {
        out.code = "HELD";
        err = "HELD";
        return out;
    }
    out.code = "NOTED";
    err.clear();
    return out;
}

} // namespace modelnet
