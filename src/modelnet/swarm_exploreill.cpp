// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_exploreill.h>

#include <string>

namespace modelnet {

SwarmExploreIllResult SwarmNoteExploration(const SwarmExploreIll& run, std::string& err)
{
    SwarmExploreIllResult result;
    // The illustration records 1, 2, and 2 and assigns nothing.
    result.assigned = false;
    result.slots = 0;
    result.illustrated_a = 1;
    result.illustrated_b = 2;
    result.illustrated_c = 2;
    if (run.run_id.empty()) {
        result.code = "RUN";
        result.assigned = false;
        result.slots = 0;
        result.illustrated_a = 1;
        result.illustrated_b = 2;
        result.illustrated_c = 2;
        err = "RUN";
        return result;
    }
    if (run.want_assign) {
        result.code = "HELD";
        result.assigned = false;
        result.slots = 0;
        result.illustrated_a = 1;
        result.illustrated_b = 2;
        result.illustrated_c = 2;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.assigned = false;
    result.slots = 0;
    result.illustrated_a = 1;
    result.illustrated_b = 2;
    result.illustrated_c = 2;
    err.clear();
    return result;
}

} // namespace modelnet
