// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cycleparent.h>

namespace modelnet {

// A qualified candidate can be recorded as the next parent. An unqualified candidate leaves the parent in place. This record does not train.
SwarmCycleParentResult SwarmAdvanceParent(const SwarmCycleParent& cycle, std::string& err)
{
    SwarmCycleParentResult result;
    result.advanced = false;

    if (cycle.parent_id.empty()) {
        result.code = "PARENT";
        err = "PARENT";
        result.advanced = false;
        result.parent_id.clear();
        return result;
    }
    if (cycle.candidate_id.empty()) {
        result.code = "CANDIDATE";
        err = "CANDIDATE";
        result.advanced = false;
        result.parent_id = cycle.parent_id;
        return result;
    }
    if (!cycle.qualified) {
        result.code = "UNQUALIFIED";
        err = "UNQUALIFIED";
        result.advanced = false;
        result.parent_id = cycle.parent_id;
        return result;
    }
    if (cycle.want_advance) {
        result.code = "HELD";
        err = "HELD";
        result.advanced = false;
        result.parent_id = cycle.parent_id;
        return result;
    }

    result.code = "NOTED";
    err.clear();
    result.advanced = true;
    result.parent_id = cycle.candidate_id;
    return result;
}

} // namespace modelnet
