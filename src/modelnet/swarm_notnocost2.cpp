// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocost2.h>

namespace modelnet {

SwarmNotNoCost2Result SwarmNoteNotNoCost2(const SwarmNotNoCost2& note, std::string& err)
{
    // An unmeasured electricity or wear cost charges nothing.
    SwarmNotNoCost2Result result;
    result.charged = false;
    result.atoms = 0;
    if (note.cost_id.empty()) {
        result.code = "COST";
        result.charged = false;
        result.atoms = 0;
        err = "COST";
        return result;
    }
    if (!note.measured) {
        result.code = "NOT_CHARGED";
        result.charged = false;
        result.atoms = 0;
        err = "NOT_CHARGED";
        return result;
    }
    if (note.want_charge) {
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
