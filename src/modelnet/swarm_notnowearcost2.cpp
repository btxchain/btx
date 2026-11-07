// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnowearcost2.h>

#include <string>

namespace modelnet {

SwarmNotNoWearCost2Result SwarmNoteNotNoWearCost2(const SwarmNotNoWearCost2& note, std::string& err)
{
    SwarmNotNoWearCost2Result result;
    result.charged = false;
    result.atoms = 0;
    // An unmeasured wear cost charges nothing.
    if (note.cost_id.empty()) {
        result.code = "COST";
        result.charged = false;
        result.atoms = 0;
        err = "COST";
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
