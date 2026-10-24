// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoeleccost2.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoElecCost2Result SwarmNoteNotNoElecCost2(const SwarmNotNoElecCost2& note, std::string& err)
{
    SwarmNotNoElecCost2Result result;
    result.charged = false;
    result.atoms = 0;
    // An unmeasured electricity cost charges nothing.
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
