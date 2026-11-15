// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocost.h>

namespace modelnet {

SwarmNotNoCostResult SwarmNoteNotNoCost(const SwarmNotNoCost& note, std::string& err)
{
    // An unmeasured electricity or wear cost charges nothing.
    SwarmNotNoCostResult result;
    result.charged = false;
    result.atoms = 0;
    if (note.run_id.empty()) {
        result.code = "RUN";
        result.charged = false;
        result.atoms = 0;
        err = "RUN";
        return result;
    }
    if (note.unmeasured) {
        result.code = "UNMEASURED";
        result.charged = false;
        result.atoms = 0;
        err = "UNMEASURED";
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
