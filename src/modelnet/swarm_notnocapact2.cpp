// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocapact2.h>

namespace modelnet {

SwarmNotNoCapAct2Result SwarmNoteNotNoCapAct2(const SwarmNotNoCapAct2& note, std::string& err)
{
    // An uncovered capability acts on nothing.
    SwarmNotNoCapAct2Result result;
    result.acted = false;
    if (note.capability_id.empty()) {
        result.code = "CAPABILITY";
        result.acted = false;
        err = "CAPABILITY";
        return result;
    }
    if (note.uncovered) {
        result.code = "NOT_ACTED";
        result.acted = false;
        err = "NOT_ACTED";
        return result;
    }
    if (note.want_act) {
        result.code = "HELD";
        result.acted = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.acted = false;
    err.clear();
    return result;
}

} // namespace modelnet
