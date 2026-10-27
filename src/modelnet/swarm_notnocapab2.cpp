// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocapab2.h>

namespace modelnet {

SwarmNotNoCapab2Result SwarmNoteNotNoCapab2(const SwarmNotNoCapab2& note, std::string& err)
{
    // An uncovered capability acts on nothing.
    SwarmNotNoCapab2Result result;
    result.acted = false;
    if (note.cap_id.empty()) {
        result.code = "CAP";
        result.acted = false;
        err = "CAP";
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
