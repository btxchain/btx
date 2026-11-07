// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocap2.h>

namespace modelnet {

SwarmNotNoCap2Result SwarmNoteNotNoCap2(const SwarmNotNoCap2& note, std::string& err)
{
    // An uncovered capability acts on nothing.
    SwarmNotNoCap2Result result;
    result.acted = false;
    result.bytes_moved = false;
    if (note.cap_id.empty()) {
        result.code = "CAP";
        result.acted = false;
        result.bytes_moved = false;
        err = "CAP";
        return result;
    }
    if (!note.covered) {
        result.code = "NOT_ACTED";
        result.acted = false;
        result.bytes_moved = false;
        err = "NOT_ACTED";
        return result;
    }
    if (note.want_act) {
        result.code = "HELD";
        result.acted = false;
        result.bytes_moved = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.acted = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
