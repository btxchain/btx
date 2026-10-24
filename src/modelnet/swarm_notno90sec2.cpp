// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notno90sec2.h>

namespace modelnet {

SwarmNotNo90Sec2Result SwarmNoteNotNo90Sec2(const SwarmNotNo90Sec2& note, std::string& err)
{
    SwarmNotNo90Sec2Result result;
    result.guaranteed = false;
    // A 90-second block spacing is not a wall-clock guarantee.
    if (note.block_id.empty()) {
        result.code = "BLOCK";
        result.guaranteed = false;
        err = "BLOCK";
        return result;
    }
    if (note.wall_clock) {
        result.code = "NOT_GUARANTEED";
        result.guaranteed = false;
        err = "NOT_GUARANTEED";
        return result;
    }
    if (note.want_guarantee) {
        result.code = "HELD";
        result.guaranteed = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.guaranteed = false;
    err.clear();
    return result;
}

} // namespace modelnet
