// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notno90blk2.h>

namespace modelnet {

SwarmNotNo90Blk2Result SwarmNoteNotNo90Blk2(const SwarmNotNo90Blk2& note, std::string& err)
{
    SwarmNotNo90Blk2Result result;
    result.guaranteed = false;
    // A 90-second block spacing is not a wall-clock guarantee.
    if (note.clock_id.empty()) {
        result.code = "CLOCK";
        result.guaranteed = false;
        err = "CLOCK";
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
