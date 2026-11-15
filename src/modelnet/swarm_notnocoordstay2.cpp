// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocoordstay2.h>

namespace modelnet {

SwarmNotNoCoordStay2Result SwarmNoteNotNoCoordStay2(const SwarmNotNoCoordStay2& note, std::string& err)
{
    // Earned rows stay when the coordinator is gone.
    SwarmNotNoCoordStay2Result result;
    result.dropped = false;
    if (note.row_id.empty()) {
        result.code = "ROW";
        result.dropped = false;
        err = "ROW";
        return result;
    }
    if (note.coordinator_gone) {
        result.code = "STAYS";
        result.dropped = false;
        err = "STAYS";
        return result;
    }
    if (note.want_drop) {
        result.code = "HELD";
        result.dropped = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.dropped = false;
    err.clear();
    return result;
}

} // namespace modelnet
