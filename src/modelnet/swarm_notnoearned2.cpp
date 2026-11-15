// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoearned2.h>

namespace modelnet {

SwarmNotNoEarned2Result SwarmNoteNotNoEarned2(const SwarmNotNoEarned2& note, std::string& err)
{
    // Earned rows stay when the coordinator is gone.
    SwarmNotNoEarned2Result result;
    result.dropped = false;
    result.atoms = 0;
    if (note.row_id.empty()) {
        result.code = "ROW";
        result.dropped = false;
        result.atoms = 0;
        err = "ROW";
        return result;
    }
    if (note.coordinator_gone) {
        result.code = "STAYS";
        result.dropped = false;
        result.atoms = 0;
        err = "STAYS";
        return result;
    }
    if (note.want_drop) {
        result.code = "HELD";
        result.dropped = false;
        result.atoms = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.dropped = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
