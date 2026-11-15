// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoearned.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoEarnedResult SwarmNoteNotNoEarned(const SwarmNotNoEarned& note, std::string& err)
{
    SwarmNotNoEarnedResult result;
    result.dropped = false;
    result.atoms = 0;
    // Earned rows stay when the coordinator is gone and nothing is paid
    // or dropped.
    if (note.row_id.empty()) {
        result.code = "ROW";
        result.dropped = false;
        result.atoms = 0;
        err = "ROW";
        return result;
    }
    if (note.coordinator_gone) {
        result.code = "KEPT";
        result.dropped = false;
        result.atoms = 0;
        err = "KEPT";
        return result;
    }
    if (note.want_drop) {
        result.code = "KEPT";
        result.dropped = false;
        result.atoms = 0;
        err = "KEPT";
        return result;
    }
    result.code = "NOTED";
    result.dropped = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
