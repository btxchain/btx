// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoconflict.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoConflictResult SwarmNoteNotNoConflict(const SwarmNotNoConflict& note, std::string& err)
{
    SwarmNotNoConflictResult result;
    result.settled = false;
    result.atoms = 0;
    // Conflicting evaluators settle nothing.
    if (note.report_id.empty()) {
        result.code = "REPORT";
        result.settled = false;
        result.atoms = 0;
        err = "REPORT";
        return result;
    }
    if (note.conflicting) {
        result.code = "CONFLICT";
        result.settled = false;
        result.atoms = 0;
        err = "CONFLICT";
        return result;
    }
    if (note.want_settle) {
        result.code = "HELD";
        result.settled = false;
        result.atoms = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.settled = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
