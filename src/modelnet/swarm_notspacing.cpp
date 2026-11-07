// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notspacing.h>

namespace modelnet {

SwarmNotSpacingResult SwarmNoteNotSpacing(const SwarmNotSpacing& note, std::string& err)
{
    SwarmNotSpacingResult result;
    result.guaranteed = false;
    result.seconds = 0;
    if (note.height_id.empty()) {
        result.code = "HEIGHT";
        result.guaranteed = false;
        result.seconds = 0;
        err = "HEIGHT";
        return result;
    }
    if (note.want_wall_clock) {
        result.code = "NOT_GUARANTEE";
        result.guaranteed = false;
        result.seconds = 0;
        err = "NOT_GUARANTEE";
        return result;
    }
    result.code = "NOTED";
    result.guaranteed = false;
    result.seconds = 0;
    err.clear();
    return result;
}

} // namespace modelnet
