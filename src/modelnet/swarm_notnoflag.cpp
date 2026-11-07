// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoflag.h>

namespace modelnet {

SwarmNotNoFlagResult SwarmNoteNotNoFlag(const SwarmNotNoFlag& note, std::string& err)
{
    SwarmNotNoFlagResult result;
    result.passed = false;
    result.demonstrated = false;
    if (note.stage_id.empty()) {
        result.code = "STAGE";
        result.passed = false;
        result.demonstrated = false;
        err = "STAGE";
        return result;
    }
    // A unit note does not pass a flagship stage.
    if (note.want_pass) {
        result.code = "NOT_PASSED";
        result.passed = false;
        result.demonstrated = false;
        err = "NOT_PASSED";
        return result;
    }
    result.code = "NOTED";
    result.passed = false;
    result.demonstrated = false;
    err.clear();
    return result;
}

} // namespace modelnet
