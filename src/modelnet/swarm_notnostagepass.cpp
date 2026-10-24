// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnostagepass.h>

#include <string>

namespace modelnet {

SwarmNotNoStagePassResult SwarmNoteNotNoStagePass(const SwarmNotNoStagePass& note, std::string& err)
{
    SwarmNotNoStagePassResult result;
    result.passed = false;
    result.gpu = false;
    if (note.stage_id.empty()) {
        result.code = "STAGE";
        result.passed = false;
        result.gpu = false;
        err = "STAGE";
        return result;
    }
    // A unit note does not pass a flagship stage.
    if (note.want_pass) {
        result.code = "UNQUALIFIED";
        result.passed = false;
        result.gpu = false;
        err = "UNQUALIFIED";
        return result;
    }
    result.code = "NOTED";
    result.passed = false;
    result.gpu = false;
    err.clear();
    return result;
}

} // namespace modelnet
