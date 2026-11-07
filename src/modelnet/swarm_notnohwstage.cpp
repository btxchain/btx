// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnohwstage.h>

#include <string>

namespace modelnet {

SwarmNotNoHwStageResult SwarmNoteNotNoHwStage(const SwarmNotNoHwStage& note, std::string& err)
{
    // A unit note does not pass a hardware stage.
    SwarmNotNoHwStageResult result;
    result.passed = false;
    result.gpu = false;
    if (note.stage_id.empty()) {
        result.code = "STAGE";
        result.passed = false;
        result.gpu = false;
        err = "STAGE";
        return result;
    }
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
