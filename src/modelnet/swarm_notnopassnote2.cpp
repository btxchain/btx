// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnopassnote2.h>

namespace modelnet {

// A unit note does not pass a hardware stage.
SwarmNotNoPassNote2Result SwarmNoteNotNoPassNote2(const SwarmNotNoPassNote2& note, std::string& err)
{
    SwarmNotNoPassNote2Result result;
    if (note.stage_id.empty()) {
        result.code = "STAGE";
        result.passed = false;
        err = "STAGE";
        return result;
    }
    if (note.want_pass) {
        result.code = "HELD";
        result.passed = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.passed = false;
    err.clear();
    return result;
}

} // namespace modelnet
