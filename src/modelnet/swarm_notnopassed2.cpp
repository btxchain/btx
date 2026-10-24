// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnopassed2.h>

#include <string>

namespace modelnet {

SwarmNotNoPassed2Result SwarmNoteNotNoPassed2(const SwarmNotNoPassed2& note, std::string& err)
{
    SwarmNotNoPassed2Result result;
    result.passed = false;
    if (note.stage_id.empty()) {
        result.code = "STAGE";
        result.passed = false;
        err = "STAGE";
        return result;
    }
    // A unit note does not pass a flagship stage.
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
