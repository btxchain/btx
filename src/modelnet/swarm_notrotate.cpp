// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notrotate.h>

#include <string>

namespace modelnet {

SwarmNotRotateResult SwarmNoteNotRotate(const SwarmNotRotate& note, std::string& err)
{
    SwarmNotRotateResult result;
    result.rotated = false;
    result.leaked = false;
    if (note.suite_id.empty()) {
        result.code = "SUITE";
        result.rotated = false;
        result.leaked = false;
        err = "SUITE";
        return result;
    }
    // This note does not rotate a holdout or reveal it.
    if (note.want_rotate) {
        result.code = "NOT_ROTATED";
        result.rotated = false;
        result.leaked = false;
        err = "NOT_ROTATED";
        return result;
    }
    result.code = "NOTED";
    result.rotated = false;
    result.leaked = false;
    err.clear();
    return result;
}

} // namespace modelnet
