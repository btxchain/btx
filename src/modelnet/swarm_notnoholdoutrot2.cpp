// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoholdoutrot2.h>

#include <string>

namespace modelnet {

SwarmNotNoHoldoutRot2Result SwarmNoteNotNoHoldoutRot2(const SwarmNotNoHoldoutRot2& note, std::string& err)
{
    SwarmNotNoHoldoutRot2Result result;
    result.rotated = false;
    // A fixed holdout is not rotating.
    if (note.holdout_id.empty()) {
        result.code = "HOLDOUT";
        result.rotated = false;
        err = "HOLDOUT";
        return result;
    }
    if (note.fixed) {
        result.code = "NOT_ROTATED";
        result.rotated = false;
        err = "NOT_ROTATED";
        return result;
    }
    if (note.want_rotate) {
        result.code = "HELD";
        result.rotated = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.rotated = false;
    err.clear();
    return result;
}

} // namespace modelnet
