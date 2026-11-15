// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoholdrot2.h>

#include <string>

namespace modelnet {

SwarmNotNoHoldRot2Result SwarmNoteNotNoHoldRot2(const SwarmNotNoHoldRot2& note, std::string& err)
{
    SwarmNotNoHoldRot2Result result;
    result.rotated = false;
    // A fixed holdout is not rotating.
    if (note.holdout_id.empty()) {
        result.code = "HOLDOUT";
        result.rotated = false;
        err = "HOLDOUT";
        return result;
    }
    if (note.fixed_set) {
        result.code = "NOT_ROTATING";
        result.rotated = false;
        err = "NOT_ROTATING";
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
