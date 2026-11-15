// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoholdout2.h>

#include <string>

namespace modelnet {

SwarmNotNoHoldout2Result SwarmNoteNotNoHoldout2(const SwarmNotNoHoldout2& note, std::string& err)
{
    SwarmNotNoHoldout2Result result;
    result.rotated = false;
    result.published = false;
    // A fixed holdout is not a rotating holdout.
    if (note.split_id.empty()) {
        result.code = "SPLIT";
        result.rotated = false;
        result.published = false;
        err = "SPLIT";
        return result;
    }
    if (note.fixed) {
        result.code = "NOT_ROTATING";
        result.rotated = false;
        result.published = false;
        err = "NOT_ROTATING";
        return result;
    }
    if (note.want_rotate) {
        result.code = "HELD";
        result.rotated = false;
        result.published = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.rotated = false;
    result.published = false;
    err.clear();
    return result;
}

} // namespace modelnet
