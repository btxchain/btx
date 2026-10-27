// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoqualgrad2.h>

namespace modelnet {

SwarmNotNoQualGrad2Result SwarmNoteNotNoQualGrad2(const SwarmNotNoQualGrad2& note, std::string& err)
{
    SwarmNotNoQualGrad2Result result;
    result.promoted = false;
    if (note.grade_id.empty()) {
        result.code = "GRADE";
        result.promoted = false;
        err = "GRADE";
        return result;
    }
    // A quality graduation is not a realm promotion.
    if (note.quality) {
        result.code = "NOT_PROMOTED";
        result.promoted = false;
        err = "NOT_PROMOTED";
        return result;
    }
    if (note.want_promote) {
        result.code = "HELD";
        result.promoted = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.promoted = false;
    err.clear();
    return result;
}

} // namespace modelnet
