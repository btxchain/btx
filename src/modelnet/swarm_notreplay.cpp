// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notreplay.h>

namespace modelnet {

SwarmNotReplayResult SwarmNoteNotReplay(const SwarmNotReplay& note, std::string& err)
{
    SwarmNotReplayResult result;
    result.admitted = false;
    if (note.candidate_id.empty()) {
        result.code = "REPLAY";
        result.admitted = false;
        err = "REPLAY";
        return result;
    }
    // Quality graduation is not ExactReplay admission. Do not mine.
    if (note.want_exact_replay) {
        result.code = "NOT_REPLAY";
        result.admitted = false;
        err = "NOT_REPLAY";
        return result;
    }
    if (note.quality_passed) {
        result.code = "HELD";
        result.admitted = false;
        err.clear();
        return result;
    }
    result.code = "NOTED";
    result.admitted = false;
    err.clear();
    return result;
}

} // namespace modelnet
