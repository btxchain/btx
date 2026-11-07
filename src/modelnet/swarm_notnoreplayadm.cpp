// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoreplayadm.h>

namespace modelnet {

SwarmNotNoReplayAdmResult SwarmNoteNotNoReplayAdm(const SwarmNotNoReplayAdm& note, std::string& err)
{
    SwarmNotNoReplayAdmResult result;
    result.admitted = false;
    result.mined = false;
    if (note.eval_id.empty()) {
        result.code = "EVAL";
        result.admitted = false;
        result.mined = false;
        err = "EVAL";
        return result;
    }
    // A quality pass is not ExactReplay admission and this note mines nothing.
    if (note.quality_pass) {
        result.code = "NOT_REPLAY";
        result.admitted = false;
        result.mined = false;
        err = "NOT_REPLAY";
        return result;
    }
    if (note.want_admit) {
        result.code = "NOT_REPLAY";
        result.admitted = false;
        result.mined = false;
        err = "NOT_REPLAY";
        return result;
    }
    result.code = "NOTED";
    result.admitted = false;
    result.mined = false;
    err.clear();
    return result;
}

} // namespace modelnet
