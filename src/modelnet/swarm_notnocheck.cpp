// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocheck.h>

#include <string>

namespace modelnet {

SwarmNotNoCheckResult SwarmNoteNotNoCheck(const SwarmNotNoCheck& note, std::string& err)
{
    // This note resumes nothing and moves no bytes. An unsaved checkpoint
    // is not resumed.
    SwarmNotNoCheckResult result;
    result.resumed = false;
    result.bytes_moved = false;
    if (note.step_id.empty()) {
        result.code = "STEP";
        result.resumed = false;
        result.bytes_moved = false;
        err = "STEP";
        return result;
    }
    if (!note.saved) {
        result.code = "NO_CHECKPOINT";
        result.resumed = false;
        result.bytes_moved = false;
        err = "NO_CHECKPOINT";
        return result;
    }
    if (note.want_resume) {
        result.code = "NO_CHECKPOINT";
        result.resumed = false;
        result.bytes_moved = false;
        err = "NO_CHECKPOINT";
        return result;
    }
    result.code = "NOTED";
    result.resumed = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
