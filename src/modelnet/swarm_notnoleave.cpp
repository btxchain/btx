// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoleave.h>

#include <string>

namespace modelnet {

SwarmNotNoLeaveResult SwarmNoteNotNoLeave(const SwarmNotNoLeave& note, std::string& err)
{
    SwarmNotNoLeaveResult result;
    result.kept = false;
    result.admitted = false;
    // An unqualified candidate leaves the parent.
    if (note.candidate_id.empty()) {
        result.code = "CANDIDATE";
        result.kept = false;
        result.admitted = false;
        err = "CANDIDATE";
        return result;
    }
    if (note.unqualified) {
        result.code = "LEFT";
        result.kept = false;
        result.admitted = false;
        err = "LEFT";
        return result;
    }
    if (note.want_keep) {
        result.code = "HELD";
        result.kept = false;
        result.admitted = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.kept = false;
    result.admitted = false;
    err.clear();
    return result;
}

} // namespace modelnet
