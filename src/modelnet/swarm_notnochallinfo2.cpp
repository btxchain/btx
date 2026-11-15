// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnochallinfo2.h>

#include <string>

namespace modelnet {

SwarmNotNoChallInfo2Result SwarmNoteNotNoChallInfo2(const SwarmNotNoChallInfo2& note, std::string& err)
{
    SwarmNotNoChallInfo2Result result;
    result.moved = false;
    // An uninformative challenge does not move fitness.
    if (note.challenge_id.empty()) {
        result.code = "CHALLENGE";
        result.moved = false;
        err = "CHALLENGE";
        return result;
    }
    if (note.uninformative) {
        result.code = "NOT_MOVED";
        result.moved = false;
        err = "NOT_MOVED";
        return result;
    }
    if (note.want_move) {
        result.code = "HELD";
        result.moved = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
