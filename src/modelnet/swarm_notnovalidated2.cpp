// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnovalidated2.h>

#include <string>

namespace modelnet {

SwarmNotNoValidated2Result SwarmNoteNotNoValidated2(const SwarmNotNoValidated2& note, std::string& err)
{
    SwarmNotNoValidated2Result result;
    result.moved = false;
    // A challenge that is not independently validated does not move fitness.
    if (note.challenge_id.empty()) {
        result.code = "CHALLENGE";
        result.moved = false;
        err = "CHALLENGE";
        return result;
    }
    if (note.unvalidated) {
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
