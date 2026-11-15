// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofitness2.h>

#include <string>

namespace modelnet {

SwarmNotNoFitness2Result SwarmNoteNotNoFitness2(const SwarmNotNoFitness2& note, std::string& err)
{
    SwarmNotNoFitness2Result result;
    result.moved = false;
    // A challenge does not move fitness until it is informative, solvable,
    // and independently validated, and this note still moves nothing.
    if (note.challenge_id.empty()) {
        result.code = "CHALLENGE";
        result.moved = false;
        err = "CHALLENGE";
        return result;
    }
    if (!note.informative || !note.solvable || !note.validated) {
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
