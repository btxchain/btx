// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoinform.h>

#include <string>

namespace modelnet {

SwarmNotNoInformResult SwarmNoteNotNoInform(const SwarmNotNoInform& note, std::string& err)
{
    SwarmNotNoInformResult result;
    result.moved = false;
    result.fitness_changed = false;
    // A challenge does not move fitness until it is informative, solvable,
    // and independently validated. This note moves nothing.
    if (note.challenge_id.empty()) {
        result.code = "CHALLENGE";
        result.moved = false;
        result.fitness_changed = false;
        err = "CHALLENGE";
        return result;
    }
    if (!note.informative || !note.solvable || !note.validated) {
        result.code = "HELD";
        result.moved = false;
        result.fitness_changed = false;
        err = "HELD";
        return result;
    }
    if (note.want_move) {
        result.code = "HELD";
        result.moved = false;
        result.fitness_changed = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.moved = false;
    result.fitness_changed = false;
    err.clear();
    return result;
}

} // namespace modelnet
