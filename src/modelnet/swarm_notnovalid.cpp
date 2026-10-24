// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnovalid.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoValidResult SwarmNoteNotNoValid(const SwarmNotNoValid& note, std::string& err)
{
    SwarmNotNoValidResult result;
    result.moved = false;
    result.fitness = 0;
    // A challenge that is not independently validated moves no fitness.
    if (note.challenge_id.empty()) {
        result.code = "CHALLENGE";
        result.moved = false;
        result.fitness = 0;
        err = "CHALLENGE";
        return result;
    }
    if (!note.validated) {
        result.code = "NOT_VALIDATED";
        result.moved = false;
        result.fitness = 0;
        err = "NOT_VALIDATED";
        return result;
    }
    if (note.want_move) {
        result.code = "HELD";
        result.moved = false;
        result.fitness = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.moved = false;
    result.fitness = 0;
    err.clear();
    return result;
}

} // namespace modelnet
