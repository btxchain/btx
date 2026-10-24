// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notfitness.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotFitnessResult SwarmNoteNotFitness(const SwarmNotFitness& note, std::string& err)
{
    SwarmNotFitnessResult result;
    result.moved = false;
    result.fitness = 0;
    // A challenge does not move fitness until it is informative, solvable,
    // and independently validated.
    if (note.challenge_id.empty()) {
        result.code = "CHALLENGE";
        result.moved = false;
        result.fitness = 0;
        err = "CHALLENGE";
        return result;
    }
    if (!note.informative || !note.solvable || !note.validated) {
        result.code = "HELD";
        result.moved = false;
        result.fitness = 0;
        err = "HELD";
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
