// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnosolver.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoSolverResult SwarmNoteNotNoSolver(const SwarmNotNoSolver& note, std::string& err)
{
    SwarmNotNoSolverResult result;
    result.moved = false;
    result.fitness = 0;
    // An unsolved challenge moves no fitness.
    if (note.challenge_id.empty()) {
        result.code = "CHALLENGE";
        result.moved = false;
        result.fitness = 0;
        err = "CHALLENGE";
        return result;
    }
    if (!note.solvable) {
        result.code = "UNSOLVED";
        result.moved = false;
        result.fitness = 0;
        err = "UNSOLVED";
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
