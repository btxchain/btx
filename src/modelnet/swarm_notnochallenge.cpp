// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnochallenge.h>

#include <string>

namespace modelnet {

SwarmNotNoChallengeResult SwarmNoteNotNoChallenge(const SwarmNotNoChallenge& note, std::string& err)
{
    SwarmNotNoChallengeResult result;
    result.moved = false;
    result.fitness_changed = false;
    // A challenge does not move fitness until it is informative, solvable,
    // and independently validated. This note never moves fitness.
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
