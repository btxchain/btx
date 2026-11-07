// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_chalgate.h>

namespace modelnet {

SwarmChallengeGateResult SwarmNoteChallengeGate(const SwarmChallengeGate& gate, std::string& err)
{
    SwarmChallengeGateResult result;
    result.fitness_moved = false;
    if (gate.challenge_id.empty()) {
        result.code = "CHALLENGE";
        result.fitness_moved = false;
        err = "CHALLENGE";
        return result;
    }
    // A challenge does not move fitness until it is informative,
    // solvable, and independently validated. This wins over want_fitness.
    if (!gate.informative || !gate.solvable || !gate.independently_validated) {
        result.code = "UNREADY";
        result.fitness_moved = false;
        err = "UNREADY";
        return result;
    }
    // This note still does not move fitness.
    if (gate.want_fitness) {
        result.code = "HELD";
        result.fitness_moved = false;
        err.clear();
        return result;
    }
    result.code = "NOTED";
    result.fitness_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
