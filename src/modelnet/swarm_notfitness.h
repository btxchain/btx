// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTFITNESS_H
#define BTX_MODELNET_SWARM_NOTFITNESS_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one challenge. informative, solvable, and validated
 * record whether the challenge is informative, solvable, and independently
 * validated. want_move asks this note to move fitness.
 *
 * A challenge does not move fitness until it is informative, solvable,
 * and independently validated. moved stays false and fitness stays 0 on
 * every path.
 */
struct SwarmNotFitness {
    std::string challenge_id;
    bool informative{false};
    bool solvable{false};
    bool validated{false};
    bool want_move{false};
};

/**
 * Outcome of noting a challenge. moved stays false and fitness stays 0
 * on every path.
 */
struct SwarmNotFitnessResult {
    std::string code;
    bool moved{false};
    int64_t fitness{0};
};

/**
 * Note a challenge without moving fitness.
 * Order, first match wins: an empty challenge_id is CHALLENGE. When
 * informative, solvable, and validated are not all true the note is HELD
 * even when want_move is false. want_move is HELD. Otherwise the note is
 * NOTED and err is clear.
 * moved stays false and fitness stays 0 on every path. A challenge does
 * not move fitness until it is informative, solvable, and independently
 * validated.
 */
SwarmNotFitnessResult SwarmNoteNotFitness(const SwarmNotFitness& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTFITNESS_H
