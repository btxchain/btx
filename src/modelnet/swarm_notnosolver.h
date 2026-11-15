// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSOLVER_H
#define BTX_MODELNET_SWARM_NOTNOSOLVER_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one challenge. solvable records whether the
 * challenge is solvable. want_move asks this note to move fitness.
 *
 * An unsolved challenge moves no fitness. moved stays false and fitness
 * stays 0 on every path.
 */
struct SwarmNotNoSolver {
    std::string challenge_id;
    bool solvable{false};
    bool want_move{false};
};

/**
 * Outcome of noting a challenge. moved stays false and fitness stays 0
 * on every path. An unsolved challenge moves no fitness.
 */
struct SwarmNotNoSolverResult {
    std::string code;
    bool moved{false};
    int64_t fitness{0};
};

/**
 * Note a challenge without moving fitness.
 * Order, first match wins: an empty challenge_id is CHALLENGE. When
 * solvable is false the note is UNSOLVED even when want_move is false.
 * want_move is HELD. Otherwise the note is NOTED and err is cleared.
 * moved stays false and fitness stays 0 on every path. An unsolved
 * challenge moves no fitness.
 */
SwarmNotNoSolverResult SwarmNoteNotNoSolver(const SwarmNotNoSolver& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSOLVER_H
