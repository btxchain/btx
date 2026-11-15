// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_CHALGATE_H
#define BTX_MODELNET_SWARM_CHALGATE_H

#include <string>

namespace modelnet {

/**
 * A local note about one challenge. challenge_id names the challenge.
 * informative, solvable, and independently_validated record whether the
 * challenge is ready to be considered. want_fitness asks this note to
 * move fitness.
 *
 * A challenge does not move fitness until it is informative, solvable,
 * and independently validated, and this note still does not move
 * fitness. fitness_moved stays false on every path. No hostnames or IPs
 * are used.
 */
struct SwarmChallengeGate {
    std::string challenge_id;
    bool informative{false};
    bool solvable{false};
    bool independently_validated{false};
    bool want_fitness{false};
};

/**
 * Outcome of noting a challenge. fitness_moved stays false on every
 * path: this note does not move fitness.
 */
struct SwarmChallengeGateResult {
    bool fitness_moved{false};
    std::string code;
};

/**
 * Note a challenge without moving fitness.
 * Order, first match wins: an empty challenge_id is CHALLENGE.
 * A challenge that is not informative, not solvable, or not
 * independently validated is UNREADY, including when want_fitness is
 * true. want_fitness is HELD and err is cleared. Otherwise the note is
 * NOTED and err is cleared.
 * fitness_moved stays false on every path. A challenge does not move
 * fitness until it is informative, solvable, and independently
 * validated, and this note still does not move fitness.
 */
SwarmChallengeGateResult SwarmNoteChallengeGate(const SwarmChallengeGate& gate, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_CHALGATE_H
