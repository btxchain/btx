// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCHALLENGE_H
#define BTX_MODELNET_SWARM_NOTNOCHALLENGE_H

#include <string>

namespace modelnet {

/**
 * A local note about one challenge. informative, solvable, and validated
 * record whether the challenge is informative, solvable, and independently
 * validated. want_move asks this note to move fitness.
 *
 * A challenge does not move fitness until it is informative, solvable,
 * and independently validated. This note never moves fitness. moved and
 * fitness_changed stay false on every path.
 */
struct SwarmNotNoChallenge {
    std::string challenge_id;
    bool informative{false};
    bool solvable{false};
    bool validated{false};
    bool want_move{false};
};

/**
 * Outcome of noting a challenge. moved and fitness_changed stay false
 * on every path. This note never moves fitness.
 */
struct SwarmNotNoChallengeResult {
    std::string code;
    bool moved{false};
    bool fitness_changed{false};
};

/**
 * Note a challenge without moving fitness.
 * Order, first match wins: an empty challenge_id is CHALLENGE. When any
 * of informative, solvable, or validated is false the note is HELD even
 * when want_move is false. want_move is HELD. Otherwise the note is NOTED
 * and err is cleared.
 * moved and fitness_changed stay false on every path. A challenge does
 * not move fitness until it is informative, solvable, and independently
 * validated. This note never moves fitness.
 */
SwarmNotNoChallengeResult SwarmNoteNotNoChallenge(const SwarmNotNoChallenge& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCHALLENGE_H
