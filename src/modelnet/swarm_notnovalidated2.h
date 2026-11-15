// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOVALIDATED2_H
#define BTX_MODELNET_SWARM_NOTNOVALIDATED2_H

#include <string>

namespace modelnet {

/**
 * A local note about one challenge. unvalidated means the challenge is not
 * independently validated. want_move asks this note to move fitness.
 *
 * A challenge that is not independently validated does not move fitness.
 * moved stays false on every path.
 */
struct SwarmNotNoValidated2 {
    std::string challenge_id;
    bool unvalidated{false};
    bool want_move{false};
};

/**
 * Outcome of noting a challenge. moved stays false on every path.
 * A challenge that is not independently validated does not move fitness.
 */
struct SwarmNotNoValidated2Result {
    std::string code;
    bool moved{false};
};

/**
 * Note a challenge without moving fitness.
 * Order, first match wins: an empty challenge_id is CHALLENGE.
 * unvalidated is NOT_MOVED even when want_move is false.
 * want_move is HELD.
 * Otherwise the note is NOTED and err is clear.
 * moved stays false on every path.
 * A challenge that is not independently validated does not move fitness.
 */
SwarmNotNoValidated2Result SwarmNoteNotNoValidated2(const SwarmNotNoValidated2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOVALIDATED2_H
