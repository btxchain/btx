// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCHALLINFO2_H
#define BTX_MODELNET_SWARM_NOTNOCHALLINFO2_H

#include <string>

namespace modelnet {

/**
 * A local note about one challenge. uninformative records that the
 * challenge does not inform fitness. want_move asks this note to move
 * fitness.
 *
 * An uninformative challenge does not move fitness. This note moves
 * nothing. moved stays false on every path.
 */
struct SwarmNotNoChallInfo2 {
    std::string challenge_id;
    bool uninformative{false};
    bool want_move{false};
};

/**
 * Outcome of noting a challenge. moved stays false on every path.
 * An uninformative challenge does not move fitness.
 */
struct SwarmNotNoChallInfo2Result {
    std::string code;
    bool moved{false};
};

/**
 * Note a challenge without moving fitness. Order, first match wins: an
 * empty challenge_id is CHALLENGE. When uninformative is true the note
 * is NOT_MOVED even when want_move is false. want_move is HELD.
 * Otherwise the note is NOTED and err is cleared. moved stays false on
 * every path. An uninformative challenge does not move fitness.
 */
SwarmNotNoChallInfo2Result SwarmNoteNotNoChallInfo2(const SwarmNotNoChallInfo2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCHALLINFO2_H
