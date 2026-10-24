// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOVALID_H
#define BTX_MODELNET_SWARM_NOTNOVALID_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one challenge. validated records whether the
 * challenge is independently validated. want_move asks this note to
 * move fitness.
 *
 * A challenge that is not independently validated moves no fitness.
 * moved stays false and fitness stays 0 on every path.
 */
struct SwarmNotNoValid {
    std::string challenge_id;
    bool validated{false};
    bool want_move{false};
};

/**
 * Outcome of noting a challenge. moved stays false and fitness stays 0
 * on every path.
 */
struct SwarmNotNoValidResult {
    std::string code;
    bool moved{false};
    int64_t fitness{0};
};

/**
 * Note a challenge without moving fitness.
 * Order, first match wins: an empty challenge_id is CHALLENGE. When
 * validated is false the note is NOT_VALIDATED even when want_move is
 * false. want_move is HELD. Otherwise the note is NOTED and err is clear.
 * moved stays false and fitness stays 0 on every path. A challenge that
 * is not independently validated moves no fitness.
 */
SwarmNotNoValidResult SwarmNoteNotNoValid(const SwarmNotNoValid& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOVALID_H
