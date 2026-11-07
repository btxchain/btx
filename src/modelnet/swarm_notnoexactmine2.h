// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOEXACTMINE2_H
#define BTX_MODELNET_SWARM_NOTNOEXACTMINE2_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one check. want_mine asks this note to mine.
 *
 * An isolated check mines nothing and does not mine past ExactReplay.
 * mined stays false and blocks stays 0 on every path.
 */
struct SwarmNotNoExactMine2 {
    std::string check_id;
    bool want_mine{false};
};

/**
 * Outcome of noting a check. mined stays false and blocks stays 0 on
 * every path: an isolated check mines nothing and does not mine past ExactReplay.
 */
struct SwarmNotNoExactMine2Result {
    std::string code;
    bool mined{false};
    int64_t blocks{0};
};

/**
 * Note a check without mining.
 * Order, first match wins: an empty check_id is CHECK. want_mine is
 * HELD. Otherwise the note is NOTED and err is cleared.
 * mined stays false and blocks stays 0 on every path. An isolated check
 * mines nothing and does not mine past ExactReplay.
 */
SwarmNotNoExactMine2Result SwarmNoteNotNoExactMine2(const SwarmNotNoExactMine2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOEXACTMINE2_H
