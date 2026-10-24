// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOREPLAYMINE2_H
#define BTX_MODELNET_SWARM_NOTNOREPLAYMINE2_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one check. want_mine asks this note to mine.
 *
 * An isolated check mines nothing past ExactReplay.
 * mined stays false and blocks stays 0 on every path.
 */
struct SwarmNotNoReplayMine2 {
    std::string check_id;
    bool want_mine{false};
};

/**
 * Outcome of noting a check. mined stays false and blocks stays 0 on
 * every path: an isolated check mines nothing past ExactReplay.
 */
struct SwarmNotNoReplayMine2Result {
    std::string code;
    bool mined{false};
    int64_t blocks{0};
};

/**
 * Note a check without mining past ExactReplay.
 * Order, first match wins: an empty check_id is CHECK. want_mine is
 * HELD. Otherwise the note is NOTED and err is cleared.
 * mined stays false and blocks stays 0 on every path. An isolated check
 * mines nothing past ExactReplay.
 */
SwarmNotNoReplayMine2Result SwarmNoteNotNoReplayMine2(const SwarmNotNoReplayMine2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOREPLAYMINE2_H
