// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOEXPLOREILL2_H
#define BTX_MODELNET_SWARM_NOTNOEXPLOREILL2_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one run. want_assign asks this note to assign a
 * worker from an exploration illustration.
 *
 * An exploration illustration records 1, 2, and 2 and assigns nothing.
 * assigned stays false and slots stays 0 on every path.
 */
struct SwarmNotNoExploreIll2 {
    std::string run_id;
    bool want_assign{false};
};

/**
 * Outcome of noting an explore request. assigned stays false and slots
 * stays 0 on every path: an exploration illustration records 1, 2, and 2
 * and assigns nothing.
 */
struct SwarmNotNoExploreIll2Result {
    std::string code;
    bool assigned{false};
    int32_t slots{0};
};

/**
 * Note an explore request without assigning a worker.
 * Order, first match wins: an empty run_id is RUN. want_assign is HELD.
 * Otherwise the note is NOTED and err is clear.
 * assigned stays false and slots stays 0 on every path. An exploration
 * illustration records 1, 2, and 2 and assigns nothing.
 */
SwarmNotNoExploreIll2Result SwarmNoteNotNoExploreIll2(const SwarmNotNoExploreIll2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOEXPLOREILL2_H
