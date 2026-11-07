// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTISLAND_H
#define BTX_MODELNET_SWARM_NOTISLAND_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one run. want_publish asks this note to publish a
 * comparison of independent training islands.
 *
 * Independent training islands have not been compared, and weights are not
 * averaged. published stays false, averaged stays false, bytes_moved stays
 * false, and delta stays 0 on every path.
 */
struct SwarmNotIsland {
    std::string run_id;
    bool want_publish{false};
};

/**
 * Outcome of noting an island comparison. published stays false, averaged
 * stays false, bytes_moved stays false, and delta stays 0 on every path.
 * Independent training islands have not been compared, and weights are not
 * averaged.
 */
struct SwarmNotIslandResult {
    std::string code;
    bool published{false};
    bool averaged{false};
    bool bytes_moved{false};
    int64_t delta{0};
};

/**
 * Note an island comparison without comparing islands or averaging weights.
 * Order, first match wins: an empty run_id is RUN.
 * want_publish is UNMEASURED.
 * Otherwise the note is NOTED and err is clear.
 * published stays false, averaged stays false, bytes_moved stays false, and
 * delta stays 0 on every path.
 * Independent training islands have not been compared, and weights are not
 * averaged.
 */
SwarmNotIslandResult SwarmNoteNotIsland(const SwarmNotIsland& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTISLAND_H
