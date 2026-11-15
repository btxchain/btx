// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCRASH_H
#define BTX_MODELNET_SWARM_NOTNOCRASH_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one node. crashed records that the node stopped.
 * want_spend asks this note to spend.
 *
 * A crash does not spend. spent stays false and atoms stays 0 on every
 * path.
 */
struct SwarmNotNoCrash {
    std::string node_id;
    bool crashed{false};
    bool want_spend{false};
};

/**
 * Outcome of noting a crash. spent stays false and atoms stays 0 on
 * every path. A crash does not spend.
 */
struct SwarmNotNoCrashResult {
    std::string code;
    bool spent{false};
    int64_t atoms{0};
};

/**
 * Note a crash without spending. Order, first match wins: an empty
 * node_id is NODE. crashed is HELD even when want_spend is false.
 * want_spend is HELD. Otherwise the note is NOTED and err is clear.
 * spent stays false and atoms stays 0 on every path. A crash does not
 * spend.
 */
SwarmNotNoCrashResult SwarmNoteNotNoCrash(const SwarmNotNoCrash& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCRASH_H
