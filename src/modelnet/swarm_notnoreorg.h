// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOREORG_H
#define BTX_MODELNET_SWARM_NOTNOREORG_H

#include <string>

namespace modelnet {

/**
 * A local note about one chain. want_reorg asks this note to reorg.
 *
 * A note does not reorg or mine past ExactReplay. reorged and mined
 * stay false on every path.
 */
struct SwarmNotNoReorg {
    std::string chain_id;
    bool want_reorg{false};
};

/**
 * Outcome of noting a chain. reorged and mined stay false on every path.
 */
struct SwarmNotNoReorgResult {
    std::string code;
    bool reorged{false};
    bool mined{false};
};

/**
 * Note a chain without reorging or mining past ExactReplay.
 * Order, first match wins: an empty chain_id is CHAIN.
 * want_reorg is NOT_MINED. Otherwise the note is NOTED and err is clear.
 * reorged and mined stay false on every path. A note does not reorg or
 * mine past ExactReplay.
 */
SwarmNotNoReorgResult SwarmNoteNotNoReorg(const SwarmNotNoReorg& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOREORG_H
