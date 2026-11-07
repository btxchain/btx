// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOMINE_H
#define BTX_MODELNET_SWARM_NOTNOMINE_H

#include <string>

namespace modelnet {

/**
 * A local note about one chain. want_mine asks this note to mine.
 *
 * A mine request is not mined and is not broadcast.
 * mined and broadcast stay false on every path.
 */
struct SwarmNotNoMine {
    std::string chain_id;
    bool want_mine{false};
};

/**
 * Outcome of noting a chain. mined and broadcast stay false on every
 * path: a mine request is not mined and is not broadcast.
 */
struct SwarmNotNoMineResult {
    std::string code;
    bool mined{false};
    bool broadcast{false};
};

/**
 * Note a chain without mining or broadcasting.
 * Order, first match wins: an empty chain_id is CHAIN. want_mine is
 * NOT_MINED. Otherwise the note is NOTED and err is cleared.
 * mined and broadcast stay false on every path. A mine request is not
 * mined and is not broadcast.
 */
SwarmNotNoMineResult SwarmNoteNotNoMine(const SwarmNotNoMine& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOMINE_H
