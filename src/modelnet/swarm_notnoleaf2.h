// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOLEAF2_H
#define BTX_MODELNET_SWARM_NOTNOLEAF2_H

#include <string>

namespace modelnet {

/**
 * A local note about one contract. want_third asks this note to build
 * a third leaf.
 *
 * A contributor HTLC note builds no third leaf. built stays false on
 * every path.
 */
struct SwarmNotNoLeaf2 {
    std::string contract_id;
    bool want_third{false};
};

/**
 * Outcome of noting a contributor HTLC. built stays false on every
 * path. A contributor HTLC note builds no third leaf.
 */
struct SwarmNotNoLeaf2Result {
    std::string code;
    bool built{false};
};

/**
 * Note a contributor HTLC without building a third leaf.
 * Order, first match wins: an empty contract_id is CONTRACT. want_third
 * is HELD. Otherwise the note is NOTED and err is cleared. built stays
 * false on every path. A contributor HTLC note builds no third leaf.
 */
SwarmNotNoLeaf2Result SwarmNoteNotNoLeaf2(const SwarmNotNoLeaf2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOLEAF2_H
