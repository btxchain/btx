// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNODNSSEED2_H
#define BTX_MODELNET_SWARM_NOTNODNSSEED2_H

#include <string>

namespace modelnet {

/**
 * A local note about one DNS seed. want_add asks this note to add it.
 *
 * The DNS seed list stays empty. Adding to it is refused.
 * added stays false on every path.
 */
struct SwarmNotNoDnsSeed2 {
    std::string seed_id;
    bool want_add{false};
};

/**
 * Outcome of noting a DNS seed. added stays false on every path.
 * The DNS seed list stays empty. Adding to it is refused.
 */
struct SwarmNotNoDnsSeed2Result {
    std::string code;
    bool added{false};
};

/**
 * Note a DNS seed without adding it.
 * Order, first match wins: an empty seed_id is SEED.
 * want_add is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * added stays false on every path.
 * The DNS seed list stays empty.
 */
SwarmNotNoDnsSeed2Result SwarmNoteNotNoDnsSeed2(const SwarmNotNoDnsSeed2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNODNSSEED2_H
