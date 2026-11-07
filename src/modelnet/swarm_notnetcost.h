// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNETCOST_H
#define BTX_MODELNET_SWARM_NOTNETCOST_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about network cost for one peer. want_publish asks this
 * note to publish a measured network cost.
 *
 * This note does not measure network cost or move atoms. published stays
 * false and atoms stays 0 on every path.
 */
struct SwarmNotNetCost {
    std::string peer_id;
    bool want_publish{false};
};

/**
 * Outcome of noting network cost. published stays false and atoms stays 0
 * on every path. This note does not measure network cost or move atoms.
 */
struct SwarmNotNetCostResult {
    std::string code;
    bool published{false};
    int64_t atoms{0};
};

/**
 * Note network cost without measuring it or moving atoms.
 * Order, first match wins: an empty peer_id is PEER.
 * want_publish is UNMEASURED.
 * Otherwise the note is NOTED and err is clear.
 * published stays false and atoms stays 0 on every path.
 */
SwarmNotNetCostResult SwarmNoteNotNetCost(const SwarmNotNetCost& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNETCOST_H
