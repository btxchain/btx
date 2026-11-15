// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOELECCOST2_H
#define BTX_MODELNET_SWARM_NOTNOELECCOST2_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one electricity cost. want_charge asks this note to
 * charge.
 *
 * An unmeasured electricity cost charges nothing, so charged stays false
 * and atoms stays 0 on every path.
 */
struct SwarmNotNoElecCost2 {
    std::string cost_id;
    bool want_charge{false};
};

/**
 * Outcome of noting an electricity cost. charged stays false and atoms
 * stays 0 on every path. An unmeasured electricity cost charges nothing.
 */
struct SwarmNotNoElecCost2Result {
    std::string code;
    bool charged{false};
    int64_t atoms{0};
};

/**
 * Note an electricity cost without charging it.
 * Order, first match wins: an empty cost_id is COST. want_charge is HELD.
 * Otherwise the note is NOTED and err is cleared. charged stays false and
 * atoms stays 0 on every path. An unmeasured electricity cost charges
 * nothing.
 */
SwarmNotNoElecCost2Result SwarmNoteNotNoElecCost2(const SwarmNotNoElecCost2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOELECCOST2_H
