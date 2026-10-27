// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCOSTCHARGE2_H
#define BTX_MODELNET_SWARM_NOTNOCOSTCHARGE2_H

#include <string>
#include <cstdint>

namespace modelnet {

/**
 * A local note about one cost. unmeasured is true when electricity or
 * wear is unmeasured. want_charge asks this note to charge.
 *
 * An unmeasured electricity or wear cost charges nothing. charged stays
 * false and atoms stays 0 on every path.
 */
struct SwarmNotNoCostCharge2 {
    std::string cost_id;
    bool unmeasured{false};
    bool want_charge{false};
};

/**
 * Outcome of noting a cost. charged stays false and atoms stays 0 on
 * every path. An unmeasured electricity or wear cost charges nothing.
 */
struct SwarmNotNoCostCharge2Result {
    std::string code;
    bool charged{false};
    int64_t atoms{0};
};

/**
 * Note a cost without charging it.
 * Order, first match wins: an empty cost_id is COST. unmeasured true is
 * NOT_CHARGED even when want_charge is false. want_charge is HELD.
 * Otherwise the note is NOTED and err is cleared. charged stays false
 * and atoms stays 0 on every path. An unmeasured electricity or wear
 * cost charges nothing.
 */
SwarmNotNoCostCharge2Result SwarmNoteNotNoCostCharge2(const SwarmNotNoCostCharge2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCOSTCHARGE2_H
