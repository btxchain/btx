// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_ELECCOST_H
#define BTX_MODELNET_SWARM_ELECCOST_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local electricity-cost record. want_charge asks this record to charge.
 *
 * An unmeasured electricity cost charges nothing, so charged stays false
 * and atoms stays 0 on every path.
 */
struct SwarmElecCost {
    std::string meter_id;
    bool measured{false};
    bool want_charge{false};
};

/**
 * Outcome of noting an electricity cost. charged stays false and atoms
 * stays 0 on every path. An unmeasured electricity cost charges nothing.
 */
struct SwarmElecCostResult {
    std::string code;
    bool charged{false};
    int64_t atoms{0};
};

/**
 * Note an electricity cost without charging it.
 * Order, first match wins: an empty meter_id is METER. measured false is
 * HELD, even when want_charge is false. want_charge is HELD. Otherwise the
 * note is NOTED and err is cleared. charged stays false and atoms stays 0
 * on every path. An unmeasured electricity cost charges nothing.
 */
SwarmElecCostResult SwarmNoteElecCost(const SwarmElecCost& meter, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_ELECCOST_H
