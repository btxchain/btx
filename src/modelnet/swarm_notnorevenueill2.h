// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOREVENUEILL2_H
#define BTX_MODELNET_SWARM_NOTNOREVENUEILL2_H

#include <string>
#include <cstdint>

namespace modelnet {

/**
 * A local note about one revenue run. run_id names the run. want_pay
 * asks this note to pay.
 *
 * A revenue illustration records 7000, 2000, and 1000 and pays nothing.
 * paid stays false and atoms stays 0 on every path.
 */
struct SwarmNotNoRevenueIll2 {
    std::string run_id;
    bool want_pay{false};
};

/**
 * Outcome of noting a revenue run. paid stays false and atoms stays 0
 * on every path. A revenue illustration records 7000, 2000, and 1000
 * and pays nothing.
 */
struct SwarmNotNoRevenueIll2Result {
    std::string code;
    bool paid{false};
    int64_t atoms{0};
};

/**
 * Note a revenue run without paying.
 * Order, first match wins: an empty run_id is RUN. want_pay is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * paid stays false and atoms stays 0 on every path. A revenue
 * illustration records 7000, 2000, and 1000 and pays nothing.
 */
SwarmNotNoRevenueIll2Result SwarmNoteNotNoRevenueIll2(const SwarmNotNoRevenueIll2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOREVENUEILL2_H
