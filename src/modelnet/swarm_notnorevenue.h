// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOREVENUE_H
#define BTX_MODELNET_SWARM_NOTNOREVENUE_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one revenue split. want_pay asks this note to pay.
 *
 * A revenue illustration pays nothing. paid stays false and atoms stays
 * 0 on every path.
 */
struct SwarmNotNoRevenue {
    std::string split_id;
    bool want_pay{false};
};

/**
 * Outcome of noting a revenue split. paid stays false and atoms stays 0
 * on every path. A revenue illustration pays nothing.
 */
struct SwarmNotNoRevenueResult {
    std::string code;
    bool paid{false};
    int64_t atoms{0};
};

/**
 * Note a revenue split without paying.
 * Order, first match wins: an empty split_id is SPLIT. want_pay is
 * HELD. Otherwise the note is NOTED and err is cleared.
 * paid stays false and atoms stays 0 on every path.
 * A revenue illustration pays nothing.
 */
SwarmNotNoRevenueResult SwarmNoteNotNoRevenue(const SwarmNotNoRevenue& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOREVENUE_H
