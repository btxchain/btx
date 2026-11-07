// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOREV122_H
#define BTX_MODELNET_SWARM_NOTNOREV122_H

#include <string>
#include <cstdint>

namespace modelnet {

/**
 * A local note about one revenue row. row_id names the row. want_pay
 * asks this note to pay.
 *
 * The revenue illustration records 7000, 2000, and 1000 and pays nothing.
 * paid stays false and atoms stays 0 on every path.
 */
struct SwarmNotNoRev122 {
    std::string row_id;
    bool want_pay{false};
};

/**
 * Outcome of noting a revenue row. paid stays false and atoms stays 0
 * on every path. The revenue illustration records 7000, 2000, and 1000
 * and pays nothing.
 */
struct SwarmNotNoRev122Result {
    std::string code;
    bool paid{false};
    int64_t atoms{0};
};

/**
 * Note a revenue row without paying.
 * Order, first match wins: an empty row_id is ROW. want_pay is
 * NOT_PAID. Otherwise the note is NOTED and err is cleared.
 * paid stays false and atoms stays 0 on every path. The revenue
 * illustration records 7000, 2000, and 1000 and pays nothing.
 */
SwarmNotNoRev122Result SwarmNoteNotNoRev122(const SwarmNotNoRev122& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOREV122_H
