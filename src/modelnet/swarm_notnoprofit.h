// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOPROFIT_H
#define BTX_MODELNET_SWARM_NOTNOPROFIT_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one split. want_share asks this note for a profit
 * share.
 *
 * Profit-share is refused and this note pays nothing. paid stays false
 * and atoms stays 0 on every path.
 */
struct SwarmNotNoProfit {
    std::string split_id;
    bool want_share{false};
};

/**
 * Outcome of noting a profit-share request. paid stays false and atoms
 * stays 0: this note pays nothing.
 */
struct SwarmNotNoProfitResult {
    std::string code;
    bool paid{false};
    int64_t atoms{0};
};

/**
 * Note a profit-share request without paying it.
 * Order, first match wins: an empty split_id is SPLIT. want_share is
 * REFUSED. Otherwise the note is NOTED and err is clear.
 * paid stays false and atoms stays 0 on every path. Profit-share is
 * refused and this note pays nothing.
 */
SwarmNotNoProfitResult SwarmNoteNotNoProfit(const SwarmNotNoProfit& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOPROFIT_H
