// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTPROFIT_H
#define BTX_MODELNET_SWARM_NOTPROFIT_H

#include <string>

namespace modelnet {

/**
 * A local note about one profit share. want_share asks this note to share
 * profit.
 *
 * Profit-share is refused. shared and paid stay false on every path.
 */
struct SwarmNotProfit {
    std::string share_id;
    bool want_share{false};
};

/**
 * Outcome of noting a profit-share request. shared and paid stay false
 * on every path: profit-share is refused.
 */
struct SwarmNotProfitResult {
    std::string code;
    bool shared{false};
    bool paid{false};
};

/**
 * Note a profit-share request without sharing or paying.
 * Order, first match wins: an empty share_id is SHARE. want_share is
 * REFUSED. Otherwise the note is NOTED and err is clear.
 * shared and paid stay false on every path. Profit-share is refused.
 */
SwarmNotProfitResult SwarmNoteNotProfit(const SwarmNotProfit& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTPROFIT_H
