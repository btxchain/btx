// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FOURBAL_H
#define BTX_MODELNET_SWARM_FOURBAL_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A four-balance record. Escrow, collateral, earned, and spendable stay
 * separate. want_merge asks this record to merge them.
 *
 * A merge request is held. It spends nothing. merged stays false on
 * every path.
 */
struct SwarmFourBal {
    std::string ledger_id;
    int64_t escrow{0};
    int64_t collateral{0};
    int64_t earned{0};
    int64_t spendable{0};
    bool want_merge{false};
};

/**
 * Outcome of keeping four balances. merged stays false on every path.
 * Escrow, collateral, earned, and spendable stay separate.
 */
struct SwarmFourBalResult {
    std::string code;
    bool merged{false};
    int64_t escrow{0};
    int64_t collateral{0};
    int64_t earned{0};
    int64_t spendable{0};
};

/**
 * Keep four balances without merging or spending them.
 * Order, first match wins: an empty ledger_id is LEDGER and the four
 * amounts are 0. Any amount below zero is RANGE and the four amounts
 * are 0. want_merge is HELD and the four amounts are copied. Otherwise
 * the record is NOTED, err is cleared, and the four amounts are copied.
 * merged stays false on every path. Four balances stay separate. This
 * record does not merge or spend them.
 */
SwarmFourBalResult SwarmKeepFourBalances(const SwarmFourBal& ledger, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FOURBAL_H
